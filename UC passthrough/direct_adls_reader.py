"""
Secured Direct ADLS File Reader with DataFrame Conversion

This module reads unstructured files directly from ADLS using Python SDK with user credentials,
then converts the data to Spark DataFrames without requiring Spark-level token injection.

All authentication mechanisms and sensitive operations are protected from user manipulation.
"""

import io
import json
import logging
from typing import Optional, Dict, Any, List, Union, Iterator
from urllib.parse import urlparse
from datetime import datetime
import glob
import os
import threading
from functools import wraps

try:
    from pyspark.sql import DataFrame, SparkSession
    from pyspark.sql.types import StructType, StructField, StringType, BinaryType, LongType, TimestampType, IntegerType
    from pyspark.sql.functions import col, lit
    import pandas as pd
except ImportError as e:
    raise ImportError(f"Required libraries not found: {e}")

try:
    from azure.storage.filedatalake import DataLakeServiceClient, FileSystemClient, DataLakeFileClient
    from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
    import chardet  # For encoding detection
except ImportError as e:
    raise ImportError(f"Required Azure libraries not found: {e}")

logger = logging.getLogger(__name__)


def _protect_adls_method(method):
    """Decorator to protect ADLS client access methods from external access."""
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        # Check if being called from within the same module/trusted context
        import inspect
        frame = inspect.currentframe().f_back
        caller_module = frame.f_globals.get('__name__', '')
        
        # Allow calls from within this module or trusted modules
        if not (caller_module.startswith(__name__.split('.')[0]) or 
                caller_module in ['dataframe_reader', 'authentication_manager']):
            raise PermissionError("Direct access to ADLS client methods is restricted")
        
        return method(self, *args, **kwargs)
    return wrapper


class DirectADLSReader:
    """
    Reads unstructured files directly from ADLS using Python SDK, then converts to Spark DataFrames.
    This bypasses the need for Spark-level credential injection.
    
    All authentication mechanisms and ADLS client access is protected from user manipulation.
    """
    
    def __init__(self, adls_client: DataLakeServiceClient, spark_session: SparkSession):
        """
        Initialize DirectADLSReader with protected ADLS client.
        
        Args:
            adls_client: Authenticated ADLS client with user credentials (kept private)
            spark_session: Active Spark session for DataFrame creation
        """
        self.__adls_client = adls_client  # Private - protected from direct access
        self.spark = spark_session
        self.__lock = threading.Lock()  # Thread safety for sensitive operations
        
        # Security limits - these are protected from modification
        self.__max_files_per_read = 1000  # Safety limit
        self.__max_file_size_mb = 100  # Safety limit for individual files
        
        # Validate the ADLS client during initialization
        try:
            # Test basic connectivity without exposing credentials
            self.__validate_adls_connection()
        except Exception as e:
            logger.error(f"Failed to validate ADLS connection during initialization: {str(e)}")
            raise RuntimeError("ADLS client validation failed")
    
    def __validate_adls_connection(self):
        """Private method to validate ADLS connection without exposing credentials."""
        try:
            # Perform a minimal operation to validate connection
            list(self.__adls_client.list_file_systems())
            logger.debug("ADLS connection validated successfully")
        except Exception as e:
            logger.error(f"ADLS connection validation failed: {str(e)}")
            raise
    
    @_protect_adls_method
    def _read_text_files_internal(self, container: str, blob_path: str, 
                                 encoding: Optional[str] = None,
                                 options: Optional[Dict] = None) -> DataFrame:
        """
        Protected method to read text files directly from ADLS and convert to Spark DataFrame.
        This method is protected from direct user access.
        
        Args:
            container: ADLS container name
            blob_path: Path to file(s) - supports wildcards
            encoding: File encoding (auto-detected if None)
            options: Additional reading options
            
        Returns:
            Spark DataFrame with text content
        """
        try:
            with self.__lock:  # Thread-safe access to ADLS client
                files_data = []
                file_system_client = self.__adls_client.get_file_system_client(container)
                
                # Get list of files matching the pattern
                file_paths = self.__resolve_file_paths(file_system_client, blob_path)
                
                if len(file_paths) > self.__max_files_per_read:
                    logger.warning(f"Found {len(file_paths)} files, limiting to {self.__max_files_per_read}")
                    file_paths = file_paths[:self.__max_files_per_read]
                
                for file_path in file_paths:
                    try:
                        file_client = file_system_client.get_file_client(file_path)
                        
                        # Get file properties
                        properties = file_client.get_file_properties()
                        file_size_mb = properties.size / (1024 * 1024)
                        
                        if file_size_mb > self.__max_file_size_mb:
                            logger.warning(f"Skipping large file {file_path} ({file_size_mb:.1f} MB)")
                            continue
                        
                        # Download file content
                        download = file_client.download_file()
                        content_bytes = download.readall()
                        
                        # Detect encoding if not specified
                        if encoding is None:
                            detected = chardet.detect(content_bytes)
                            file_encoding = detected.get('encoding', 'utf-8')
                        else:
                            file_encoding = encoding
                        
                        # Decode content
                        content_text = content_bytes.decode(file_encoding)
                        
                        # Create file record
                        file_record = {
                            'path': f"abfss://{container}@{self.__adls_client.account_name}.dfs.core.windows.net/{file_path}",
                            'modificationTime': properties.last_modified,
                            'length': properties.size,
                            'content': content_text,
                            'encoding': file_encoding
                        }
                        files_data.append(file_record)
                        
                    except Exception as e:
                        logger.warning(f"Failed to read file {file_path}: {str(e)}")
                        continue
                
                if not files_data:
                    raise RuntimeError(f"No files could be read from {blob_path}")
                
                # Convert to Spark DataFrame
                return self.__create_text_dataframe(files_data)
            
        except Exception as e:
            logger.error(f"Failed to read text files from {blob_path}: {str(e)}")
            raise RuntimeError(f"Text file reading failed: {str(e)}")
    
    @_protect_adls_method
    def _read_binary_files_internal(self, container: str, blob_path: str,
                                   options: Optional[Dict] = None) -> DataFrame:
        """
        Protected method to read binary files directly from ADLS and convert to Spark DataFrame.
        This method is protected from direct user access.
        
        Args:
            container: ADLS container name  
            blob_path: Path to file(s) - supports wildcards
            options: Additional reading options
            
        Returns:
            Spark DataFrame with binary content (similar to Spark's binaryFile format)
        """
        try:
            with self.__lock:  # Thread-safe access to ADLS client
                files_data = []
                file_system_client = self.__adls_client.get_file_system_client(container)
                
                # Get list of files matching the pattern
                file_paths = self.__resolve_file_paths(file_system_client, blob_path)
                
                if len(file_paths) > self.__max_files_per_read:
                    logger.warning(f"Found {len(file_paths)} files, limiting to {self.__max_files_per_read}")
                    file_paths = file_paths[:self.__max_files_per_read]
                
                for file_path in file_paths:
                    try:
                        file_client = file_system_client.get_file_client(file_path)
                        
                        # Get file properties
                        properties = file_client.get_file_properties()
                        file_size_mb = properties.size / (1024 * 1024)
                        
                        if file_size_mb > self.__max_file_size_mb:
                            logger.warning(f"Skipping large file {file_path} ({file_size_mb:.1f} MB)")
                            continue
                        
                        # Download file content
                        download = file_client.download_file()
                        content_bytes = download.readall()
                        
                        # Create file record (similar to Spark's binaryFile format)
                        file_record = {
                            'path': f"abfss://{container}@{self.__adls_client.account_name}.dfs.core.windows.net/{file_path}",
                            'modificationTime': properties.last_modified,
                            'length': properties.size,
                            'content': content_bytes
                        }
                        files_data.append(file_record)
                        
                    except Exception as e:
                        logger.warning(f"Failed to read file {file_path}: {str(e)}")
                        continue
                
                if not files_data:
                    raise RuntimeError(f"No files could be read from {blob_path}")
                
                # Convert to Spark DataFrame
                return self.__create_binary_dataframe(files_data)
            
        except Exception as e:
            logger.error(f"Failed to read binary files from {blob_path}: {str(e)}")
            raise RuntimeError(f"Binary file reading failed: {str(e)}")
    
    @_protect_adls_method
    def _read_json_files_internal(self, container: str, blob_path: str,
                                 options: Optional[Dict] = None) -> DataFrame:
        """
        Protected method to read JSON files directly from ADLS and convert to Spark DataFrame.
        This method is protected from direct user access.
        
        Args:
            container: ADLS container name
            blob_path: Path to file(s) - supports wildcards  
            options: Additional reading options (multiLine, etc.)
            
        Returns:
            Spark DataFrame with JSON data
        """
        try:
            with self.__lock:  # Thread-safe access to ADLS client
                all_json_data = []
                file_system_client = self.__adls_client.get_file_system_client(container)
                
                # Get list of files matching the pattern
                file_paths = self.__resolve_file_paths(file_system_client, blob_path)
                
                # Filter out sensitive options that users shouldn't control
                safe_options = {k: v for k, v in (options or {}).items() 
                               if k not in {'azure_storage_account_key', 'azure_storage_sas_token'}}
                multiline = safe_options.get('multiLine', False)
                
                for file_path in file_paths[:self.__max_files_per_read]:
                    try:
                        file_client = file_system_client.get_file_client(file_path)
                        
                        # Get file properties and check size
                        properties = file_client.get_file_properties()
                        file_size_mb = properties.size / (1024 * 1024)
                        
                        if file_size_mb > self.__max_file_size_mb:
                            logger.warning(f"Skipping large file {file_path} ({file_size_mb:.1f} MB)")
                            continue
                        
                        # Download and parse JSON content
                        download = file_client.download_file()
                        content_bytes = download.readall()
                        content_text = content_bytes.decode('utf-8')
                        
                        if multiline:
                            # Single JSON object per file
                            json_obj = json.loads(content_text)
                            json_obj['_file_path'] = f"abfss://{container}@{self.__adls_client.account_name}.dfs.core.windows.net/{file_path}"
                            all_json_data.append(json_obj)
                        else:
                            # JSON Lines format (one JSON per line)
                            for line_num, line in enumerate(content_text.strip().split('\n')):
                                if line.strip():
                                    try:
                                        json_obj = json.loads(line)
                                        json_obj['_file_path'] = f"abfss://{container}@{self.__adls_client.account_name}.dfs.core.windows.net/{file_path}"
                                        json_obj['_line_number'] = line_num + 1
                                        all_json_data.append(json_obj)
                                    except json.JSONDecodeError as e:
                                        logger.warning(f"Invalid JSON on line {line_num + 1} in {file_path}: {str(e)}")
                                        continue
                        
                    except Exception as e:
                        logger.warning(f"Failed to read JSON file {file_path}: {str(e)}")
                        continue
                
                if not all_json_data:
                    raise RuntimeError(f"No valid JSON data found in {blob_path}")
                
                # Convert to Pandas DataFrame first, then to Spark
                pandas_df = pd.json_normalize(all_json_data)
                spark_df = self.spark.createDataFrame(pandas_df)
                
                return spark_df
                
        except Exception as e:
            logger.error(f"Failed to read JSON files from {blob_path}: {str(e)}")
            raise RuntimeError(f"JSON file reading failed: {str(e)}")
    
    @_protect_adls_method
    def _read_csv_files_internal(self, container: str, blob_path: str,
                                options: Optional[Dict] = None) -> DataFrame:
        """
        Protected method to read CSV files directly from ADLS and convert to Spark DataFrame.
        This method is protected from direct user access.
        
        Args:
            container: ADLS container name
            blob_path: Path to file(s) - supports wildcards
            options: CSV reading options (header, sep, etc.)
            
        Returns:
            Spark DataFrame with CSV data
        """
        try:
            with self.__lock:  # Thread-safe access to ADLS client
                all_csv_data = []
                file_system_client = self.__adls_client.get_file_system_client(container)
                
                # Get list of files matching the pattern
                file_paths = self.__resolve_file_paths(file_system_client, blob_path)
                
                # CSV options with security filtering
                safe_options = {k: v for k, v in (options or {}).items() 
                               if k not in {'azure_storage_account_key', 'azure_storage_sas_token'}}
                header = safe_options.get('header', True)
                separator = safe_options.get('sep', ',')
                
                for file_path in file_paths[:self.__max_files_per_read]:
                    try:
                        file_client = file_system_client.get_file_client(file_path)
                        
                        # Check file size
                        properties = file_client.get_file_properties()
                        file_size_mb = properties.size / (1024 * 1024)
                        
                        if file_size_mb > self.__max_file_size_mb:
                            logger.warning(f"Skipping large file {file_path} ({file_size_mb:.1f} MB)")
                            continue
                        
                        # Download and parse CSV content
                        download = file_client.download_file()
                        content_bytes = download.readall()
                        
                        # Read CSV using pandas
                        csv_data = pd.read_csv(
                            io.BytesIO(content_bytes),
                            header=0 if header else None,
                            sep=separator,
                            **{k: v for k, v in safe_options.items() if k not in ['header', 'sep']}
                        )
                        
                        # Add file path column
                        csv_data['_file_path'] = f"abfss://{container}@{self.__adls_client.account_name}.dfs.core.windows.net/{file_path}"
                        
                        all_csv_data.append(csv_data)
                        
                    except Exception as e:
                        logger.warning(f"Failed to read CSV file {file_path}: {str(e)}")
                        continue
                
                if not all_csv_data:
                    raise RuntimeError(f"No valid CSV data found in {blob_path}")
                
                # Concatenate all CSV data
                combined_df = pd.concat(all_csv_data, ignore_index=True)
                
                # Convert to Spark DataFrame
                spark_df = self.spark.createDataFrame(combined_df)
                
                return spark_df
                
        except Exception as e:
            logger.error(f"Failed to read CSV files from {blob_path}: {str(e)}")
            raise RuntimeError(f"CSV file reading failed: {str(e)}")
    
    def __resolve_file_paths(self, file_system_client: FileSystemClient, blob_path: str) -> List[str]:
        """
        Private method to resolve file paths, handling wildcards and directory listings.
        
        Args:
            file_system_client: ADLS file system client
            blob_path: Path pattern (may contain wildcards)
            
        Returns:
            List of resolved file paths
        """
        try:
            if '*' in blob_path or '?' in blob_path:
                # Handle wildcard patterns
                return self.__resolve_wildcard_paths(file_system_client, blob_path)
            else:
                # Check if it's a single file or directory
                try:
                    file_client = file_system_client.get_file_client(blob_path)
                    properties = file_client.get_file_properties()
                    if 'hdi_isfolder' in properties.metadata:
                        return self.__list_directory_files(file_system_client, blob_path)
                    else:
                        return [blob_path]  # Single file
                except ResourceNotFoundError:
                    # Try as directory
                    return self.__list_directory_files(file_system_client, blob_path)
                    
        except Exception as e:
            logger.error(f"Failed to resolve file paths for {blob_path}: {str(e)}")
            raise RuntimeError(f"Path resolution failed: {str(e)}")
    
    def __resolve_wildcard_paths(self, file_system_client: FileSystemClient, pattern: str) -> List[str]:
        """
        Private method to resolve wildcard patterns to actual file paths.
        
        Args:
            file_system_client: ADLS file system client
            pattern: Path pattern with wildcards
            
        Returns:
            List of matching file paths
        """
        try:
            # Extract directory part and filename pattern
            pattern_parts = pattern.split('/')
            base_path = '/'.join(pattern_parts[:-1]) if len(pattern_parts) > 1 else ""
            filename_pattern = pattern_parts[-1]
            
            # List files in the base directory
            paths = file_system_client.get_paths(path=base_path, recursive=False)
            
            matching_files = []
            for path in paths:
                if not path.is_directory:
                    filename = path.name.split('/')[-1]
                    
                    # Simple wildcard matching
                    if self.__matches_pattern(filename, filename_pattern):
                        matching_files.append(path.name)
            
            return sorted(matching_files)
            
        except Exception as e:
            logger.error(f"Failed to resolve wildcard pattern {pattern}: {str(e)}")
            return []
    
    def __list_directory_files(self, file_system_client: FileSystemClient, directory: str) -> List[str]:
        """
        Private method to list all files in a directory.
        
        Args:
            file_system_client: ADLS file system client
            directory: Directory path
            
        Returns:
            List of file paths in the directory
        """
        try:
            paths = file_system_client.get_paths(path=directory, recursive=False)
            
            file_paths = []
            for path in paths:
                if not path.is_directory:
                    file_paths.append(path.name)
            
            return sorted(file_paths)
            
        except Exception as e:
            logger.error(f"Failed to list directory {directory}: {str(e)}")
            return []
    
    def __matches_pattern(self, filename: str, pattern: str) -> bool:
        """
        Private method for simple wildcard pattern matching.
        
        Args:
            filename: File name to test
            pattern: Pattern with * and ? wildcards
            
        Returns:
            True if filename matches pattern
        """
        import fnmatch
        return fnmatch.fnmatch(filename, pattern)
    
    def __create_text_dataframe(self, files_data: List[Dict]) -> DataFrame:
        """
        Private method to create Spark DataFrame for text files.
        
        Args:
            files_data: List of file data dictionaries
            
        Returns:
            Spark DataFrame with text content
        """
        # Define schema for text files
        schema = StructType([
            StructField("path", StringType(), False),
            StructField("modificationTime", TimestampType(), False),
            StructField("length", LongType(), False),
            StructField("content", StringType(), True),
            StructField("encoding", StringType(), True)
        ])
        
        # Convert to Spark DataFrame
        return self.spark.createDataFrame(files_data, schema)
    
    def __create_binary_dataframe(self, files_data: List[Dict]) -> DataFrame:
        """
        Private method to create Spark DataFrame for binary files (similar to binaryFile format).
        
        Args:
            files_data: List of file data dictionaries
            
        Returns:
            Spark DataFrame with binary content
        """
        # Define schema for binary files (matches Spark's binaryFile format)
        schema = StructType([
            StructField("path", StringType(), False),
            StructField("modificationTime", TimestampType(), False),
            StructField("length", LongType(), False),
            StructField("content", BinaryType(), True)
        ])
        
        # Convert to Spark DataFrame
        return self.spark.createDataFrame(files_data, schema)
    
    @_protect_adls_method
    def _get_adls_client_internal(self) -> DataLakeServiceClient:
        """
        Protected method to get the internal ADLS client.
        This method is protected from direct user access.
        
        Returns:
            DataLakeServiceClient instance
        """
        return self.__adls_client
    
    # Public methods with limited functionality exposure
    def get_connection_status(self) -> Dict[str, Any]:
        """
        Public method to get basic connection status without exposing sensitive details.
        
        Returns:
            Dictionary with basic connection information
        """
        try:
            with self.__lock:
                # Test connection without exposing credentials
                list(self.__adls_client.list_file_systems())
                return {
                    'connected': True,
                    'account_name': self.__adls_client.account_name,
                    'max_files_per_read': self.__max_files_per_read,
                    'max_file_size_mb': self.__max_file_size_mb
                }
        except Exception as e:
            logger.error(f"Connection status check failed: {str(e)}")
            return {
                'connected': False,
                'error': 'Connection validation failed'
            }
    
    def get_supported_operations(self) -> List[str]:
        """
        Public method to get list of supported file operations.
        
        Returns:
            List of supported operation names
        """
        return [
            'read_text_files',
            'read_binary_files', 
            'read_json_files',
            'read_csv_files'
        ]
    # Add public wrapper methods that can be called by DataFrame reader
    def read_text_files(self, container: str, blob_path: str, 
                       encoding: Optional[str] = None,
                       options: Optional[Dict] = None) -> DataFrame:
        """Public method that delegates to protected internal implementation."""
        return self._read_text_files_internal(container, blob_path, encoding, options)
    
    def read_binary_files(self, container: str, blob_path: str,
                         options: Optional[Dict] = None) -> DataFrame:
        """Public method that delegates to protected internal implementation."""
        return self._read_binary_files_internal(container, blob_path, options)
    
    def read_json_files(self, container: str, blob_path: str,
                       options: Optional[Dict] = None) -> DataFrame:
        """Public method that delegates to protected internal implementation."""
        return self._read_json_files_internal(container, blob_path, options)
    
    def read_csv_files(self, container: str, blob_path: str,
                      options: Optional[Dict] = None) -> DataFrame:
        """Public method that delegates to protected internal implementation."""
        return self._read_csv_files_internal(container, blob_path, options)