"""
Secured Direct ADLS File Writer with Transaction Safety

This module writes data directly to ADLS using Python SDK with user credentials,
converting Spark DataFrames to various file formats without requiring Spark-level token injection.

All authentication mechanisms and sensitive operations are protected from user manipulation.
Implements transaction-like behavior for write safety and rollback capabilities.

UPDATED: Fixed ADLS Gen2 x-ms-blob-type header issue by using proper Data Lake API sequence.
"""

import io
import json
import logging
from typing import Optional, Dict, Any, List, Union, Tuple
from urllib.parse import urlparse
from datetime import datetime
import uuid
import os
import threading
from functools import wraps
from contextlib import contextmanager

try:
    from pyspark.sql import DataFrame, SparkSession
    from pyspark.sql.types import StructType, StructField, StringType, BinaryType
    from pyspark.sql.functions import col, lit
    import pandas as pd
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError as e:
    raise ImportError(f"Required libraries not found: {e}")

try:
    from azure.storage.filedatalake import DataLakeServiceClient, FileSystemClient, DataLakeFileClient
    from azure.core.exceptions import ResourceNotFoundError, HttpResponseError, ResourceExistsError
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
        
        # Get the base module name
        base_module = __name__.split('.')[0] if '.' in __name__ else __name__
        caller_base_module = caller_module.split('.')[0] if '.' in caller_module else caller_module
        
        # Allow calls from within the same package or trusted modules
        trusted_modules = {
            'authentication_manager',
            'direct_adls_reader', 
            'direct_adls_writer',
            'uc_passthrough_library',
            'uc_dataframe_writer',
            '__main__'  # Allow calls from main execution context
        }
        
        if (caller_base_module == base_module or 
            caller_module in trusted_modules or
            caller_base_module in trusted_modules):
            return method(self, *args, **kwargs)
        else:
            logger.warning(f"Blocked access to protected method {method.__name__} from {caller_module}")
            raise PermissionError("Direct access to ADLS client methods is restricted")
        
    return wrapper


def _adls_gen2_safe_upload(file_client: DataLakeFileClient, data, overwrite: bool = True):
    """
    Upload data to ADLS Gen2 using the correct Data Lake API sequence.
    This avoids the x-ms-blob-type header issue by using Data Lake APIs instead of Blob APIs.
    
    The issue occurs because ADLS Gen2 has dual API compatibility and upload_data() 
    sometimes routes to the Blob API which requires x-ms-blob-type header.
    Using create_file → append_data → flush_data sequence uses Data Lake API directly.
    
    Args:
        file_client: DataLakeFileClient instance
        data: Data to upload (bytes or string)
        overwrite: Whether to overwrite existing files
    """
    try:
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Step 1: Handle existing file if overwrite is requested
        if overwrite:
            try:
                file_client.delete_file()
                logger.debug("Deleted existing file for overwrite")
            except Exception:
                pass  # File might not exist, that's fine
        
        # Step 2: Create the file using Data Lake API (this sets correct headers internally)
        file_client.create_file()
        logger.debug("Created file using Data Lake API")
        
        # Step 3: Upload data if there is any
        if data and len(data) > 0:
            # Append the data
            file_client.append_data(data, offset=0, length=len(data))
            logger.debug(f"Appended {len(data)} bytes of data")
            
            # Flush/commit the data (this is crucial!)
            file_client.flush_data(len(data))
            logger.debug("Flushed data to finalize upload")
        
        return True
        
    except Exception as e:
        logger.error(f"ADLS Gen2 safe upload failed: {str(e)}")
        raise


class WriteTransactionContext:
    """
    Context manager for transaction-safe writes to ADLS.
    Provides rollback capabilities for failed write operations.
    """
    
    def __init__(self, file_system_client: FileSystemClient, target_path: str, 
                 write_mode: str, adls_client_account_name: str):
        """
        Initialize transaction context.
        
        Args:
            file_system_client: ADLS file system client
            target_path: Final target path for the data
            write_mode: Write mode ('overwrite', 'append', 'ignore', 'error')
            adls_client_account_name: ADLS account name for path construction
        """
        self.file_system_client = file_system_client
        self.target_path = target_path.rstrip('/')
        self.write_mode = write_mode
        self.account_name = adls_client_account_name
        
        # Generate unique transaction ID
        self.transaction_id = str(uuid.uuid4())[:8]
        self.temp_path = f"{self.target_path}_temp_{self.transaction_id}"
        self.backup_path = None
        
        self.committed = False
        self.files_written = []  # Track files for cleanup
        
        logger.debug(f"Created transaction context: {self.transaction_id}")
    
    def __enter__(self):
        """Enter transaction context."""
        try:
            # Handle different write modes
            if self.write_mode == 'error':
                # Check if target already exists
                if self._path_exists(self.target_path):
                    raise FileExistsError(f"Target path already exists and mode is 'error': {self.target_path}")
            
            elif self.write_mode == 'ignore':
                # Check if target already exists
                if self._path_exists(self.target_path):
                    logger.info(f"Target path exists and mode is 'ignore', skipping write: {self.target_path}")
                    self.committed = True  # Mark as committed to skip actual write
                    return self
            
            elif self.write_mode == 'overwrite':
                # Create backup if target exists
                if self._path_exists(self.target_path):
                    self.backup_path = f"{self.target_path}_backup_{self.transaction_id}"
                    self._move_path(self.target_path, self.backup_path)
                    logger.debug(f"Created backup: {self.backup_path}")
            
            elif self.write_mode == 'append':
                # For append mode, validate target exists and is compatible
                if self._path_exists(self.target_path):
                    logger.debug(f"Appending to existing path: {self.target_path}")
                else:
                    logger.debug(f"Target does not exist, creating new: {self.target_path}")
            
            return self
            
        except Exception as e:
            logger.error(f"Failed to enter transaction context: {str(e)}")
            raise
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit transaction context with rollback on failure."""
        try:
            if exc_type is None and not self.committed:
                # Success case - commit transaction
                self._commit_transaction()
            elif exc_type is not None:
                # Failure case - rollback transaction
                self._rollback_transaction()
            
        except Exception as rollback_error:
            logger.error(f"Error during transaction cleanup: {str(rollback_error)}")
        
        return False  # Don't suppress any exceptions
    
    def _commit_transaction(self):
        """Commit the transaction by moving temp files to target."""
        try:
            if self.write_mode == 'ignore' and self._path_exists(self.target_path):
                # Nothing to commit for ignore mode when target exists
                self.committed = True
                return
            
            # Move temp files to target location
            if self._path_exists(self.temp_path):
                if self.write_mode == 'append' and self._path_exists(self.target_path):
                    # For append mode, merge the files
                    self._merge_paths(self.temp_path, self.target_path)
                else:
                    # For other modes, replace target with temp
                    self._move_path(self.temp_path, self.target_path)
            
            # Clean up backup if successful
            if self.backup_path and self._path_exists(self.backup_path):
                self._delete_path(self.backup_path)
                logger.debug(f"Deleted backup: {self.backup_path}")
            
            self.committed = True
            logger.debug(f"Transaction committed: {self.transaction_id}")
            
        except Exception as e:
            logger.error(f"Failed to commit transaction {self.transaction_id}: {str(e)}")
            raise
    
    def _rollback_transaction(self):
        """Rollback the transaction by restoring from backup."""
        try:
            # Delete temp files
            if self._path_exists(self.temp_path):
                self._delete_path(self.temp_path)
                logger.debug(f"Deleted temp path: {self.temp_path}")
            
            # Restore from backup if needed
            if self.backup_path and self._path_exists(self.backup_path):
                self._move_path(self.backup_path, self.target_path)
                logger.debug(f"Restored from backup: {self.backup_path}")
            
            logger.info(f"Transaction rolled back: {self.transaction_id}")
            
        except Exception as e:
            logger.error(f"Failed to rollback transaction {self.transaction_id}: {str(e)}")
            raise
    
    def _path_exists(self, path: str) -> bool:
        """Check if a path exists in ADLS."""
        try:
            # Try to get path properties - more reliable than get_paths
            paths = list(self.file_system_client.get_paths(path=path, max_results=1))
            return len(paths) > 0
        except ResourceNotFoundError:
            return False
        except Exception as e:
            logger.debug(f"Error checking path existence {path}: {str(e)}")
            return False
    
    def _move_path(self, source_path: str, dest_path: str):
        """Move a path from source to destination."""
        try:
            # List all files in source path
            source_paths = list(self.file_system_client.get_paths(path=source_path, recursive=True))
            
            for source_file in source_paths:
                if not source_file.is_directory:
                    # Calculate relative path
                    relative_path = source_file.name[len(source_path):].lstrip('/')
                    dest_file_path = f"{dest_path}/{relative_path}" if relative_path else dest_path
                    
                    # Get source file client
                    source_client = self.file_system_client.get_file_client(source_file.name)
                    dest_client = self.file_system_client.get_file_client(dest_file_path)
                    
                    # Copy data using safe upload method
                    download = source_client.download_file()
                    data = download.readall()
                    _adls_gen2_safe_upload(dest_client, data, overwrite=True)
            
            # Delete source after successful copy
            self._delete_path(source_path)
            
        except Exception as e:
            logger.error(f"Failed to move path {source_path} to {dest_path}: {str(e)}")
            raise
    
    def _merge_paths(self, source_path: str, dest_path: str):
        """Merge source path into destination path (for append mode)."""
        try:
            # List all files in source path
            source_paths = list(self.file_system_client.get_paths(path=source_path, recursive=True))
            
            for source_file in source_paths:
                if not source_file.is_directory:
                    # Generate unique filename for append
                    filename = source_file.name.split('/')[-1]
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    unique_filename = f"part-{timestamp}-{self.transaction_id}-{filename}"
                    dest_file_path = f"{dest_path}/{unique_filename}"
                    
                    # Copy file to destination using safe upload method
                    source_client = self.file_system_client.get_file_client(source_file.name)
                    dest_client = self.file_system_client.get_file_client(dest_file_path)
                    
                    download = source_client.download_file()
                    data = download.readall()
                    _adls_gen2_safe_upload(dest_client, data, overwrite=True)
            
            # Delete source after successful merge
            self._delete_path(source_path)
            
        except Exception as e:
            logger.error(f"Failed to merge path {source_path} into {dest_path}: {str(e)}")
            raise
    
    def _delete_path(self, path: str):
        """Delete a path and all its contents."""
        try:
            # List all files in path
            paths = list(self.file_system_client.get_paths(path=path, recursive=True))
            
            # Delete files first (reverse order to handle nested structures)
            for file_path in reversed(paths):
                if not file_path.is_directory:
                    file_client = self.file_system_client.get_file_client(file_path.name)
                    file_client.delete_file()
            
            # Delete directories
            for dir_path in reversed(paths):
                if dir_path.is_directory:
                    dir_client = self.file_system_client.get_directory_client(dir_path.name)
                    dir_client.delete_directory()
                    
        except Exception as e:
            logger.warning(f"Error deleting path {path}: {str(e)}")
    
    def get_temp_path(self) -> str:
        """Get the temporary path for writing."""
        return self.temp_path


class DirectADLSWriter:
    """
    Writes data directly to ADLS using Python SDK with user credentials.
    Provides transaction safety and rollback capabilities for write operations.
    
    All authentication mechanisms and ADLS client access is protected from user manipulation.
    UPDATED: Uses correct ADLS Gen2 API sequence to avoid x-ms-blob-type header issues.
    """
    
    def __init__(self, adls_client: DataLakeServiceClient, spark_session: SparkSession):
        """
        Initialize DirectADLSWriter with protected ADLS client.
        
        Args:
            adls_client: Authenticated ADLS client with user credentials (kept private)
            spark_session: Active Spark session for DataFrame operations
        """
        self.__adls_client = adls_client  # Private - protected from direct access
        self.spark = spark_session
        self.__lock = threading.Lock()  # Thread safety for sensitive operations
        
        # Security limits - these are protected from modification
        self.__max_files_per_write = 1000  # Safety limit
        self.__max_partition_files = 100  # Safety limit per partition
        self.__max_file_size_mb = 500  # Safety limit for individual files
        
        logger.debug("DirectADLSWriter initialized with protected ADLS client and ADLS Gen2 fix")
    
    @_protect_adls_method
    def write_text_files(self, dataframe: DataFrame, container: str, blob_path: str,
                        mode: str = 'error', partition_columns: List[str] = None,
                        options: Optional[Dict] = None) -> None:
        """
        Protected method to write text files directly to ADLS.
        This method is protected from direct user access.
        
        Args:
            dataframe: DataFrame to write
            container: ADLS container name
            blob_path: Target path for files
            mode: Write mode ('overwrite', 'append', 'ignore', 'error')
            partition_columns: Optional partition columns
            options: Additional writing options
        """
        try:
            with self.__lock:  # Thread-safe access to ADLS client
                file_system_client = self.__adls_client.get_file_system_client(container)
                
                # Filter sensitive options
                safe_options = self._filter_sensitive_options(options)
                encoding = safe_options.get('encoding', 'utf-8')
                
                # Use transaction context for safety
                with WriteTransactionContext(file_system_client, blob_path, mode, self.__adls_client.account_name) as tx:
                    if tx.committed:  # Skip if ignore mode and target exists
                        return
                    
                    write_path = tx.get_temp_path()
                    
                    if partition_columns:
                        self._write_partitioned_text_files(dataframe, file_system_client, write_path,
                                                         partition_columns, encoding, safe_options)
                    else:
                        self._write_single_text_file(dataframe, file_system_client, write_path,
                                                   encoding, safe_options)
                
                logger.info(f"Successfully wrote text files to {blob_path} (mode: {mode})")
                
        except Exception as e:
            logger.error(f"Failed to write text files to {blob_path}: {str(e)}")
            raise RuntimeError(f"Text file writing failed: {str(e)}")
    
    @_protect_adls_method  
    def write_json_files(self, dataframe: DataFrame, container: str, blob_path: str,
                        mode: str = 'error', partition_columns: List[str] = None,
                        options: Optional[Dict] = None) -> None:
        """
        Protected method to write JSON files directly to ADLS.
        This method is protected from direct user access.
        
        Args:
            dataframe: DataFrame to write
            container: ADLS container name
            blob_path: Target path for files
            mode: Write mode ('overwrite', 'append', 'ignore', 'error')
            partition_columns: Optional partition columns
            options: Additional writing options
        """
        try:
            with self.__lock:  # Thread-safe access to ADLS client
                file_system_client = self.__adls_client.get_file_system_client(container)
                
                # Filter sensitive options
                safe_options = self._filter_sensitive_options(options)
                
                # Use transaction context for safety
                with WriteTransactionContext(file_system_client, blob_path, mode, self.__adls_client.account_name) as tx:
                    if tx.committed:  # Skip if ignore mode and target exists
                        return
                    
                    write_path = tx.get_temp_path()
                    
                    if partition_columns:
                        self._write_partitioned_json_files(dataframe, file_system_client, write_path,
                                                         partition_columns, safe_options)
                    else:
                        self._write_single_json_file(dataframe, file_system_client, write_path, safe_options)
                
                logger.info(f"Successfully wrote JSON files to {blob_path} (mode: {mode})")
                
        except Exception as e:
            logger.error(f"Failed to write JSON files to {blob_path}: {str(e)}")
            raise RuntimeError(f"JSON file writing failed: {str(e)}")
    def _filter_sensitive_options(self, options: Optional[Dict]) -> Dict:
        """
        Filter out sensitive authentication options that users shouldn't control directly.
        
        Args:
            options: Dictionary of user-provided options (can be None)
            
        Returns:
            Dictionary with sensitive authentication options removed
        """
        if not options:
            return {}
        
        # Define sensitive keys that should be filtered out for security
        sensitive_keys = {
            'azure_storage_account_key', 
            'azure_storage_sas_token',
            'azure_tenant_id', 
            'azure_client_id', 
            'azure_client_secret',
            'fs.azure.account.auth.type', 
            'fs.azure.account.oauth.provider.type',
            'fs.azure.account.oauth2.client.id', 
            'fs.azure.account.oauth2.client.secret',
            'fs.azure.account.oauth2.client.endpoint',
            'fs.azure.account.oauth2.token.endpoint',
            # Additional sensitive patterns
            'azure_storage_connection_string',
            'fs.azure.sas',
            'fs.azure.account.key'
        }
        
        # Filter out sensitive options (case-insensitive comparison)
        filtered_options = {}
        for key, value in options.items():
            if key.lower() not in {sk.lower() for sk in sensitive_keys}:
                filtered_options[key] = value
            else:
                logger.warning(f"Filtered out sensitive authentication option: {key}")
        
        return filtered_options
        
    @_protect_adls_method
    def write_csv_files(self, dataframe: DataFrame, container: str, blob_path: str,
                       mode: str = 'error', partition_columns: List[str] = None,
                       options: Optional[Dict] = None) -> None:
        """
        Protected method to write CSV files directly to ADLS.
        This method is protected from direct user access.
        
        Args:
            dataframe: DataFrame to write
            container: ADLS container name
            blob_path: Target path for files
            mode: Write mode ('overwrite', 'append', 'ignore', 'error')
            partition_columns: Optional partition columns
            options: Additional writing options
        """
        try:
            with self.__lock:  # Thread-safe access to ADLS client
                file_system_client = self.__adls_client.get_file_system_client(container)
                
                # Filter sensitive options
                safe_options = self._filter_sensitive_options(options)
                
                # Use transaction context for safety
                with WriteTransactionContext(file_system_client, blob_path, mode, self.__adls_client.account_name) as tx:
                    if tx.committed:  # Skip if ignore mode and target exists
                        return
                    
                    write_path = tx.get_temp_path()
                    
                    if partition_columns:
                        self._write_partitioned_csv_files(dataframe, file_system_client, write_path,
                                                        partition_columns, safe_options)
                    else:
                        self._write_single_csv_file(dataframe, file_system_client, write_path, safe_options)
                
                logger.info(f"Successfully wrote CSV files to {blob_path} (mode: {mode})")
                
        except Exception as e:
            logger.error(f"Failed to write CSV files to {blob_path}: {str(e)}")
            raise RuntimeError(f"CSV file writing failed: {str(e)}")
        
    def _write_single_csv_file(self, dataframe: DataFrame, file_system_client: FileSystemClient,
                          target_path: str, options: Dict) -> None:
            """Write DataFrame as a single CSV file using ADLS Gen2 safe upload."""
            try:
                # Convert DataFrame to CSV
                pandas_df = dataframe.toPandas()
                
                # Extract CSV options with defaults
                header = options.get('header', True)
                separator = options.get('sep', ',')
                quote_char = options.get('quote', '"')
                escape_char = options.get('escape', '\\')
                null_value = options.get('nullValue', '')
                date_format = options.get('dateFormat', None)
                timestamp_format = options.get('timestampFormat', None)
                
                # Create CSV string using StringIO buffer
                csv_buffer = io.StringIO()
                
                # Convert to CSV with specified options
                pandas_df.to_csv(
                    csv_buffer, 
                    index=False, 
                    header=header, 
                    sep=separator,
                    quotechar=quote_char,
                    escapechar=escape_char,
                    na_rep=null_value,
                    date_format=date_format
                )
                
                csv_content = csv_buffer.getvalue()
                csv_buffer.close()
                
                # Create target file
                filename = "part-00000.csv"
                file_path = f"{target_path}/{filename}"
                
                # Upload CSV content using safe ADLS Gen2 method
                file_client = file_system_client.get_file_client(file_path)
                _adls_gen2_safe_upload(file_client, csv_content, overwrite=True)
                
                logger.debug(f"Wrote CSV file: {file_path} ({len(csv_content)} bytes)")
                
            except Exception as e:
                logger.error(f"Failed to write single CSV file: {str(e)}")
                raise
    @_protect_adls_method
    def write_binary_files(self, dataframe: DataFrame, container: str, blob_path: str,
                        mode: str = 'error', partition_columns: List[str] = None,
                        options: Optional[Dict] = None) -> None:
        """
        Protected method to write binary files directly to ADLS.
        Expected DataFrame schema: path (string), content (binary)
        This method is protected from direct user access.
        
        Args:
            dataframe: DataFrame to write (must have 'path' and 'content' columns)
            container: ADLS container name
            blob_path: Target path for files
            mode: Write mode ('overwrite', 'append', 'ignore', 'error')
            partition_columns: Optional partition columns
            options: Additional writing options
        """
        try:
            # Validate DataFrame schema for binary files
            required_columns = ['path', 'content']
            df_columns = set(dataframe.columns)
            missing_columns = set(required_columns) - df_columns
            
            if missing_columns:
                raise ValueError(f"DataFrame missing required columns for binary files: {missing_columns}")
            
            with self.__lock:  # Thread-safe access to ADLS client
                file_system_client = self.__adls_client.get_file_system_client(container)
                
                # Filter sensitive options
                safe_options = self._filter_sensitive_options(options)
                
                # Use transaction context for safety
                with WriteTransactionContext(file_system_client, blob_path, mode, self.__adls_client.account_name) as tx:
                    if tx.committed:  # Skip if ignore mode and target exists
                        return
                    
                    write_path = tx.get_temp_path()
                    
                    if partition_columns:
                        self._write_partitioned_binary_files(dataframe, file_system_client, write_path,
                                                        partition_columns, safe_options)
                    else:
                        self._write_single_binary_files(dataframe, file_system_client, write_path, safe_options)
                
                logger.info(f"Successfully wrote binary files to {blob_path} (mode: {mode})")
                
        except Exception as e:
            logger.error(f"Failed to write binary files to {blob_path}: {str(e)}")
            raise RuntimeError(f"Binary file writing failed: {str(e)}")

    def _write_single_binary_files(self, dataframe: DataFrame, file_system_client: FileSystemClient,
                                target_path: str, options: Dict) -> None:
        """Write DataFrame with binary content to individual files using ADLS Gen2 safe upload."""
        try:
            # Convert DataFrame to Pandas for easier binary handling
            pandas_df = dataframe.toPandas()
            
            for idx, row in pandas_df.iterrows():
                # Extract original filename from path
                original_path = row['path']
                filename = original_path.split('/')[-1] if '/' in original_path else f"binary_file_{idx}.bin"
                
                # Create target file path
                target_file_path = f"{target_path}/{filename}"
                
                # Upload binary content using safe method
                file_client = file_system_client.get_file_client(target_file_path)
                _adls_gen2_safe_upload(file_client, row['content'], overwrite=True)
                
                logger.debug(f"Wrote binary file: {target_file_path}")
                
        except Exception as e:
            logger.error(f"Failed to write binary files: {str(e)}")
            raise

    def _write_partitioned_binary_files(self, dataframe: DataFrame, file_system_client: FileSystemClient,
                                    target_path: str, partition_columns: List[str], options: Dict) -> None:
        """Write DataFrame with binary content as partitioned files using ADLS Gen2 safe upload."""
        try:
            # Convert to Pandas for partitioning
            pandas_df = dataframe.toPandas()
            
            # Group by partition columns
            grouped = pandas_df.groupby(partition_columns)
            
            for partition_values, group_df in grouped:
                # Create partition directory structure
                if len(partition_columns) == 1:
                    partition_values = [partition_values]
                
                partition_path_parts = []
                for i, col in enumerate(partition_columns):
                    partition_path_parts.append(f"{col}={partition_values[i]}")
                
                partition_dir = "/".join(partition_path_parts)
                full_partition_path = f"{target_path}/{partition_dir}"
                
                # Write each binary file in the partition
                for idx, row in group_df.iterrows():
                    # Extract original filename from path
                    original_path = row['path']
                    filename = original_path.split('/')[-1] if '/' in original_path else f"binary_file_{idx}.bin"
                    
                    # Create partition file path
                    file_path = f"{full_partition_path}/{filename}"
                    
                    # Upload binary content
                    file_client = file_system_client.get_file_client(file_path)
                    _adls_gen2_safe_upload(file_client, row['content'], overwrite=True)
                    
                    logger.debug(f"Wrote partitioned binary file: {file_path}")
                    
        except Exception as e:
            logger.error(f"Failed to write partitioned binary files: {str(e)}")
            raise
            
    def _write_single_text_file(self, dataframe: DataFrame, file_system_client: FileSystemClient,
                            target_path: str, encoding: str, options: Dict) -> None:
        """Write DataFrame as a single text file using ADLS Gen2 safe upload."""
        try:
            # Convert DataFrame to text content
            pandas_df = dataframe.toPandas()
            
            # Handle different text output formats
            if 'content' in pandas_df.columns:
                # DataFrame has a content column - use it directly
                text_content = '\n'.join(pandas_df['content'].astype(str))
            else:
                # Convert entire DataFrame to text representation
                text_content = pandas_df.to_string(index=False)
            
            # Create target file
            filename = f"part-00000.txt"
            file_path = f"{target_path}/{filename}"
            
            file_client = file_system_client.get_file_client(file_path)
            
            # Upload text content using safe ADLS Gen2 method
            _adls_gen2_safe_upload(file_client, text_content, overwrite=True)
            
            logger.debug(f"Wrote text file: {file_path}")
            
        except Exception as e:
            logger.error(f"Failed to write single text file: {str(e)}")
            raise

    def _write_partitioned_text_files(self, dataframe: DataFrame, file_system_client: FileSystemClient,
                                    target_path: str, partition_columns: List[str], 
                                    encoding: str, options: Dict) -> None:
        """Write DataFrame as partitioned text files using ADLS Gen2 safe upload."""
        try:
            # Convert to Pandas for partitioning
            pandas_df = dataframe.toPandas()
            
            # Group by partition columns
            grouped = pandas_df.groupby(partition_columns)
            
            for partition_values, group_df in grouped:
                # Create partition directory structure
                if len(partition_columns) == 1:
                    partition_values = [partition_values]
                
                partition_path_parts = []
                for i, col in enumerate(partition_columns):
                    partition_path_parts.append(f"{col}={partition_values[i]}")
                
                partition_dir = "/".join(partition_path_parts)
                full_partition_path = f"{target_path}/{partition_dir}"
                
                # Write partition data
                if 'content' in group_df.columns:
                    text_content = '\n'.join(group_df['content'].astype(str))
                else:
                    # Drop partition columns from output and convert to text
                    output_df = group_df.drop(columns=partition_columns)
                    text_content = output_df.to_string(index=False)
                
                # Create partition file
                filename = f"part-00000.txt"
                file_path = f"{full_partition_path}/{filename}"
                
                file_client = file_system_client.get_file_client(file_path)
                _adls_gen2_safe_upload(file_client, text_content, overwrite=True)
                
                logger.debug(f"Wrote partitioned text file: {file_path}")
                
        except Exception as e:
            logger.error(f"Failed to write partitioned text files: {str(e)}")
            raise
    def validate_dataframe_for_format(self, dataframe: DataFrame, format_type: str) -> List[str]:
        """
        Validate DataFrame schema compatibility with target format.
        
        Args:
            dataframe: DataFrame to validate
            format_type: Target format ('csv', 'json', 'text', 'binaryfile')
            
        Returns:
            List of validation warnings/errors
        """
        warnings = []
        df_columns = set(dataframe.columns)
        
        if format_type.lower() == 'binaryfile':
            required_columns = {'path', 'content'}
            missing = required_columns - df_columns
            if missing:
                warnings.append(f"Binary format requires columns: {missing}")
            
            # Check if content column is actually binary type
            try:
                content_type = dict(dataframe.dtypes)['content']
                if content_type != 'binary':
                    warnings.append(f"Content column should be binary type, got: {content_type}")
            except KeyError:
                pass
        
        elif format_type.lower() == 'text':
            # For text format, either need 'content' column or will convert entire DF
            if 'content' not in df_columns:
                warnings.append("Text format: no 'content' column found, will convert entire DataFrame")
        
        # Check for problematic column names
        problematic_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        for col in df_columns:
            if any(char in col for char in problematic_chars):
                warnings.append(f"Column '{col}' contains characters that may cause issues in file systems")
        
        return warnings

    def estimate_write_size(self, dataframe: DataFrame) -> Dict[str, Any]:
        """
        Estimate the size and complexity of the write operation.
        
        Args:
            dataframe: DataFrame to analyze
            
        Returns:
            Dictionary with size estimates
        """
        try:
            row_count = dataframe.count()
            column_count = len(dataframe.columns)
            
            # Estimate size based on DataFrame characteristics
            estimated_mb = (row_count * column_count * 50) / (1024 * 1024)  # Rough estimate
            
            return {
                'row_count': row_count,
                'column_count': column_count,
                'estimated_size_mb': estimated_mb,
                'exceeds_single_file_limit': estimated_mb > self.__max_file_size_mb,
                'exceeds_safety_limits': row_count > 1000000,  # 1M row safety limit
                'recommended_partitions': max(1, int(estimated_mb / 100))  # 100MB per partition
            }
            
        except Exception as e:
            return {
                'error': f"Failed to estimate write size: {str(e)}",
                'row_count': -1,
                'column_count': len(dataframe.columns),
                'estimated_size_mb': -1
            }

    def get_write_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about write operations performed by this writer instance.
        """
        # This would require adding instance variables to track stats
        return {
            'operations_supported': self.get_supported_write_operations(),
            'modes_supported': self.get_supported_write_modes(),
            'max_files_per_write': self.__max_files_per_write,
            'max_file_size_mb': self.__max_file_size_mb,
            'adls_gen2_safe_upload': True,
            'transaction_safety': True
        }

    def cleanup_failed_writes(self, container: str, pattern: str = "*_temp_*") -> Dict[str, Any]:
        """
        Clean up temporary files from failed write operations.
        
        Args:
            container: ADLS container to clean
            pattern: Pattern to match temporary files
            
        Returns:
            Dictionary with cleanup results
        """
        try:
            with self.__lock:
                file_system_client = self.__adls_client.get_file_system_client(container)
                
                # Find temporary files
                temp_files = []
                paths = file_system_client.get_paths(recursive=True)
                
                for path in paths:
                    if not path.is_directory and pattern.replace("*", "") in path.name:
                        temp_files.append(path.name)
                
                # Delete temporary files
                deleted_count = 0
                for temp_file in temp_files:
                    try:
                        file_client = file_system_client.get_file_client(temp_file)
                        file_client.delete_file()
                        deleted_count += 1
                    except Exception as e:
                        logger.warning(f"Failed to delete temp file {temp_file}: {str(e)}")
                
                return {
                    'success': True,
                    'temp_files_found': len(temp_files),
                    'temp_files_deleted': deleted_count,
                    'container': container
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'container': container
            }

    # Enhanced error handling wrapper
    def _safe_write_operation(operation_name: str):
        """
        Decorator for safe write operations with comprehensive error handling.
        """
        def decorator(method):
            @wraps(method)
            def wrapper(self, *args, **kwargs):
                start_time = datetime.now()
                operation_id = str(uuid.uuid4())[:8]
                
                logger.info(f"Starting {operation_name} operation: {operation_id}")
                
                try:
                    # Pre-operation validation
                    if len(args) > 0 and hasattr(args[0], 'count'):  # DataFrame check
                        df = args[0]
                        size_info = self.estimate_write_size(df)
                        if size_info.get('exceeds_safety_limits'):
                            logger.warning(f"Write operation {operation_id} exceeds safety limits: {size_info}")
                    
                    # Execute the operation
                    result = method(self, *args, **kwargs)
                    
                    # Log success
                    duration = (datetime.now() - start_time).total_seconds()
                    logger.info(f"Completed {operation_name} operation: {operation_id} in {duration:.2f}s")
                    
                    return result
                    
                except Exception as e:
                    # Log failure with context
                    duration = (datetime.now() - start_time).total_seconds()
                    logger.error(f"Failed {operation_name} operation: {operation_id} after {duration:.2f}s - {str(e)}")
                    
                    # Attempt cleanup if needed
                    try:
                        if len(args) > 1:  # container is usually second argument
                            container = args[1]
                            cleanup_result = self.cleanup_failed_writes(container, f"*_temp_{operation_id}*")
                            if cleanup_result['success']:
                                logger.info(f"Cleaned up {cleanup_result['temp_files_deleted']} temporary files")
                    except:
                        pass  # Cleanup is best effort
                    
                    raise RuntimeError(f"{operation_name} operation failed: {str(e)}")
            
            return wrapper
        return decorator

        