"""
UC Passthrough Library - DataFrame Reader Module

This module provides the main Spark API wrapper that intelligently routes data access
between Unity Catalog governance and direct ADLS access with user credentials.
"""

import logging
from typing import Optional, Dict, Any, Union, List
from urllib.parse import urlparse
import json

try:
    from pyspark.sql import DataFrame, SparkSession
    from pyspark.sql.types import StructType
except ImportError as e:
    raise ImportError(
        f"PySpark not found: {e}. "
        f"This library requires PySpark to be installed and available."
    )

try:
    from azure.storage.filedatalake import DataLakeServiceClient, FileSystemClient
    import pandas as pd
except ImportError as e:
    raise ImportError(
        f"Required Azure libraries not found: {e}. "
        f"Please install: pip install azure-storage-file-datalake pandas"
    )

# Import our custom classes
from path_analyzer import PathAnalyzer
from authentication_manager import AuthenticationManager

logger = logging.getLogger(__name__)


class UCPassthroughFormatReader:
    """
    Format-specific reader that handles the actual data loading logic.
    This class is created by UCPassthroughDataFrameReader.format() calls.
    """
    
    def __init__(self, format_type: str, spark_session: SparkSession, 
                 auth_manager: AuthenticationManager, path_analyzer: PathAnalyzer):
        """
        Initialize format reader.
        
        Args:
            format_type: Spark format type (e.g., 'delta', 'parquet', 'text')
            spark_session: Active Spark session
            auth_manager: Authentication manager for ADLS access
            path_analyzer: Path analyzer for routing decisions
        """
        self.format_type = format_type
        self.spark = spark_session
        self.auth_manager = auth_manager
        self.path_analyzer = path_analyzer
        self.options = {}
        self.schema = None
        
        logger.debug(f"Created format reader for: {format_type}")
    
    def option(self, key: str, value: Any) -> 'UCPassthroughFormatReader':
        """
        Add option for data reading.
        
        Args:
            key: Option key
            value: Option value
            
        Returns:
            Self for method chaining
        """
        self.options[key] = value
        return self
    
    def options(self, **options) -> 'UCPassthroughFormatReader':
        """
        Add multiple options for data reading.
        
        Args:
            **options: Key-value option pairs
            
        Returns:
            Self for method chaining
        """
        self.options.update(options)
        return self
    
    def schema(self, schema: Union[StructType, str]) -> 'UCPassthroughFormatReader':
        """
        Set schema for data reading.
        
        Args:
            schema: StructType or DDL string schema
            
        Returns:
            Self for method chaining
        """
        self.schema = schema
        return self
    
    def load(self, path: Optional[str] = None) -> DataFrame:
        """
        Load data from specified path with intelligent routing.
        
        Args:
            path: Optional path to load data from
            
        Returns:
            Spark DataFrame
            
        Raises:
            ValueError: If path cannot be determined or routing fails
            RuntimeError: If data loading fails
        """
        if not path:
            raise ValueError("Path must be specified for load operation")
        
        # Check for explicit override in options
        explicit_override = self.options.get('uc_passthrough_override')
        
        try:
            # Analyze path to determine routing
            access_method, analysis = self.path_analyzer.analyze_path(
                path=path,
                format_type=self.format_type,
                explicit_override=explicit_override
            )
            
            logger.info(f"Loading {path} via {access_method} method")
            logger.debug(f"Routing reasoning: {'; '.join(analysis['reasoning'])}")
            
            if access_method == 'uc':
                return self._load_via_unity_catalog(path)
            else:  # access_method == 'adls'
                return self._load_via_adls_direct(path)
                
        except Exception as e:
            logger.error(f"Failed to load data from {path}: {str(e)}")
            raise RuntimeError(f"Data loading failed: {str(e)}")
    
    def _load_via_unity_catalog(self, path: str) -> DataFrame:
        """
        Load data using standard Unity Catalog governance flow.
        
        Args:
            path: Path to load data from
            
        Returns:
            Spark DataFrame loaded via Unity Catalog
        """
        logger.debug(f"Loading via Unity Catalog: {path}")
        
        # Create standard Spark DataFrameReader
        reader = self.spark.read.format(self.format_type)
        
        # Apply options (excluding our custom options)
        filtered_options = {k: v for k, v in self.options.items() 
                          if not k.startswith('uc_passthrough_')}
        
        for key, value in filtered_options.items():
            reader = reader.option(key, value)
        
        # Apply schema if provided
        if self.schema:
            reader = reader.schema(self.schema)
        
        # Load using standard Spark/UC flow
        return reader.load(path)
    
    def _load_via_adls_direct(self, path: str) -> DataFrame:
        """
        Load data using direct ADLS access with user credentials.
        
        Args:
            path: Path to load data from
            
        Returns:
            Spark DataFrame loaded via direct ADLS access
        """
        logger.debug(f"Loading via ADLS direct access: {path}")
        
        # Ensure user is authenticated
        if not self.auth_manager.is_authenticated():
            raise RuntimeError("User not authenticated for ADLS direct access")
        
        # Parse ADLS path
        storage_account_url, container, blob_path = self._parse_adls_path(path)
        
        # Get authenticated ADLS client
        adls_client = self.auth_manager.get_adls_client(storage_account_url)
        
        # Import DirectADLSReader
        from direct_adls_reader import DirectADLSReader
        
        # Create direct ADLS reader
        direct_reader = DirectADLSReader(adls_client, self.spark)
        
        # Handle different format types using direct reading approach
        format_lower = self.format_type.lower()
        
        if format_lower == 'text':
            return direct_reader.read_text_files(container, blob_path, 
                                               encoding=self.options.get('encoding'),
                                               options=self.options)
        elif format_lower == 'binaryfile':
            return direct_reader.read_binary_files(container, blob_path, options=self.options)
        elif format_lower == 'json':
            return direct_reader.read_json_files(container, blob_path, options=self.options)
        elif format_lower == 'csv':
            return direct_reader.read_csv_files(container, blob_path, options=self.options)
        elif format_lower in ['parquet', 'delta', 'orc', 'avro']:
            # For structured formats routed to ADLS direct, still try direct approach
            # but fall back to UC governance if it fails
            try:
                logger.info(f"Attempting direct read of structured format {format_lower}")
                return self._load_structured_format_direct(direct_reader, container, blob_path)
            except Exception as e:
                logger.warning(f"Direct structured format read failed, falling back to UC: {str(e)}")
                return self._load_via_unity_catalog(path)
        else:
            raise ValueError(f"Unsupported format for ADLS direct access: {self.format_type}")
    
    def _parse_adls_path(self, path: str) -> tuple:
        """
        Parse ADLS path into components.
        
        Args:
            path: ADLS path (e.g., abfss://container@account.dfs.core.windows.net/path/file)
            
        Returns:
            Tuple of (storage_account_url, container, blob_path)
        """
        if not path.startswith('abfss://'):
            raise ValueError(f"Expected abfss:// path for ADLS access, got: {path}")
        
        parsed = urlparse(path)
        
        # Extract container and account from netloc
        # Format: container@account.dfs.core.windows.net
        netloc_parts = parsed.netloc.split('@')
        if len(netloc_parts) != 2:
            raise ValueError(f"Invalid ADLS path format: {path}")
        
        container = netloc_parts[0]
        account_host = netloc_parts[1]
        
        storage_account_url = f"https://{account_host}"
        blob_path = parsed.path.lstrip('/')
        
        return storage_account_url, container, blob_path
    
    def _load_structured_format_direct(self, direct_reader: 'DirectADLSReader', 
                                      container: str, blob_path: str) -> DataFrame:
        """
        Attempt to load structured formats using direct ADLS access.
        
        This is a fallback for when structured formats are routed to ADLS direct
        but we want to try reading them without Spark token injection.
        
        Args:
            direct_reader: DirectADLSReader instance
            container: ADLS container
            blob_path: Blob path within container
            
        Returns:
            Spark DataFrame
        """
        format_lower = self.format_type.lower()
        
        if format_lower == 'parquet':
            # Read parquet files as binary, then use PyArrow to parse
            try:
                import pyarrow.parquet as pq
                import pyarrow as pa
                
                # Get ADLS client and read file(s) directly
                adls_client = direct_reader.adls_client
                file_system_client = adls_client.get_file_system_client(container)
                
                # For now, handle single parquet files
                file_client = file_system_client.get_file_client(blob_path)
                download = file_client.download_file()
                content_bytes = download.readall()
                
                # Read parquet from bytes using PyArrow
                parquet_file = pq.read_table(pa.BufferReader(content_bytes))
                pandas_df = parquet_file.to_pandas()
                
                # Convert to Spark DataFrame
                return self.spark.createDataFrame(pandas_df)
                
            except ImportError:
                raise RuntimeError("PyArrow required for direct parquet reading. Install: pip install pyarrow")
            
        else:
            # For other structured formats (delta, orc, avro), fall back to UC
            raise ValueError(f"Direct reading not supported for {format_lower} format")
    
    def _verify_directory_access(self, file_system_client: FileSystemClient, blob_path: str):
        """
        Verify user has access to directory by attempting to list files.
        
        Args:
            file_system_client: Authenticated ADLS file system client
            blob_path: Directory path to verify
            
        Raises:
            RuntimeError: If access verification fails
        """
        try:
            # Remove trailing slash and wildcards for directory listing
            dir_path = blob_path.rstrip('/').split('*')[0]
            
            # Attempt to list directory contents
            paths = file_system_client.get_paths(path=dir_path, max_results=1)
            list(paths)  # Consume iterator to trigger API call
            
        except Exception as e:
            raise RuntimeError(f"Access denied to directory {blob_path}: {str(e)}")


# Remove the old methods that are no longer needed
# _load_text_based_format, _load_binary_format, _load_structured_format_with_user_auth, _load_with_temporary_credentials
            
            # Use Spark with temporary SAS token or delegated credentials
            return self._load_with_temporary_credentials(original_path)
            
        except Exception as e:
            logger.error(f"Failed to load text format via ADLS: {str(e)}")
            raise RuntimeError(f"ADLS direct access failed: {str(e)}")
    
    def _load_binary_format(self, file_system_client: FileSystemClient, 
                           blob_path: str, original_path: str) -> DataFrame:
        """
        Load binary formats via ADLS direct access.
        
        Args:
            file_system_client: Authenticated ADLS file system client
            blob_path: Blob path within container
            original_path: Original path for Spark operations
            
        Returns:
            Spark DataFrame with binary content
        """
        try:
            # For binary files, verify access and use Spark with temp credentials
            if blob_path.endswith('/') or '*' in blob_path:
                self._verify_directory_access(file_system_client, blob_path)
            else:
                file_client = file_system_client.get_file_client(blob_path)
                file_client.get_file_properties()
            
            return self._load_with_temporary_credentials(original_path)
            
        except Exception as e:
            logger.error(f"Failed to load binary format via ADLS: {str(e)}")
            raise RuntimeError(f"ADLS direct access failed: {str(e)}")
    
    def _load_structured_format_with_user_auth(self, path: str) -> DataFrame:
        """
        Load structured formats (parquet, delta, etc.) with user authentication.
        
        For structured formats routed to ADLS direct access, we still use Spark
        but with user-scoped credentials to ensure RBAC is respected.
        
        Args:
            path: Path to load data from
            
        Returns:
            Spark DataFrame
        """
        try:
            # Get user's ADLS access token
            access_token = self.auth_manager.get_adls_access_token()
            
            # Create Spark reader with user token
            reader = self.spark.read.format(self.format_type)
            
            # Apply user authentication via Spark configuration
            # Note: This requires setting temporary Spark configuration with user token
            reader = reader.option("spark.databricks.passthrough.adls.token", access_token)
            
            # Apply other options
            filtered_options = {k: v for k, v in self.options.items() 
                              if not k.startswith('uc_passthrough_')}
            for key, value in filtered_options.items():
                reader = reader.option(key, value)
            
            if self.schema:
                reader = reader.schema(self.schema)
            
            return reader.load(path)
            
        except Exception as e:
            logger.error(f"Failed to load structured format with user auth: {str(e)}")
            raise RuntimeError(f"Structured format loading failed: {str(e)}")
    
    def _verify_directory_access(self, file_system_client: FileSystemClient, blob_path: str):
        """
        Verify user has access to directory by attempting to list files.
        
        Args:
            file_system_client: Authenticated ADLS file system client
            blob_path: Directory path to verify
            
        Raises:
            RuntimeError: If access verification fails
        """
        try:
            # Remove trailing slash and wildcards for directory listing
            dir_path = blob_path.rstrip('/').split('*')[0]
            
            # Attempt to list directory contents
            paths = file_system_client.get_paths(path=dir_path, max_results=1)
            list(paths)  # Consume iterator to trigger API call
            
        except Exception as e:
            raise RuntimeError(f"Access denied to directory {blob_path}: {str(e)}")
    
    def _load_with_temporary_credentials(self, path: str) -> DataFrame:
        """
        Load data using Spark with temporary user credentials.
        
        This is a simplified implementation. In practice, you would need to:
        1. Generate SAS tokens with user's permissions
        2. Or configure Spark session with user's access token
        3. Or use Databricks credential passthrough mechanisms
        
        Args:
            path: Path to load data from
            
        Returns:
            Spark DataFrame
        """
        try:
            # Get user's access token
            access_token = self.auth_manager.get_adls_access_token()
            
            # Create reader with temporary authentication
            reader = self.spark.read.format(self.format_type)
            
            # Set temporary authentication (implementation depends on Databricks internals)
            # This is a placeholder - actual implementation would require integration
            # with Databricks' credential management system
            reader = reader.option("spark.databricks.adls.user.token", access_token)
            
            # Apply options
            filtered_options = {k: v for k, v in self.options.items() 
                              if not k.startswith('uc_passthrough_')}
            for key, value in filtered_options.items():
                reader = reader.option(key, value)
            
            if self.schema:
                reader = reader.schema(self.schema)
            
            return reader.load(path)
            
        except Exception as e:
            logger.error(f"Failed to load with temporary credentials: {str(e)}")
            # Fallback to standard UC loading
            logger.warning("Falling back to Unity Catalog governance")
            return self._load_via_unity_catalog(path)


class UCPassthroughDataFrameReader:
    """
    Main DataFrame reader that provides drop-in replacement for spark.read
    with intelligent routing between Unity Catalog and direct ADLS access.
    """
    
    def __init__(self, spark_session: SparkSession, auth_manager: AuthenticationManager, 
                 path_analyzer: PathAnalyzer):
        """
        Initialize the passthrough DataFrame reader.
        
        Args:
            spark_session: Active Spark session
            auth_manager: Authentication manager for ADLS access
            path_analyzer: Path analyzer for routing decisions
        """
        self.spark = spark_session
        self.auth_manager = auth_manager
        self.path_analyzer = path_analyzer
        
        logger.debug("UCPassthroughDataFrameReader initialized")
    
    def format(self, source: str) -> UCPassthroughFormatReader:
        """
        Specify format for reading data.
        
        Args:
            source: Data source format (e.g., 'delta', 'parquet', 'text', 'binaryFile')
            
        Returns:
            UCPassthroughFormatReader for method chaining
        """
        return UCPassthroughFormatReader(
            format_type=source,
            spark_session=self.spark,
            auth_manager=self.auth_manager,
            path_analyzer=self.path_analyzer
        )
    
    def option(self, key: str, value: Any) -> UCPassthroughFormatReader:
        """
        Set option and return a format reader (for compatibility with spark.read.option().load()).
        Note: This assumes a default format and should generally be used after format().
        
        Args:
            key: Option key
            value: Option value
            
        Returns:
            UCPassthroughFormatReader with option applied
        """
        logger.warning("Using option() without format() - defaulting to 'text' format")
        return self.format('text').option(key, value)
    
    def options(self, **options) -> UCPassthroughFormatReader:
        """
        Set multiple options and return a format reader.
        
        Args:
            **options: Key-value option pairs
            
        Returns:
            UCPassthroughFormatReader with options applied
        """
        logger.warning("Using options() without format() - defaulting to 'text' format")
        return self.format('text').options(**options)
    
    def schema(self, schema: Union[StructType, str]) -> UCPassthroughFormatReader:
        """
        Set schema and return a format reader.
        
        Args:
            schema: StructType or DDL string schema
            
        Returns:
            UCPassthroughFormatReader with schema applied
        """
        logger.warning("Using schema() without format() - defaulting to 'parquet' format")
        return self.format('parquet').schema(schema)
    
    def load(self, path: str, format: Optional[str] = None) -> DataFrame:
        """
        Direct load method for simple use cases.
        
        Args:
            path: Path to load data from
            format: Optional format specification
            
        Returns:
            Spark DataFrame
        """
        if format:
            return self.format(format).load(path)
        else:
            # Try to infer format from path
            inferred_format = self._infer_format_from_path(path)
            return self.format(inferred_format).load(path)
    
    def _infer_format_from_path(self, path: str) -> str:
        """
        Infer format from file extension.
        
        Args:
            path: File path
            
        Returns:
            Inferred format string
        """
        import os
        
        _, ext = os.path.splitext(path.lower())
        
        format_mapping = {
            '.delta': 'delta',
            '.parquet': 'parquet',
            '.json': 'json',
            '.csv': 'csv',
            '.txt': 'text',
            '.log': 'text',
            '.xml': 'xml',
            '.orc': 'orc',
            '.avro': 'avro'
        }
        
        return format_mapping.get(ext, 'text')  # Default to text


# # Example usage and testing
# if __name__ == "__main__":
#     # Configure logging
#     logging.basicConfig(level=logging.INFO)
    
#     print("UCPassthroughDataFrameReader class created successfully")
#     print("This class provides drop-in replacement for spark.read with intelligent routing")
#     print("\nUsage examples:")
#     print("1. reader = UCPassthroughDataFrameReader(spark, auth_manager, path_analyzer)")
#     print("2. df = reader.format('text').load('abfss://container@storage.dfs.core.windows.net/raw/logs/')")
#     print("3. df = reader.format('delta').load('/Volumes/catalog/schema/volume/table.delta')")
#     print("4. df = reader.format('parquet').option('key', 'value').load('path/to/data.parquet')")
