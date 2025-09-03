"""
UC Passthrough Library - Unified DataFrame Interface

This module provides a single unified interface for both read and write operations
that intelligently routes between Unity Catalog governance and direct ADLS access.
All sensitive authentication mechanisms and tokens are protected from user manipulation.
"""

import logging
from typing import Optional, Dict, Any, Union, List
from urllib.parse import urlparse
import threading
from functools import wraps
import uuid
import os

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
from direct_adls_reader import DirectADLSReader
from direct_adls_writer import DirectADLSWriter

logger = logging.getLogger(__name__)


def _protect_auth_method(method):
    """Decorator to protect authentication-related methods from external access."""
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        # Check if being called from within the same module/trusted context
        import inspect
        frame = inspect.currentframe().f_back
        caller_module = frame.f_globals.get('__name__', '')
        
        # Allow calls from within this module or trusted modules
        if not (caller_module.startswith(__name__) or 
                caller_module in ['authentication_manager', 'direct_adls_reader', 'direct_adls_writer']):
            raise PermissionError("Direct access to authentication methods is restricted")
        
        return method(self, *args, **kwargs)
    return wrapper


class UCPassthroughFormatReader:
    """
    Format-specific reader that handles the actual data loading logic.
    This class is created by UCPassthroughDataFrameInterface.read.format() calls.
    Sensitive authentication details are protected from user manipulation.
    """
    
    def __init__(self, format_type: str, spark_session: SparkSession, 
                 auth_manager: AuthenticationManager, path_analyzer: PathAnalyzer,
                 adls_client=None):
        """
        Initialize format reader.
        
        Args:
            format_type: Spark format type (e.g., 'delta', 'parquet', 'text')
            spark_session: Active Spark session
            auth_manager: Authentication manager for ADLS access
            path_analyzer: Path analyzer for routing decisions
            adls_client: Pre-created ADLS client
        """
        self.format_type = format_type
        self.spark = spark_session
        self.__auth_manager = auth_manager  # Private attribute
        self.__path_analyzer = path_analyzer  # Private attribute
        self.__adls_client = adls_client  # Private attribute - pre-created client
        self.options = {}
        self.schema = None
        self.__lock = threading.Lock()  # Thread safety for sensitive operations
        logger.debug(f"Created format reader for: {format_type}, ADLS client available: {self.__adls_client is not None}")
    
    def option(self, key: str, value: Any) -> 'UCPassthroughFormatReader':
        """
        Add option for data reading. Sensitive auth options are filtered.
        
        Args:
            key: Option key
            value: Option value
            
        Returns:
            Self for method chaining
        """
        # Filter out sensitive authentication options that users shouldn't set directly
        sensitive_keys = {
            'azure_storage_account_key', 'azure_storage_sas_token',
            'azure_tenant_id', 'azure_client_id', 'azure_client_secret',
            'fs.azure.account.auth.type', 'fs.azure.account.oauth.provider.type',
            'fs.azure.account.oauth2.client.id', 'fs.azure.account.oauth2.client.secret'
        }
        
        if key.lower() in sensitive_keys:
            logger.warning(f"Ignoring sensitive authentication option: {key}")
            return self
        
        self.options[key] = value
        return self
    
    def options(self, **options) -> 'UCPassthroughFormatReader':
        """
        Add multiple options for data reading. Sensitive auth options are filtered.
        
        Args:
            **options: Key-value option pairs
            
        Returns:
            Self for method chaining
        """
        for key, value in options.items():
            self.option(key, value)  # Uses filtering logic from option()
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
        Authentication is handled securely internally.
        
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
        
        # Check for explicit override in options (non-auth overrides only)
        explicit_override = self.options.get('uc_passthrough_override')
        
        try:
            with self.__lock:  # Thread-safe access to sensitive operations
                # Analyze path to determine routing
                access_method, analysis = self.__path_analyzer.analyze_path(
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
        print("✓ Reading via UC")
        
        # Create standard Spark DataFrameReader
        reader = self.spark.read.format(self.format_type)
        
        # Apply options (excluding our custom options and any sensitive ones)
        filtered_options = {
            k: v for k, v in self.options.items() 
            if not k.startswith('uc_passthrough_') and 
               k.lower() not in {'azure_storage_account_key', 'azure_storage_sas_token',
                                'azure_tenant_id', 'azure_client_id', 'azure_client_secret'}
        }
        
        for key, value in filtered_options.items():
            reader = reader.option(key, value)
        
        # Apply schema if provided
        if self.schema:
            reader = reader.schema(self.schema)
        
        # Load using standard Spark/UC flow
        return reader.load(path)
    
    @_protect_auth_method
    def _load_via_adls_direct(self, path: str) -> DataFrame:
        """
        Load data using direct ADLS access with user credentials.
        This method is protected from direct external access.
        
        Args:
            path: Path to load data from
            
        Returns:
            Spark DataFrame loaded via direct ADLS access
        """
        logger.debug(f"Loading via ADLS direct access: {path}")
        print("✓ Reading via Passthrough")
        
        with self.__lock:  # Thread-safe access to auth manager
            # Ensure user is authenticated
            if not self.__auth_manager.is_authenticated():
                raise RuntimeError("User not authenticated for ADLS direct access")
            
            # Use the pre-created ADLS client
            if not self.__adls_client:
                raise RuntimeError("ADLS client not available for direct access")
            
            # Parse ADLS path
            storage_account_url, container, blob_path = self.__parse_adls_path(path)
        
        # Create direct ADLS reader with pre-created client
        direct_reader = DirectADLSReader(self.__adls_client, self.spark)
        
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
                return self.__load_structured_format_direct(direct_reader, container, blob_path)
            except Exception as e:
                logger.warning(f"Direct structured format read failed, falling back to UC: {str(e)}")
                return self._load_via_unity_catalog(path)
        else:
            raise ValueError(f"Unsupported format for ADLS direct access: {self.format_type}")
    
    def __parse_adls_path(self, path: str) -> tuple:
        """
        Private method to parse ADLS path into components.
        
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
    
    def __load_structured_format_direct(self, direct_reader: 'DirectADLSReader', 
                                       container: str, blob_path: str) -> DataFrame:
        """
        Private method to attempt loading structured formats using direct ADLS access.
        
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
                adls_client = direct_reader._get_adls_client_internal()
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


class UCPassthroughFormatWriter:
    """
    Format-specific writer that handles the actual data writing logic.
    This class is created by UCPassthroughDataFrameInterface.write.format() calls.
    Sensitive authentication details are protected from user manipulation.
    """
    
    def __init__(self, dataframe: DataFrame, format_type: str, spark_session: SparkSession,
                 auth_manager: AuthenticationManager, path_analyzer: PathAnalyzer,
                 adls_client=None):
        """
        Initialize format writer.
        
        Args:
            dataframe: DataFrame to write
            format_type: Spark format type (e.g., 'delta', 'parquet', 'text')
            spark_session: Active Spark session
            auth_manager: Authentication manager for ADLS access
            path_analyzer: Path analyzer for routing decisions
            adls_client: Pre-created ADLS client
        """
        self.dataframe = dataframe
        self.format_type = format_type
        self.spark = spark_session
        self.__auth_manager = auth_manager  # Private attribute
        self.__path_analyzer = path_analyzer  # Private attribute
        self.__adls_client = adls_client  # Private attribute - pre-created client
        self.options = {}
        self.write_mode = 'error'  # Default write mode (errorifexists)
        self.partition_columns = []
        self.__lock = threading.Lock()  # Thread safety for sensitive operations
        logger.debug(f"Created format writer for: {format_type}, ADLS client available: {self.__adls_client is not None}")
    
    def mode(self, saveMode: str) -> 'UCPassthroughFormatWriter':
        """
        Specify save mode for writing data.
        
        Args:
            saveMode: Save mode ('overwrite', 'append', 'ignore', 'error'/'errorifexists')
            
        Returns:
            Self for method chaining
        """
        # Normalize mode names
        mode_mapping = {
            'errorifexists': 'error',
            'failifexists': 'error'
        }
        normalized_mode = mode_mapping.get(saveMode.lower(), saveMode.lower())
        
        if normalized_mode not in ['overwrite', 'append', 'ignore', 'error']:
            raise ValueError(f"Invalid save mode: {saveMode}. Must be one of: overwrite, append, ignore, error")
        
        self.write_mode = normalized_mode
        logger.debug(f"Set write mode to: {normalized_mode}")
        return self
    
    def option(self, key: str, value: Any) -> 'UCPassthroughFormatWriter':
        """
        Add option for data writing. Sensitive auth options are filtered.
        
        Args:
            key: Option key
            value: Option value
            
        Returns:
            Self for method chaining
        """
        # Filter out sensitive authentication options that users shouldn't set directly
        sensitive_keys = {
            'azure_storage_account_key', 'azure_storage_sas_token',
            'azure_tenant_id', 'azure_client_id', 'azure_client_secret',
            'fs.azure.account.auth.type', 'fs.azure.account.oauth.provider.type',
            'fs.azure.account.oauth2.client.id', 'fs.azure.account.oauth2.client.secret'
        }
        
        if key.lower() in sensitive_keys:
            logger.warning(f"Ignoring sensitive authentication option: {key}")
            return self
        
        self.options[key] = value
        return self
    
    def options(self, **options) -> 'UCPassthroughFormatWriter':
        """
        Add multiple options for data writing. Sensitive auth options are filtered.
        
        Args:
            **options: Key-value option pairs
            
        Returns:
            Self for method chaining
        """
        for key, value in options.items():
            self.option(key, value)  # Uses filtering logic from option()
        return self
    
    def partitionBy(self, *cols: str) -> 'UCPassthroughFormatWriter':
        """
        Partition output by given columns.
        
        Args:
            *cols: Column names to partition by
            
        Returns:
            Self for method chaining
        """
        self.partition_columns = list(cols)
        logger.debug(f"Set partition columns to: {self.partition_columns}")
        return self
    
    def save(self, path: Optional[str] = None) -> None:
        """
        Write DataFrame to specified path with intelligent routing and validation.
        Authentication is handled securely internally.
        
        Args:
            path: Path to write data to (required)
            
        Raises:
            ValueError: If path cannot be determined or validation fails
            RuntimeError: If data writing fails
        """
        if not path:
            raise ValueError("Path must be specified for save operation")
        
        # Pre-write validation
        validation = self.validate_write_operation(path)
        if not validation['valid']:
            error_msg = "; ".join(validation['errors'])
            raise ValueError(f"Write validation failed: {error_msg}")
        
        if validation['warnings']:
            for warning in validation['warnings']:
                logger.warning(f"Write validation warning: {warning}")
        
        # Check for explicit override in options (non-auth overrides only)
        explicit_override = self.options.get('uc_passthrough_override')
        
        try:
            with self.__lock:  # Thread-safe access to sensitive operations
                # Analyze path to determine routing
                access_method, analysis = self.__path_analyzer.analyze_path(
                    path=path,
                    format_type=self.format_type,
                    explicit_override=explicit_override
                )
            
            logger.info(f"Writing {path} via {access_method} method (mode: {self.write_mode})")
            logger.debug(f"Routing reasoning: {'; '.join(analysis['reasoning'])}")
            
            # Log write operation details
            write_details = {
                'path': path,
                'format': self.format_type,
                'mode': self.write_mode,
                'partition_columns': self.partition_columns,
                'access_method': access_method,
                'row_count': self.dataframe.count(),
                'column_count': len(self.dataframe.columns)
            }
            logger.info(f"Write operation details: {write_details}")
            
            if access_method == 'uc':
                self._write_via_unity_catalog(path)
            else:  # access_method == 'adls'
                self._write_via_adls_direct(path)
            
            logger.info(f"Successfully completed write operation to {path}")
                
        except Exception as e:
            logger.error(f"Failed to write data to {path}: {str(e)}")
            raise RuntimeError(f"Data writing failed: {str(e)}")
    
    def _write_via_unity_catalog(self, path: str) -> None:
        """
        Write data using standard Unity Catalog governance flow.
        
        Args:
            path: Path to write data to
        """
        logger.debug(f"Writing via Unity Catalog: {path}")
        print("✓ Writing via UC")
        
        try:
            # Create standard Spark DataFrameWriter
            writer = self.dataframe.write.format(self.format_type)
            
            # Set write mode
            writer = writer.mode(self.write_mode)
            
            # Apply partitioning
            if self.partition_columns:
                writer = writer.partitionBy(*self.partition_columns)
            
            # Apply options (excluding our custom options and any sensitive ones)
            filtered_options = {
                k: v for k, v in self.options.items() 
                if not k.startswith('uc_passthrough_') and 
                   k.lower() not in {'azure_storage_account_key', 'azure_storage_sas_token',
                                    'azure_tenant_id', 'azure_client_id', 'azure_client_secret'}
            }
            
            for key, value in filtered_options.items():
                writer = writer.option(key, value)
            
            # Execute write using standard Spark/UC flow
            writer.save(path)
            logger.info(f"Successfully wrote data to {path} via Unity Catalog")
            
        except Exception as e:
            logger.error(f"UC write failed for {path}: {str(e)}")
            raise RuntimeError(f"Unity Catalog write failed: {str(e)}")

    def validate_write_operation(self, path: str) -> Dict[str, Any]:
        """
        Validate write operation before execution.
        
        Args:
            path: Target path for writing
            
        Returns:
            Validation results dictionary
        """
        validation = {
            'valid': True,
            'warnings': [],
            'errors': []
        }
        
        try:
            # Validate DataFrame
            if not self.dataframe:
                validation['errors'].append("No DataFrame provided for write operation")
                validation['valid'] = False
                return validation
            
            # Check DataFrame is not empty
            if self.dataframe.count() == 0:
                validation['warnings'].append("DataFrame is empty")
            
            # Validate path format
            if not path:
                validation['errors'].append("Path cannot be empty")
                validation['valid'] = False
            
            # Check for problematic characters in path
            if any(char in path for char in ['<', '>', '|', '"']):
                validation['errors'].append(f"Path contains invalid characters: {path}")
                validation['valid'] = False
            
            # Format-specific validation
            format_lower = self.format_type.lower()
            if format_lower == 'binaryfile':
                df_columns = set(self.dataframe.columns)
                required = {'path', 'content'}
                missing = required - df_columns
                if missing:
                    validation['errors'].append(f"Binary format missing required columns: {missing}")
                    validation['valid'] = False
            
            # Write mode validation
            if self.write_mode not in ['overwrite', 'append', 'ignore', 'error']:
                validation['errors'].append(f"Invalid write mode: {self.write_mode}")
                validation['valid'] = False
            
            # Partition column validation
            if self.partition_columns:
                df_columns = set(self.dataframe.columns)
                missing_partition_cols = set(self.partition_columns) - df_columns
                if missing_partition_cols:
                    validation['errors'].append(f"Partition columns not found in DataFrame: {missing_partition_cols}")
                    validation['valid'] = False
            
            return validation
            
        except Exception as e:
            validation['errors'].append(f"Validation failed: {str(e)}")
            validation['valid'] = False
            return validation
        
    @_protect_auth_method
    def _write_via_adls_direct(self, path: str) -> None:
        """
        Write data using direct ADLS access with user credentials.
        This method is protected from direct external access.
        
        Args:
            path: Path to write data to
        """
        logger.debug(f"Writing via ADLS direct access: {path}")
        print("✓ Writing via Passthrough")
        
        with self.__lock:  # Thread-safe access to auth manager
            # Ensure user is authenticated
            if not self.__auth_manager.is_authenticated():
                raise RuntimeError("User not authenticated for ADLS direct access")
            
            # Use the pre-created ADLS client
            if not self.__adls_client:
                raise RuntimeError("ADLS client not available for direct access")
            
            # Parse ADLS path
            storage_account_url, container, blob_path = self.__parse_adls_path(path)
        
        # Create direct ADLS writer with pre-created client
        direct_writer = DirectADLSWriter(self.__adls_client, self.spark)
        
        # Handle different format types using direct writing approach
        format_lower = self.format_type.lower()
        
        try:
            if format_lower == 'text':
                direct_writer.write_text_files(
                    self.dataframe, container, blob_path,
                    mode=self.write_mode,
                    partition_columns=self.partition_columns,
                    options=self.options
                )
            elif format_lower == 'binaryfile':
                direct_writer.write_binary_files(
                    self.dataframe, container, blob_path,
                    mode=self.write_mode,
                    partition_columns=self.partition_columns,
                    options=self.options
                )
            elif format_lower == 'json':
                direct_writer.write_json_files(
                    self.dataframe, container, blob_path,
                    mode=self.write_mode,
                    partition_columns=self.partition_columns,
                    options=self.options
                )
            elif format_lower == 'csv':
                direct_writer.write_csv_files(
                    self.dataframe, container, blob_path,
                    mode=self.write_mode,
                    partition_columns=self.partition_columns,
                    options=self.options
                )
            elif format_lower in ['parquet', 'delta', 'orc', 'avro']:
                # For structured formats routed to ADLS direct, still try direct approach
                # but fall back to UC governance if it fails
                try:
                    logger.info(f"Attempting direct write of structured format {format_lower}")
                    direct_writer.write_structured_format_files(
                        self.dataframe, container, blob_path, format_lower,
                        mode=self.write_mode,
                        partition_columns=self.partition_columns,
                        options=self.options
                    )
                except Exception as e:
                    logger.warning(f"Direct structured format write failed, falling back to UC: {str(e)}")
                    self._write_via_unity_catalog(path)
            else:
                raise ValueError(f"Unsupported format for ADLS direct access: {self.format_type}")
                
            logger.info(f"Successfully wrote data to {path} via ADLS direct access")
            
        except Exception as e:
            logger.error(f"ADLS direct write failed for {path}: {str(e)}")
            raise RuntimeError(f"ADLS direct write failed: {str(e)}")
    
    def __parse_adls_path(self, path: str) -> tuple:
        """
        Private method to parse ADLS path into components.
        
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


class UCPassthroughReadInterface:
    """
    Read interface that provides all read functionality.
    This class is accessed via UCPassthroughDataFrame.read property.
    """
    
    def __init__(self, spark_session: SparkSession, auth_manager: AuthenticationManager,
                 path_analyzer: PathAnalyzer, adls_client=None):
        """
        Initialize read interface with protected authentication.
        
        Args:
            spark_session: Active Spark session
            auth_manager: Authentication manager
            path_analyzer: Path analyzer
            adls_client: Pre-created ADLS client
        """
        self.spark = spark_session
        self.__auth_manager = auth_manager
        self.__path_analyzer = path_analyzer
        self.__adls_client = adls_client
        self.__lock = threading.Lock()
    
    def format(self, source: str) -> UCPassthroughFormatReader:
        """
        Specify format for reading data.
        
        Args:
            source: Data source format (e.g., 'delta', 'parquet', 'text', 'binaryFile')
            
        Returns:
            UCPassthroughFormatReader for method chaining
        """
        with self.__lock:
            return UCPassthroughFormatReader(
                format_type=source,
                spark_session=self.spark,
                auth_manager=self.__auth_manager,
                path_analyzer=self.__path_analyzer,
                adls_client=self.__adls_client
            )
    
    def option(self, key: str, value: Any) -> UCPassthroughFormatReader:
        """Set option and return a format reader."""
        logger.warning("Using option() without format() - defaulting to 'text' format")
        return self.format('text').option(key, value)
    
    def options(self, **options) -> UCPassthroughFormatReader:
        """Set multiple options and return a format reader."""
        logger.warning("Using options() without format() - defaulting to 'text' format")
        return self.format('text').options(**options)
    
    def schema(self, schema: Union[StructType, str]) -> UCPassthroughFormatReader:
        """Set schema and return a format reader."""
        logger.warning("Using schema() without format() - defaulting to 'parquet' format")
        return self.format('parquet').schema(schema)
    
    def load(self, path: str, format: Optional[str] = None) -> DataFrame:
        """Direct load method for simple use cases."""
        if format:
            return self.format(format).load(path)
        else:
            # Try to infer format from path
            inferred_format = self.__infer_format_from_path(path)
            return self.format(inferred_format).load(path)
    
    def table(self, table_name: str) -> DataFrame:
        """Read a table using table reference syntax."""
        # Validate table name format
        parts = table_name.split('.')
        if len(parts) < 2 or len(parts) > 3:
            raise ValueError(f"Invalid table name format: {table_name}")
        
        # Table references always use UC governance
        logger.info(f"Reading table via Unity Catalog: {table_name}")
        return self.spark.read.table(table_name)
    
    # Direct format methods for better compatibility
    def text(self, paths: Union[str, List[str]]) -> DataFrame:
        """Read text files (compatibility method)."""
        if isinstance(paths, list):
            dfs = [self.format('text').load(path) for path in paths]
            return dfs[0].unionAll(*dfs[1:]) if len(dfs) > 1 else dfs[0]
        else:
            return self.format('text').load(paths)
    
    def json(self, path: Union[str, List[str]], **kwargs) -> DataFrame:
        """Read JSON files with all Spark options."""
        reader = self.format('json')
        
        # Handle schema parameter
        if 'schema' in kwargs:
            reader = reader.schema(kwargs.pop('schema'))
        
        # Apply all other options
        if kwargs:
            reader = reader.options(**kwargs)
        
        if isinstance(path, list):
            dfs = [reader.load(p) for p in path]
            return dfs[0].unionAll(*dfs[1:]) if len(dfs) > 1 else dfs[0]
        else:
            return reader.load(path)
    
    def orc(self, path: Union[str, List[str]], **options) -> DataFrame:
        """Read ORC files (compatibility method)."""
        reader = self.format('orc')
        if options:
            reader = reader.options(**options)
        
        if isinstance(path, list):
            dfs = [reader.load(p) for p in path]
            return dfs[0].unionAll(*dfs[1:]) if len(dfs) > 1 else dfs[0]
        else:
            return reader.load(path)
    
    def __infer_format_from_path(self, path: str) -> str:
        """Private method to infer format from file extension."""
        import os
        _, ext = os.path.splitext(path.lower())
        
        format_mapping = {
            '.delta': 'delta', '.parquet': 'parquet', '.json': 'json',
            '.csv': 'csv', '.txt': 'text', '.log': 'text', 
            '.xml': 'xml', '.orc': 'orc', '.avro': 'avro'
        }
        
        return format_mapping.get(ext, 'text')  # Default to text


class UCPassthroughWriteInterface:
    """
    Write interface that provides all write functionality.
    This class is accessed via UCPassthroughDataFrame.write property.
    """
    
    def __init__(self, dataframe: DataFrame, spark_session: SparkSession, 
                 auth_manager: AuthenticationManager, path_analyzer: PathAnalyzer,
                 adls_client=None):
        """
        Initialize write interface with protected authentication.
        
        Args:
            dataframe: DataFrame to write (None for interface-level operations)
            spark_session: Active Spark session
            auth_manager: Authentication manager
            path_analyzer: Path analyzer
            adls_client: Pre-created ADLS client
        """
        self.dataframe = dataframe
        self.spark = spark_session
        self.__auth_manager = auth_manager
        self.__path_analyzer = path_analyzer
        self.__adls_client = adls_client
        self.__lock = threading.Lock()
    
    def format(self, source: str) -> UCPassthroughFormatWriter:
        """
        Specify format for writing data.
        
        Args:
            source: Data source format (e.g., 'delta', 'parquet', 'text', 'json', 'csv')
            
        Returns:
            UCPassthroughFormatWriter for method chaining
        """
        if not self.dataframe:
            raise ValueError("No DataFrame available for write operations")
            
        with self.__lock:
            return UCPassthroughFormatWriter(
                dataframe=self.dataframe,
                format_type=source,
                spark_session=self.spark,
                auth_manager=self.__auth_manager,
                path_analyzer=self.__path_analyzer,
                adls_client=self.__adls_client
            )
    
    def mode(self, saveMode: str) -> UCPassthroughFormatWriter:
        """Set save mode and return a format writer."""
        logger.warning("Using mode() without format() - defaulting to 'parquet' format")
        return self.format('parquet').mode(saveMode)
    
    def option(self, key: str, value: Any) -> UCPassthroughFormatWriter:
        """Set option and return a format writer."""
        logger.warning("Using option() without format() - defaulting to 'parquet' format")
        return self.format('parquet').option(key, value)
    
    def options(self, **options) -> UCPassthroughFormatWriter:
        """Set multiple options and return a format writer."""
        logger.warning("Using options() without format() - defaulting to 'parquet' format")
        return self.format('parquet').options(**options)
    
    def partitionBy(self, *cols: str) -> UCPassthroughFormatWriter:
        """Set partition columns and return a format writer."""
        logger.warning("Using partitionBy() without format() - defaulting to 'parquet' format")
        return self.format('parquet').partitionBy(*cols)
    
    def save(self, path: str, format: Optional[str] = None) -> None:
        """Direct save method for simple use cases."""
        if format:
            self.format(format).save(path)
        else:
            # Try to infer format from path
            inferred_format = self.__infer_format_from_path(path)
            self.format(inferred_format).save(path)
    
    def saveAsTable(self, name: str, format: Optional[str] = None, mode: Optional[str] = None,
                    partitionBy: Optional[List[str]] = None, **options) -> None:
        """Save DataFrame as a table using table reference syntax."""
        if not self.dataframe:
            raise ValueError("No DataFrame available for saveAsTable operation")
            
        # Validate table name format
        parts = name.split('.')
        if len(parts) < 2 or len(parts) > 3:
            raise ValueError(f"Invalid table name format: {name}")
        
        # Table references always use UC governance
        logger.info(f"Writing table via Unity Catalog: {name}")
        
        try:
            writer = self.dataframe.write
            
            if format:
                writer = writer.format(format)
            else:
                writer = writer.format('delta')  # Default to Delta for tables
            
            if mode:
                writer = writer.mode(mode)
            
            if partitionBy:
                writer = writer.partitionBy(*partitionBy)
            
            for key, value in options.items():
                writer = writer.option(key, value)
            
            # Save as table
            writer.saveAsTable(name)
            logger.info(f"Successfully wrote DataFrame as table: {name}")
            
        except Exception as e:
            logger.error(f"Failed to write DataFrame as table {name}: {str(e)}")
            raise RuntimeError(f"Table write failed: {str(e)}")
    
    def __infer_format_from_path(self, path: str) -> str:
        """Private method to infer format from file extension."""
        import os
        _, ext = os.path.splitext(path.lower())
        
        format_mapping = {
            '.delta': 'delta', '.parquet': 'parquet', '.json': 'json',
            '.csv': 'csv', '.txt': 'text', '.log': 'text',
            '.xml': 'xml', '.orc': 'orc', '.avro': 'avro'
        }
        
        return format_mapping.get(ext, 'parquet')  # Default to parquet for writes


class UCPassthroughDataFrame:
    """
    Unified DataFrame interface that provides both read and write functionality
    with intelligent routing between Unity Catalog and direct ADLS access.
    
    This replaces the need for separate reader and writer classes.
    All sensitive authentication mechanisms are protected from user manipulation.
    """
    
    def __init__(self, spark_session: SparkSession, dataframe: DataFrame = None,
                 auth_manager: AuthenticationManager = None,
                 path_analyzer: PathAnalyzer = None):
        """
        Initialize the unified UC Passthrough interface.
        
        Args:
            spark_session: Active Spark session
            dataframe: Optional DataFrame for write operations
            auth_manager: Optional authentication manager (will create if None)
            path_analyzer: Optional path analyzer (will create if None)
        """
        self.spark = spark_session
        self.dataframe = dataframe
        self.__lock = threading.Lock()
        
        # Initialize components if not provided - these are kept private
        with self.__lock:
            if auth_manager is None:
                auth_manager = AuthenticationManager()
                auth_manager.initialize_user_context(spark_session)
            
            if path_analyzer is None:
                path_analyzer = PathAnalyzer()
            
            self.__auth_manager = auth_manager  # Private attribute
            self.__path_analyzer = path_analyzer  # Private attribute
            
            # Create ADLS client once during initialization (protected)
            self.__adls_client = None
            self.__initialize_adls_client()
        
        logger.debug("UCPassthroughDataFrame initialized with protected authentication")
    
    def __initialize_adls_client(self):
        """Private method to initialize ADLS client with protected credentials."""
        storage_url = os.getenv("PASSTHROUGH_STORAGE_URL")
        if storage_url and self.__auth_manager.is_authenticated():
            try:
                self.__adls_client = self.__auth_manager.get_adls_client(storage_url)
                logger.info(f"ADLS client created successfully for: {storage_url}")
            except Exception as e:
                logger.warning(f"Failed to create ADLS client during initialization: {str(e)}")
                self.__adls_client = None
    
    @property
    def read(self) -> UCPassthroughReadInterface:
        """
        Get read interface for data loading operations.
        
        Returns:
            UCPassthroughReadInterface with all read functionality
        """
        with self.__lock:
            return UCPassthroughReadInterface(
                spark_session=self.spark,
                auth_manager=self.__auth_manager,
                path_analyzer=self.__path_analyzer,
                adls_client=self.__adls_client
            )
    
    def write(self, dataframe: DataFrame = None) -> UCPassthroughWriteInterface:
        """
        Get write interface for data writing operations.
        
        Args:
            dataframe: DataFrame to write (uses self.dataframe if None)
            
        Returns:
            UCPassthroughWriteInterface with all write functionality
        """
        df = dataframe or self.dataframe
        if not df:
            raise ValueError("No DataFrame provided for write operations")
            
        with self.__lock:
            return UCPassthroughWriteInterface(
                dataframe=df,
                spark_session=self.spark,
                auth_manager=self.__auth_manager,
                path_analyzer=self.__path_analyzer,
                adls_client=self.__adls_client
            )
    
    # Convenience methods for common operations
    def set_dataframe(self, dataframe: DataFrame) -> 'UCPassthroughDataFrame':
        """
        Set the DataFrame for write operations.
        
        Args:
            dataframe: DataFrame to set
            
        Returns:
            Self for method chaining
        """
        self.dataframe = dataframe
        return self
    
    def get_auth_status(self) -> Dict[str, Any]:
        """
        Get authentication status without exposing sensitive details.
        
        Returns:
            Dictionary with safe authentication status
        """
        return {
            'authenticated': self.__auth_manager.is_authenticated(),
            'current_user': self.__auth_manager.get_current_user(),
            'adls_client_available': self.__adls_client is not None,
            'cache_stats': self.__auth_manager.get_cache_stats(),
            'config_info': self.__auth_manager.get_configuration_info()
        }
    
    def validate_setup(self) -> Dict[str, Any]:
        """
        Validate the complete setup and return status.
        
        Returns:
            Dictionary with validation results
        """
        validation_results = {
            'overall_status': 'unknown',
            'auth_validation': [],
            'path_analyzer_valid': False,
            'adls_connectivity': False,
            'recommendations': []
        }
        
        try:
            # Validate authentication
            auth_warnings = self.__auth_manager.validate_configuration()
            validation_results['auth_validation'] = auth_warnings
            
            # Validate path analyzer
            validation_results['path_analyzer_valid'] = self.__path_analyzer.validate_basic_configuration()
            
            # Test ADLS connectivity
            if self.__adls_client:
                try:
                    list(self.__adls_client.list_file_systems())
                    validation_results['adls_connectivity'] = True
                except:
                    validation_results['adls_connectivity'] = False
            
            # Determine overall status
            if (not auth_warnings and 
                validation_results['path_analyzer_valid'] and 
                validation_results['adls_connectivity']):
                validation_results['overall_status'] = 'healthy'
            elif not auth_warnings and validation_results['path_analyzer_valid']:
                validation_results['overall_status'] = 'partial'
                validation_results['recommendations'].append("ADLS connectivity issues detected")
            else:
                validation_results['overall_status'] = 'issues_detected'
                if auth_warnings:
                    validation_results['recommendations'].append("Authentication configuration issues")
                if not validation_results['path_analyzer_valid']:
                    validation_results['recommendations'].append("Path analyzer configuration issues")
            
        except Exception as e:
            validation_results['overall_status'] = 'error'
            validation_results['recommendations'].append(f"Validation error: {str(e)}")
        
        return validation_results


# Enhanced DataFrame monkey patching for unified interface
def patch_dataframe_with_uc_passthrough(spark_session: SparkSession,
                                       auth_manager: AuthenticationManager = None,
                                       path_analyzer: PathAnalyzer = None) -> None:
    """
    Monkey patch DataFrame to add UC Passthrough write functionality.
    This creates a unified interface where df.write automatically uses UC Passthrough.
    
    Args:
        spark_session: Spark session to configure
        auth_manager: Optional authentication manager
        path_analyzer: Optional path analyzer
    """
    # Store original write property
    original_write_property = DataFrame.write
    
    # Get or create shared components
    if not hasattr(spark_session, '_uc_passthrough_auth_manager'):
        if auth_manager is None:
            auth_manager = AuthenticationManager()
            auth_manager.initialize_user_context(spark_session)
        spark_session._uc_passthrough_auth_manager = auth_manager
    
    if not hasattr(spark_session, '_uc_passthrough_path_analyzer'):
        if path_analyzer is None:
            path_analyzer = PathAnalyzer()
        spark_session._uc_passthrough_path_analyzer = path_analyzer
    
    if not hasattr(spark_session, '_uc_passthrough_adls_client'):
        storage_url = os.getenv("PASSTHROUGH_STORAGE_URL")
        if storage_url and spark_session._uc_passthrough_auth_manager.is_authenticated():
            try:
                spark_session._uc_passthrough_adls_client = spark_session._uc_passthrough_auth_manager.get_adls_client(storage_url)
            except Exception as e:
                logger.warning(f"Failed to create ADLS client: {str(e)}")
                spark_session._uc_passthrough_adls_client = None
        else:
            spark_session._uc_passthrough_adls_client = None
    
    def _create_uc_passthrough_writer(self):
        """Create UC Passthrough writer for this DataFrame."""
        return UCPassthroughWriteInterface(
            dataframe=self,
            spark_session=self.sparkSession,
            auth_manager=self.sparkSession._uc_passthrough_auth_manager,
            path_analyzer=self.sparkSession._uc_passthrough_path_analyzer,
            adls_client=self.sparkSession._uc_passthrough_adls_client
        )
    
    # Replace DataFrame.write property
    DataFrame.write = property(_create_uc_passthrough_writer)
    DataFrame._original_write = original_write_property
    
    logger.info("DataFrame.write patched with UC Passthrough functionality")


# Main convenience function for easy setup
def create_uc_passthrough_interface(spark_session: SparkSession = None,
                                   app_name: str = "UC Passthrough App",
                                   patch_dataframe: bool = True,
                                   **spark_conf) -> UCPassthroughDataFrame:
    """
    Create a unified UC Passthrough interface with optional Spark session creation.
    
    Args:
        spark_session: Existing Spark session (will create if None)
        app_name: Spark application name (if creating new session)
        patch_dataframe: Whether to monkey patch DataFrame.write
        **spark_conf: Additional Spark configuration
        
    Returns:
        UCPassthroughDataFrame interface for both read and write operations
    """
    # Create or use existing Spark session
    if spark_session is None:
        builder = SparkSession.builder.appName(app_name)
        for key, value in spark_conf.items():
            builder = builder.config(key, value)
        spark_session = builder.getOrCreate()
    
    # Initialize authentication and path analysis
    auth_manager = AuthenticationManager()
    auth_manager.initialize_user_context(spark_session)
    path_analyzer = PathAnalyzer()
    
    # Create unified interface
    uc_interface = UCPassthroughDataFrame(
        spark_session=spark_session,
        auth_manager=auth_manager,
        path_analyzer=path_analyzer
    )
    
    # Optionally patch DataFrame.write for automatic UC Passthrough
    if patch_dataframe:
        patch_dataframe_with_uc_passthrough(spark_session, auth_manager, path_analyzer)
    
    logger.info("UC Passthrough unified interface created successfully")
    return uc_interface


# # Example usage
# if __name__ == "__main__":
#     import logging
#     logging.basicConfig(level=logging.INFO)
    
#     print("UC Passthrough Library - Unified Interface")
#     print("=" * 50)
#     print("Usage Examples:")
#     print()
#     print("# Method 1: Unified Interface")
#     print("from uc_passthrough_library import create_uc_passthrough_interface")
#     print("uc_passthrough = create_uc_passthrough_interface()")
#     print()
#     print("# Reading data")
#     print("df = uc_passthrough.read.format('csv').load('path/to/file.csv')")
#     print("df = uc_passthrough.read.csv('path/to/file.csv')")
#     print("df = uc_passthrough.read.table('catalog.schema.table')")
#     print()
#     print("# Writing data (with DataFrame patching enabled)")
#     print("df.write.format('csv').save('path/to/output.csv')")
#     print("df.write.mode('overwrite').saveAsTable('catalog.schema.new_table')")
#     print()
#     print("# Writing data (using interface directly)")
#     print("uc_passthrough.write(df).format('json').save('path/to/output.json')")
#     print()
#     print("# Method 2: Direct UCPassthroughDataFrame")
#     print("from uc_passthrough_library import UCPassthroughDataFrame")
#     print("uc_interface = UCPassthroughDataFrame(spark)")
#     print("df = uc_interface.read.format('parquet').load('path/to/file.parquet')")
#     print("uc_interface.write(df).format('delta').save('catalog.schema.table')")
#     print()
#     print("Key Benefits:")
#     print("✓ Single unified interface for read and write")
#     print("✓ Automatic intelligent routing between UC and ADLS") 
#     print("✓ Seamless DataFrame.write integration")
#     print("✓ Protected authentication and security")
#     print("✓ Transaction safety for write operations")
#     print("✓ Complete API compatibility with Spark")
        
#         if isinstance(path, list):
#             dfs = [reader.load(p) for p in path]
#             return dfs[0].unionAll(*dfs[1:]) if len(dfs) > 1 else dfs[0]
#         else:
#             return reader.load(path)
    
#     def parquet(self, *paths: str, **options) -> DataFrame:
#         """Read Parquet files (compatibility method)."""
#         reader = self.format('parquet')
#         if options:
#             reader = reader.options(**options)
        
#         if len(paths) == 1:
#             return reader.load(paths[0])
#         else:
#             dfs = [reader.load(path) for path in paths]
#             return dfs[0].unionAll(*dfs[1:]) if len(dfs) > 1 else dfs[0]
    
#     def csv(self, path: Union[str, List[str]], **kwargs) -> DataFrame:
#         """Read CSV files with all Spark options."""
#         reader = self.format('csv')
        
#         # Handle schema parameter
#         if 'schema' in kwargs:
#             reader = reader.schema(kwargs.pop('schema'))
        
#         # Apply all other options
#         if kwargs:
#             reader = reader.options(**kwargs)