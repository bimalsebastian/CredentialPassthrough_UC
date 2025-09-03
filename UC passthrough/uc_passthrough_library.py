"""
UC Passthrough Library - Secured DataFrame Reader Module

This module provides the main Spark API wrapper that intelligently routes data access
between Unity Catalog governance and direct ADLS access with user credentials.
All sensitive authentication mechanisms and tokens are protected from user manipulation.
"""

import logging
from typing import Optional, Dict, Any, Union, List
from urllib.parse import urlparse
import json
import os
import threading
from functools import wraps

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
                caller_module in ['authentication_manager', 'direct_adls_reader']):
            raise PermissionError("Direct access to authentication methods is restricted")
        
        return method(self, *args, **kwargs)
    return wrapper


class UCPassthroughFormatReader:
    """
    Format-specific reader that handles the actual data loading logic.
    This class is created by UCPassthroughDataFrameReader.format() calls.
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
        
        # Import DirectADLSReader
        from direct_adls_reader import DirectADLSReader
        
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
                adls_client = direct_reader.get_adls_client()
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


class UCPassthroughDataFrameReader:
    """
    Main DataFrame reader that provides drop-in replacement for spark.read
    with intelligent routing between Unity Catalog and direct ADLS access.
    
    All sensitive authentication mechanisms are protected from user manipulation.
    This class is designed to be 100% compatible with Spark's DataFrameReader API.
    """
    
    def __init__(self, spark_session: SparkSession, auth_manager: AuthenticationManager = None, 
                 path_analyzer: PathAnalyzer = None):
        """
        Initialize the passthrough DataFrame reader with protected authentication.
        
        Args:
            spark_session: Active Spark session
            auth_manager: Optional authentication manager (will create if None)
            path_analyzer: Optional path analyzer (will create if None)
        """
        self.spark = spark_session
        self.__lock = threading.Lock()  # Thread safety for sensitive operations
        
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
        
        # Add self as read property to make spark_passthrough.read work
        self.read = self
        
        logger.debug("UCPassthroughDataFrameReader initialized with protected authentication")
    
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
    
    def format(self, source: str) -> UCPassthroughFormatReader:
        """
        Specify format for reading data.
        
        Args:
            source: Data source format (e.g., 'delta', 'parquet', 'text', 'binaryFile')
            
        Returns:
            UCPassthroughFormatReader for method chaining
        """

        
        with self.__lock:  # Thread-safe access to protected components
            logger.debug(f"Creating format reader with ADLS client: {self.__adls_client is not None}")
            return UCPassthroughFormatReader(
                format_type=source,
                spark_session=self.spark,
                auth_manager=self.__auth_manager,
                path_analyzer=self.__path_analyzer,
                adls_client=self.__adls_client
            )
    
    def option(self, key: str, value: Any) -> UCPassthroughFormatReader:
        """
        Set option and return a format reader (for compatibility with spark.read.option().load()).
        Sensitive authentication options are filtered out.
        
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
        Sensitive authentication options are filtered out.
        
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
            inferred_format = self.__infer_format_from_path(path)
            return self.format(inferred_format).load(path)
    
    # Add direct format methods for better compatibility
    def text(self, paths: Union[str, List[str]]) -> DataFrame:
        """Read text files (compatibility method)."""
        if isinstance(paths, list):
            # Handle multiple paths by reading each and union
            dfs = [self.format('text').load(path) for path in paths]
            return dfs[0].unionAll(*dfs[1:]) if len(dfs) > 1 else dfs[0]
        else:
            return self.format('text').load(paths)
    
    def json(self, path: Union[str, List[str]], schema: Optional[StructType] = None, 
             primitivesAsString: Optional[bool] = None, prefersDecimal: Optional[bool] = None,
             allowComments: Optional[bool] = None, allowUnquotedFieldNames: Optional[bool] = None,
             allowSingleQuotes: Optional[bool] = None, allowNumericLeadingZero: Optional[bool] = None,
             allowBackslashEscapingAnyCharacter: Optional[bool] = None, mode: Optional[str] = None,
             columnNameOfCorruptRecord: Optional[str] = None, dateFormat: Optional[str] = None,
             timestampFormat: Optional[str] = None, multiLine: Optional[bool] = None,
             allowUnquotedControlChars: Optional[bool] = None, lineSep: Optional[str] = None,
             samplingRatio: Optional[float] = None, dropFieldIfAllNull: Optional[bool] = None,
             encoding: Optional[str] = None, locale: Optional[str] = None, pathGlobFilter: Optional[str] = None,
             recursiveFileLookup: Optional[bool] = None, modifiedBefore: Optional[bool] = None,
             modifiedAfter: Optional[bool] = None) -> DataFrame:
        """Read JSON files with all Spark options (compatibility method)."""
        reader = self.format('json')
        
        if schema:
            reader = reader.schema(schema)
        
        # Apply all JSON-specific options (authentication options are filtered in option() method)
        options_dict = {}
        if primitivesAsString is not None:
            options_dict['primitivesAsString'] = primitivesAsString
        if prefersDecimal is not None:
            options_dict['prefersDecimal'] = prefersDecimal
        if allowComments is not None:
            options_dict['allowComments'] = allowComments
        if allowUnquotedFieldNames is not None:
            options_dict['allowUnquotedFieldNames'] = allowUnquotedFieldNames
        if allowSingleQuotes is not None:
            options_dict['allowSingleQuotes'] = allowSingleQuotes
        if allowNumericLeadingZero is not None:
            options_dict['allowNumericLeadingZero'] = allowNumericLeadingZero
        if allowBackslashEscapingAnyCharacter is not None:
            options_dict['allowBackslashEscapingAnyCharacter'] = allowBackslashEscapingAnyCharacter
        if mode is not None:
            options_dict['mode'] = mode
        if columnNameOfCorruptRecord is not None:
            options_dict['columnNameOfCorruptRecord'] = columnNameOfCorruptRecord
        if dateFormat is not None:
            options_dict['dateFormat'] = dateFormat
        if timestampFormat is not None:
            options_dict['timestampFormat'] = timestampFormat
        if multiLine is not None:
            options_dict['multiLine'] = multiLine
        if allowUnquotedControlChars is not None:
            options_dict['allowUnquotedControlChars'] = allowUnquotedControlChars
        if lineSep is not None:
            options_dict['lineSep'] = lineSep
        if samplingRatio is not None:
            options_dict['samplingRatio'] = samplingRatio
        if dropFieldIfAllNull is not None:
            options_dict['dropFieldIfAllNull'] = dropFieldIfAllNull
        if encoding is not None:
            options_dict['encoding'] = encoding
        if locale is not None:
            options_dict['locale'] = locale
        if pathGlobFilter is not None:
            options_dict['pathGlobFilter'] = pathGlobFilter
        if recursiveFileLookup is not None:
            options_dict['recursiveFileLookup'] = recursiveFileLookup
        if modifiedBefore is not None:
            options_dict['modifiedBefore'] = modifiedBefore
        if modifiedAfter is not None:
            options_dict['modifiedAfter'] = modifiedAfter
            
        if options_dict:
            reader = reader.options(**options_dict)
        
        if isinstance(path, list):
            # Handle multiple paths
            dfs = [reader.load(p) for p in path]
            return dfs[0].unionAll(*dfs[1:]) if len(dfs) > 1 else dfs[0]
        else:
            return reader.load(path)
    
    def parquet(self, *paths: str, **options) -> DataFrame:
        """Read Parquet files (compatibility method)."""
        reader = self.format('parquet')
        if options:
            reader = reader.options(**options)
        
        if len(paths) == 1:
            return reader.load(paths[0])
        else:
            # Handle multiple paths
            dfs = [reader.load(path) for path in paths]
            return dfs[0].unionAll(*dfs[1:]) if len(dfs) > 1 else dfs[0]
    
    def csv(self, path: Union[str, List[str]], schema: Optional[StructType] = None,
            sep: Optional[str] = None, encoding: Optional[str] = None, quote: Optional[str] = None,
            escape: Optional[str] = None, comment: Optional[str] = None, header: Optional[bool] = None,
            inferSchema: Optional[bool] = None, ignoreLeadingWhiteSpace: Optional[bool] = None,
            ignoreTrailingWhiteSpace: Optional[bool] = None, nullValue: Optional[str] = None,
            nanValue: Optional[str] = None, positiveInf: Optional[str] = None, negativeInf: Optional[str] = None,
            dateFormat: Optional[str] = None, timestampFormat: Optional[str] = None, maxColumns: Optional[int] = None,
            maxCharsPerColumn: Optional[int] = None, maxMalformedLogPerPartition: Optional[int] = None,
            mode: Optional[str] = None, columnNameOfCorruptRecord: Optional[str] = None, multiLine: Optional[bool] = None,
            charToEscapeQuoteEscaping: Optional[str] = None, samplingRatio: Optional[float] = None,
            enforceSchema: Optional[bool] = None, emptyValue: Optional[str] = None, locale: Optional[str] = None,
            lineSep: Optional[str] = None, pathGlobFilter: Optional[str] = None, recursiveFileLookup: Optional[bool] = None,
            modifiedBefore: Optional[bool] = None, modifiedAfter: Optional[bool] = None,
            unescapedQuoteHandling: Optional[str] = None) -> DataFrame:
        """Read CSV files with all Spark options (compatibility method)."""
        reader = self.format('csv')
        
        if schema:
            reader = reader.schema(schema)
        
        # Apply all CSV-specific options (authentication options are filtered automatically)
        options_dict = {}
        if sep is not None:
            options_dict['sep'] = sep
        if encoding is not None:
            options_dict['encoding'] = encoding
        if quote is not None:
            options_dict['quote'] = quote
        if escape is not None:
            options_dict['escape'] = escape
        if comment is not None:
            options_dict['comment'] = comment
        if header is not None:
            options_dict['header'] = header
        if inferSchema is not None:
            options_dict['inferSchema'] = inferSchema
        if ignoreLeadingWhiteSpace is not None:
            options_dict['ignoreLeadingWhiteSpace'] = ignoreLeadingWhiteSpace
        if ignoreTrailingWhiteSpace is not None:
            options_dict['ignoreTrailingWhiteSpace'] = ignoreTrailingWhiteSpace
        if nullValue is not None:
            options_dict['nullValue'] = nullValue
        if nanValue is not None:
            options_dict['nanValue'] = nanValue
        if positiveInf is not None:
            options_dict['positiveInf'] = positiveInf
        if negativeInf is not None:
            options_dict['negativeInf'] = negativeInf
        if dateFormat is not None:
            options_dict['dateFormat'] = dateFormat
        if timestampFormat is not None:
            options_dict['timestampFormat'] = timestampFormat
        if maxColumns is not None:
            options_dict['maxColumns'] = maxColumns
        if maxCharsPerColumn is not None:
            options_dict['maxCharsPerColumn'] = maxCharsPerColumn
        if maxMalformedLogPerPartition is not None:
            options_dict['maxMalformedLogPerPartition'] = maxMalformedLogPerPartition
        if mode is not None:
            options_dict['mode'] = mode
        if columnNameOfCorruptRecord is not None:
            options_dict['columnNameOfCorruptRecord'] = columnNameOfCorruptRecord
        if multiLine is not None:
            options_dict['multiLine'] = multiLine
        if charToEscapeQuoteEscaping is not None:
            options_dict['charToEscapeQuoteEscaping'] = charToEscapeQuoteEscaping
        if samplingRatio is not None:
            options_dict['samplingRatio'] = samplingRatio
        if enforceSchema is not None:
            options_dict['enforceSchema'] = enforceSchema
        if emptyValue is not None:
            options_dict['emptyValue'] = emptyValue
        if locale is not None:
            options_dict['locale'] = locale
        if lineSep is not None:
            options_dict['lineSep'] = lineSep
        if pathGlobFilter is not None:
            options_dict['pathGlobFilter'] = pathGlobFilter
        if recursiveFileLookup is not None:
            options_dict['recursiveFileLookup'] = recursiveFileLookup
        if modifiedBefore is not None:
            options_dict['modifiedBefore'] = modifiedBefore
        if modifiedAfter is not None:
            options_dict['modifiedAfter'] = modifiedAfter
        if unescapedQuoteHandling is not None:
            options_dict['unescapedQuoteHandling'] = unescapedQuoteHandling
            
        if options_dict:
            reader = reader.options(**options_dict)
        
        if isinstance(path, list):
            # Handle multiple paths
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
    
    def table(self, tableName: str) -> DataFrame:
        """Read a table using Unity Catalog (compatibility method)."""
        return self.format('table').load(tableName)
    
    def __infer_format_from_path(self, path: str) -> str:
        """
        Private method to infer format from file extension.
        
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
    
    # Security methods - users cannot access these directly
    def _get_auth_manager(self):
        """Protected method to get auth manager - internal use only."""
        import inspect
        frame = inspect.currentframe().f_back
        caller_module = frame.f_globals.get('__name__', '')
        
        if not caller_module.startswith(__name__):
            raise PermissionError("Direct access to authentication manager is restricted")
        
        return self.__auth_manager


# # Convenience function to create a Spark session with UC Passthrough
# def create_spark_with_uc_passthrough(app_name: str = "UC Passthrough App", **spark_conf) -> SparkSession:
#     """
#     Create a Spark session with UC Passthrough Library integrated.
    
#     Args:
#         app_name: Spark application name
#         **spark_conf: Additional Spark configuration
        
#     Returns:
#         SparkSession with UC Passthrough integrated
#     """
#     # Create Spark session
#     builder = SparkSession.builder.appName(app_name)
    
#     # Apply additional configuration
#     for key, value in spark_conf.items():
#         builder = builder.config(key, value)
    
#     spark = builder.getOrCreate()
    
#     # Replace spark.read with UC Passthrough reader
#     original_read = spark.read
#     uc_read = UCPassthroughDataFrameReader(spark)
    
#     # Monkey patch spark.read
#     spark.read = uc_read
    
#     # Store original for fallback if needed
#     spark._original_read = original_read
    
#     logger.info("Spark session created with UC Passthrough Library integrated")
#     return spark


# # Example usage and testing
# if __name__ == "__main__":
#     # Configure logging
#     logging.basicConfig(level=logging.INFO)
    
#     # Set environment variables for configuration
#     os.environ['UC_PASSTHROUGH_CLIENT_ID'] = 'your-client-id'
#     os.environ['UC_PASSTHROUGH_CLIENT_SECRET'] = 'your-client-secret'
#     os.environ['UC_PASSTHROUGH_TENANT_ID'] = 'your-tenant-id'
    
#     # Create Spark session with UC Passthrough
#     spark = create_spark_with_uc_passthrough("UC Passthrough Test")
    
#     print("🚀 UC Passthrough Library successfully integrated!")
#     print("\nNow you can use all these patterns:")
#     print("✅ spark.read.format('csv').load(path)")
#     print("✅ spark.read.csv(path)")
#     print("✅ spark.read.json(path)")
#     print("✅ spark.read.parquet(path)")
#     print("✅ spark.read.text(path)")
#     print("✅ spark.read.option('key', 'value').load(path)")
#     print("✅ All standard Spark DataFrameReader methods supported!")