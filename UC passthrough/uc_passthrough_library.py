"""
UC Passthrough Library - DataFrame Reader Module

Drop-in replacement for spark.read that routes data access between
Unity Catalog governance and direct ADLS access with user credentials.

Usage:
    # Wrap spark session once
    spark = UCPassthroughDataFrameReader(spark, auth_manager, path_analyzer)

    # Then use exactly like spark.read
    df = spark.read.format('csv').option('header', 'true').load('abfss://...')
    df = spark.read.csv('abfss://...', header=True)
    df = spark.read.parquet('abfss://...')
    df = spark.read.table('catalog.schema.table')
"""

import logging
from typing import Optional, Dict, Any, Union, List
from urllib.parse import urlparse

try:
    from pyspark.sql import DataFrame, SparkSession
    from pyspark.sql.types import StructType
except ImportError as e:
    raise ImportError(f"PySpark not found: {e}.")

try:
    from azure.storage.filedatalake import DataLakeServiceClient, FileSystemClient
    import pandas as pd
except ImportError as e:
    raise ImportError(f"Required Azure libraries not found: {e}. "
                      f"Install: pip install azure-storage-file-datalake pandas")

from path_analyzer import PathAnalyzer
from authentication_manager import AuthenticationManager

logger = logging.getLogger(__name__)


class UCPassthroughFormatReader:
    """
    Format-specific reader returned by UCPassthroughDataFrameReader.format().
    Mirrors the Spark DataFrameReader API exactly.

    Fixes vs original:
    - _read_options dict (renamed from 'options') avoids name clash with options() method
    - _schema (renamed from 'schema') avoids name clash with schema() method
    - load() accepts list of paths
    - table() supported
    - shorthand format methods (csv, json, parquet, text, orc, avro) added
    """

    def __init__(self, format_type: str, spark_session: SparkSession,
                 auth_manager: AuthenticationManager, path_analyzer: PathAnalyzer):
        self.format_type = format_type
        self.spark = spark_session
        self.auth_manager = auth_manager
        self.path_analyzer = path_analyzer
        self._read_options: Dict[str, Any] = {}   # renamed — avoids clash with options()
        self._schema = None                         # renamed — avoids clash with schema()

        logger.debug(f"UCPassthroughFormatReader created for format: {format_type}")

    # ------------------------------------------------------------------ #
    #  Builder methods (all return self for chaining)                      #
    # ------------------------------------------------------------------ #

    def option(self, key: str, value: Any) -> 'UCPassthroughFormatReader':
        """Set a single read option."""
        self._read_options[key] = value
        return self

    def options(self, **kwargs) -> 'UCPassthroughFormatReader':
        """Set multiple read options at once."""
        self._read_options.update(kwargs)
        return self

    def schema(self, schema: Union[StructType, str]) -> 'UCPassthroughFormatReader':
        """Set the schema for reading."""
        self._schema = schema
        return self

    # ------------------------------------------------------------------ #
    #  Core load                                                           #
    # ------------------------------------------------------------------ #

    def load(self, path: Optional[Union[str, List[str]]] = None) -> DataFrame:
        """
        Load data from path(s).  Accepts a single string or a list of paths,
        matching the native Spark DataFrameReader.load() signature.
        """
        if path is None:
            raise ValueError("Path must be specified for load()")

        # Normalise to list
        paths = [path] if isinstance(path, str) else path

        if len(paths) == 1:
            return self._load_single(paths[0])

        # Multiple paths — load each and union
        dfs = [self._load_single(p) for p in paths]
        result = dfs[0]
        for df in dfs[1:]:
            result = result.union(df)
        return result

    def _load_single(self, path: str) -> DataFrame:
        explicit_override = self._read_options.get('uc_passthrough_override')

        try:
            access_method, analysis = self.path_analyzer.analyze_path(
                path=path,
                format_type=self.format_type,
                explicit_override=explicit_override
            )
            logger.info(f"Routing {path} → {access_method} "
                        f"({'; '.join(analysis['reasoning'])})")

            if access_method == 'uc':
                return self._load_via_unity_catalog(path)
            else:
                return self._load_via_adls_direct(path)

        except Exception as e:
            logger.error(f"Failed to load {path}: {e}")
            raise RuntimeError(f"Data loading failed: {e}")

    # ------------------------------------------------------------------ #
    #  Shorthand format methods  (mirrors spark.read.csv(...) etc.)        #
    # ------------------------------------------------------------------ #

    def csv(self, path: Union[str, List[str]], **kwargs) -> DataFrame:
        """Shorthand for format('csv').options(**kwargs).load(path)."""
        self.format_type = 'csv'
        self._read_options.update(kwargs)
        return self.load(path)

    def json(self, path: Union[str, List[str]], **kwargs) -> DataFrame:
        """Shorthand for format('json').options(**kwargs).load(path)."""
        self.format_type = 'json'
        self._read_options.update(kwargs)
        return self.load(path)

    def parquet(self, path: Union[str, List[str]], **kwargs) -> DataFrame:
        """Shorthand for format('parquet').options(**kwargs).load(path)."""
        self.format_type = 'parquet'
        self._read_options.update(kwargs)
        return self.load(path)

    def text(self, path: Union[str, List[str]], **kwargs) -> DataFrame:
        """Shorthand for format('text').options(**kwargs).load(path)."""
        self.format_type = 'text'
        self._read_options.update(kwargs)
        return self.load(path)

    def orc(self, path: Union[str, List[str]], **kwargs) -> DataFrame:
        """Shorthand for format('orc').options(**kwargs).load(path)."""
        self.format_type = 'orc'
        self._read_options.update(kwargs)
        return self.load(path)

    def avro(self, path: Union[str, List[str]], **kwargs) -> DataFrame:
        """Shorthand for format('avro').options(**kwargs).load(path)."""
        self.format_type = 'avro'
        self._read_options.update(kwargs)
        return self.load(path)

    def table(self, table_name: str) -> DataFrame:
        """
        Load a Unity Catalog table by name (catalog.schema.table).
        Always routed through UC governance — never through ADLS direct.
        """
        logger.info(f"Loading table via UC: {table_name}")
        try:
            return self.spark.read.table(table_name)
        except Exception as e:
            raise RuntimeError(f"Table load failed for {table_name}: {e}")

    # ------------------------------------------------------------------ #
    #  Routing implementations                                             #
    # ------------------------------------------------------------------ #

    def _load_via_unity_catalog(self, path: str) -> DataFrame:
        """Standard Spark read — UC governs access."""
        reader = self.spark.read.format(self.format_type)

        for key, value in self._user_options().items():
            reader = reader.option(key, value)

        if self._schema:
            reader = reader.schema(self._schema)

        return reader.load(path)

    def _load_via_adls_direct(self, path: str) -> DataFrame:
        """Direct ADLS read using the user's credential token."""
        if not self.auth_manager.is_authenticated():
            raise RuntimeError("User not authenticated. Call auth_manager.initialize_user_context() first.")

        storage_account_url, container, blob_path = self._parse_adls_path(path)
        adls_client = self.auth_manager.get_adls_client(storage_account_url)

        from direct_adls_reader import DirectADLSReader
        reader = DirectADLSReader(adls_client, self.spark)

        fmt = self.format_type.lower()
        opts = self._user_options()

        dispatch = {
                'csv':        lambda: reader.read_csv_files(container, blob_path, options=opts),
                'json':       lambda: reader.read_json_files(container, blob_path, options=opts),
                'text':       lambda: reader.read_text_files(container, blob_path,
                                        encoding=opts.get('encoding'), options=opts),
                'binaryfile': lambda: reader.read_binary_files(container, blob_path, options=opts),
                'xml':        lambda: reader.read_xml_files(container, blob_path, options=opts),
                'parquet':    lambda: reader.read_parquet_files(container, blob_path, options=opts),
                'orc':        lambda: reader.read_orc_files(container, blob_path, options=opts),
                'avro':       lambda: reader.read_avro_files(container, blob_path, options=opts),
            }

        handler = dispatch.get(fmt)
        if handler is None:
            # Unsupported format for direct access — fall back to UC
            logger.warning(f"Format '{fmt}' not supported for direct ADLS access, "
                           f"falling back to Unity Catalog")
            return self._load_via_unity_catalog(path)

        try:
            return handler()
        except Exception as e:
            raise RuntimeError(f"ADLS direct read failed for {path}: {e}")

    def _load_structured_direct(self, reader, container: str, blob_path: str) -> DataFrame:
        """Read parquet directly via PyArrow without Spark token injection."""
        try:
            import pyarrow.parquet as pq
            import pyarrow as pa

            fs_client = reader.adls_client.get_file_system_client(container)
            file_client = fs_client.get_file_client(blob_path)
            content_bytes = file_client.download_file().readall()

            table = pq.read_table(pa.BufferReader(content_bytes))
            return self.spark.createDataFrame(table.to_pandas())

        except ImportError:
            raise RuntimeError("PyArrow required for direct parquet reading. "
                               "Install: pip install pyarrow")

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _user_options(self) -> Dict[str, Any]:
        """Return options with internal uc_passthrough_ keys stripped."""
        return {k: v for k, v in self._read_options.items()
                if not k.startswith('uc_passthrough_')}

    def _parse_adls_path(self, path: str):
        """
        Parse abfss://container@account.dfs.core.windows.net/path
        into (storage_account_url, container, blob_path).
        """
        if not path.startswith('abfss://'):
            raise ValueError(f"Expected abfss:// path, got: {path}")

        parsed = urlparse(path)
        parts = parsed.netloc.split('@')
        if len(parts) != 2:
            raise ValueError(f"Invalid abfss path format: {path}")

        container = parts[0]
        account_host = parts[1]
        storage_account_url = f"https://{account_host}"
        blob_path = parsed.path.lstrip('/')

        return storage_account_url, container, blob_path


# --------------------------------------------------------------------------- #
#  UCPassthroughDataFrameReader                                                #
#  Drop-in wrapper for the SparkSession.  Exposes a .read property that        #
#  behaves exactly like spark.read, plus passes through all other spark attrs. #
# --------------------------------------------------------------------------- #

class UCPassthroughDataFrameReader:
    """
    Wraps a SparkSession so that spark.read is intercepted and routed through
    the passthrough library, while all other spark.* attributes work unchanged.

    Usage:
        spark = UCPassthroughDataFrameReader(spark, auth_manager, path_analyzer)

        # These now use credential passthrough where appropriate:
        df = spark.read.format('csv').option('header', 'true').load('abfss://...')
        df = spark.read.csv('abfss://...', header='true')
        df = spark.read.parquet('abfss://...')
        df = spark.read.table('catalog.schema.table')

        # These pass straight through to native Spark unchanged:
        spark.sql("SELECT ...")
        spark.createDataFrame(...)
        spark.catalog.listTables()
    """

    def __init__(self, spark_session: SparkSession,
                 auth_manager: AuthenticationManager,
                 path_analyzer: PathAnalyzer):
        # Store under mangled names so __getattr__ doesn't intercept them
        object.__setattr__(self, '_spark', spark_session)
        object.__setattr__(self, '_auth_manager', auth_manager)
        object.__setattr__(self, '_path_analyzer', path_analyzer)

    # ------------------------------------------------------------------ #
    #  .read property — returns our reader, not spark.read                 #
    # ------------------------------------------------------------------ #

    @property
    def read(self) -> 'UCPassthroughReaderProxy':
        """Returns a reader proxy that mirrors the full DataFrameReader API."""
        return UCPassthroughReaderProxy(
            spark_session=object.__getattribute__(self, '_spark'),
            auth_manager=object.__getattribute__(self, '_auth_manager'),
            path_analyzer=object.__getattribute__(self, '_path_analyzer')
        )

    # ------------------------------------------------------------------ #
    #  Pass all other spark.* attributes straight through                  #
    # ------------------------------------------------------------------ #

    def __getattr__(self, name: str):
        spark = object.__getattribute__(self, '_spark')
        return getattr(spark, name)

    def __repr__(self):
        spark = object.__getattribute__(self, '_spark')
        return f"UCPassthroughDataFrameReader(wrapping={repr(spark)})"


# --------------------------------------------------------------------------- #
#  UCPassthroughReaderProxy                                                    #
#  Returned by spark.read — mirrors DataFrameReader completely.               #
# --------------------------------------------------------------------------- #

class UCPassthroughReaderProxy:
    """
    Mirrors spark.read exactly.  Creates a UCPassthroughFormatReader internally
    and delegates all DataFrameReader methods to it.

    Supports:
        .format(fmt)
        .option(k, v)
        .options(**kwargs)
        .schema(schema)
        .load(path)          — single path or list of paths
        .csv(path, **opts)
        .json(path, **opts)
        .parquet(path, **opts)
        .text(path, **opts)
        .orc(path, **opts)
        .avro(path, **opts)
        .table(table_name)
    """

    def __init__(self, spark_session: SparkSession,
                 auth_manager: AuthenticationManager,
                 path_analyzer: PathAnalyzer):
        self._spark = spark_session
        self._auth_manager = auth_manager
        self._path_analyzer = path_analyzer
        # Internal format reader — starts with a default format
        self._reader = UCPassthroughFormatReader(
            format_type='text',          # overridden by format() or shorthand methods
            spark_session=spark_session,
            auth_manager=auth_manager,
            path_analyzer=path_analyzer
        )

    def format(self, source: str) -> 'UCPassthroughReaderProxy':
        self._reader.format_type = source
        return self

    def option(self, key: str, value: Any) -> 'UCPassthroughReaderProxy':
        self._reader.option(key, value)
        return self

    def options(self, **kwargs) -> 'UCPassthroughReaderProxy':
        self._reader.options(**kwargs)
        return self

    def schema(self, schema: Union[StructType, str]) -> 'UCPassthroughReaderProxy':
        self._reader.schema(schema)
        return self

    def load(self, path: Optional[Union[str, List[str]]] = None) -> DataFrame:
        return self._reader.load(path)

    def csv(self, path: Union[str, List[str]], **kwargs) -> DataFrame:
        return self._reader.csv(path, **kwargs)

    def json(self, path: Union[str, List[str]], **kwargs) -> DataFrame:
        return self._reader.json(path, **kwargs)

    def parquet(self, path: Union[str, List[str]], **kwargs) -> DataFrame:
        return self._reader.parquet(path, **kwargs)

    def text(self, path: Union[str, List[str]], **kwargs) -> DataFrame:
        return self._reader.text(path, **kwargs)

    def orc(self, path: Union[str, List[str]], **kwargs) -> DataFrame:
        return self._reader.orc(path, **kwargs)

    def avro(self, path: Union[str, List[str]], **kwargs) -> DataFrame:
        return self._reader.avro(path, **kwargs)

    def table(self, table_name: str) -> DataFrame:
        return self._reader.table(table_name)

    def __repr__(self):
        return (f"UCPassthroughReaderProxy(format={self._reader.format_type}, "
                f"options={self._reader._read_options})")
