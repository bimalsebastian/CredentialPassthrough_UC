"""
UC Passthrough Library - DataFrame Writer Module

Drop-in replacement for df.write and spark.write that routes data writes between
Unity Catalog governance and direct ADLS access with user credentials — mirroring
the same routing logic used on the read side.

Usage:
    # Wrap once at session level (also exposes spark.write)
    spark = UCPassthroughDataFrameReader(spark, auth_manager, path_analyzer)

    # Intercept df.write for any DataFrame produced by the session
    df = spark.read.parquet('abfss://...')
    spark.patch_dataframe_write(df)       # df.write is now passthrough-aware
    df.write.mode('overwrite').parquet('abfss://...')

    # Or use the writer proxy directly
    writer = UCPassthroughWriterProxy(df, spark, auth_manager, path_analyzer)
    writer.mode('overwrite').format('parquet').save('abfss://...')
    writer.saveAsTable('catalog.schema.table')
"""

import logging
from typing import Optional, Dict, Any, Union, List
from urllib.parse import urlparse

try:
    from pyspark.sql import DataFrame, SparkSession
    from pyspark.sql.types import StructType
except ImportError as e:
    raise ImportError(f"PySpark not found: {e}.")

from path_analyzer import PathAnalyzer
from authentication_manager import AuthenticationManager

logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────────
#  UCPassthroughFormatWriter
#  Core routing logic — analogous to UCPassthroughFormatReader
# ────────────────────────────────────────────────────────────────────────────────

class UCPassthroughFormatWriter:
    """
    Format-specific writer that mirrors the Spark DataFrameWriter API and applies
    the same path-based routing logic used by UCPassthroughFormatReader.

    Routing rules:
    - Output path is analysed by PathAnalyzer to decide UC vs ADLS direct.
    - uc_passthrough_override option ('uc' or 'adls') always wins.
    - Delta format always routes through UC (transaction log managed by UC/Delta).
    - saveAsTable / insertInto always route through UC governance.
    """

    # Formats routed directly to ADLS when path analysis says 'adls'
    _ADLS_DIRECT_FORMATS = {'csv', 'json', 'text', 'binaryfile', 'parquet', 'orc', 'avro'}

    # Formats that always go through UC regardless of path
    _UC_ONLY_FORMATS = {'delta', 'jdbc', 'table'}

    def __init__(self, dataframe: DataFrame, format_type: str,
                 spark_session: SparkSession,
                 auth_manager: AuthenticationManager,
                 path_analyzer: PathAnalyzer):
        self._df = dataframe
        self._format_type = format_type
        self._spark = spark_session
        self._auth_manager = auth_manager
        self._path_analyzer = path_analyzer

        self._write_options: Dict[str, Any] = {}
        self._write_mode: str = 'error'
        self._partition_cols: List[str] = []
        self._sort_cols: List[str] = []
        self._bucket_count: Optional[int] = None
        self._bucket_cols: List[str] = []

        logger.debug(f"UCPassthroughFormatWriter created for format: {format_type}")

    # ── builder methods ──────────────────────────────────────────────────────

    def option(self, key: str, value: Any) -> 'UCPassthroughFormatWriter':
        self._write_options[key] = value
        return self

    def options(self, **kwargs) -> 'UCPassthroughFormatWriter':
        self._write_options.update(kwargs)
        return self

    def mode(self, save_mode: str) -> 'UCPassthroughFormatWriter':
        """Set the write mode: 'overwrite', 'append', 'ignore', 'error'."""
        valid = {'overwrite', 'append', 'ignore', 'error', 'errorifexists'}
        if save_mode.lower() not in valid:
            raise ValueError(f"Invalid mode '{save_mode}'. Must be one of {valid}.")
        self._write_mode = save_mode.lower()
        return self

    def partitionBy(self, *cols) -> 'UCPassthroughFormatWriter':
        """Partition the output by the given column names."""
        self._partition_cols = list(cols[0] if len(cols) == 1 and isinstance(cols[0], list) else cols)
        return self

    def bucketBy(self, num_buckets: int, *cols) -> 'UCPassthroughFormatWriter':
        """Bucket by column(s) — only meaningful for UC-routed writes."""
        self._bucket_count = num_buckets
        self._bucket_cols = list(cols[0] if len(cols) == 1 and isinstance(cols[0], list) else cols)
        return self

    def sortBy(self, *cols) -> 'UCPassthroughFormatWriter':
        """Sort within buckets — only meaningful for UC-routed writes."""
        self._sort_cols = list(cols[0] if len(cols) == 1 and isinstance(cols[0], list) else cols)
        return self

    # ── terminal actions ─────────────────────────────────────────────────────

    def save(self, path: str) -> None:
        """Write the DataFrame to the given path, routing via PathAnalyzer."""
        if path is None:
            raise ValueError("Path must be specified for save().")

        explicit_override = self._write_options.get('uc_passthrough_override')

        try:
            access_method, analysis = self._path_analyzer.analyze_path(
                path=path,
                format_type=self._format_type,
                explicit_override=explicit_override
            )
            logger.info(
                f"Write routing {path} → {access_method} "
                f"({'; '.join(analysis['reasoning'])})"
            )

            if access_method == 'uc' or self._format_type.lower() in self._UC_ONLY_FORMATS:
                self._write_via_unity_catalog(path)
            else:
                self._write_via_adls_direct(path)

        except Exception as e:
            logger.error(f"Failed to write to {path}: {e}")
            raise RuntimeError(f"Data write failed: {e}")

    def saveAsTable(self, table_name: str) -> None:
        """
        Save the DataFrame as a Unity Catalog table (catalog.schema.table).
        Always routed through UC governance — never through ADLS direct.
        """
        logger.info(f"Writing table via UC: {table_name}")
        try:
            writer = self._build_spark_writer()
            writer.saveAsTable(table_name)
        except Exception as e:
            raise RuntimeError(f"saveAsTable failed for {table_name}: {e}")

    def insertInto(self, table_name: str, overwrite: bool = False) -> None:
        """
        Insert into an existing Unity Catalog table.
        Always routed through UC governance.
        """
        logger.info(f"insertInto via UC: {table_name} (overwrite={overwrite})")
        try:
            writer = self._build_spark_writer()
            writer.insertInto(table_name, overwrite=overwrite)
        except Exception as e:
            raise RuntimeError(f"insertInto failed for {table_name}: {e}")

    # ── format shorthands ────────────────────────────────────────────────────

    def csv(self, path: str, **kwargs) -> None:
        self._format_type = 'csv'
        self._write_options.update(kwargs)
        self.save(path)

    def json(self, path: str, **kwargs) -> None:
        self._format_type = 'json'
        self._write_options.update(kwargs)
        self.save(path)

    def parquet(self, path: str, **kwargs) -> None:
        self._format_type = 'parquet'
        self._write_options.update(kwargs)
        self.save(path)

    def orc(self, path: str, **kwargs) -> None:
        self._format_type = 'orc'
        self._write_options.update(kwargs)
        self.save(path)

    def avro(self, path: str, **kwargs) -> None:
        self._format_type = 'avro'
        self._write_options.update(kwargs)
        self.save(path)

    def text(self, path: str, **kwargs) -> None:
        self._format_type = 'text'
        self._write_options.update(kwargs)
        self.save(path)

    # ── routing implementations ───────────────────────────────────────────────

    def _write_via_unity_catalog(self, path: str) -> None:
        """Delegate to Spark's native DataFrameWriter — UC governs access."""
        writer = self._build_spark_writer()
        writer.save(path)

    def _build_spark_writer(self):
        """Construct a native Spark DataFrameWriter from current state."""
        writer = self._df.write.format(self._format_type).mode(self._write_mode)

        for key, value in self._user_options().items():
            writer = writer.option(key, value)

        if self._partition_cols:
            writer = writer.partitionBy(*self._partition_cols)

        if self._bucket_count and self._bucket_cols:
            writer = writer.bucketBy(self._bucket_count, *self._bucket_cols)
            if self._sort_cols:
                writer = writer.sortBy(*self._sort_cols)

        return writer

    def _write_via_adls_direct(self, path: str) -> None:
        """Direct ADLS write using the user's credential token."""
        if not self._auth_manager.is_authenticated():
            raise RuntimeError(
                "User not authenticated. Call auth_manager.initialize_user_context() first."
            )

        storage_account_url, container, blob_path = self._parse_adls_path(path)
        adls_client = self._auth_manager.get_adls_client(storage_account_url)

        from direct_adls_writer import DirectADLSWriter
        writer = DirectADLSWriter(adls_client, self._spark)

        fmt = self._format_type.lower()
        opts = self._user_options()
        mode = self._write_mode
        partition_cols = self._partition_cols or None

        dispatch = {
            'csv':        lambda: writer.write_csv_files(
                              self._df, container, blob_path, mode, partition_cols, opts),
            'json':       lambda: writer.write_json_files(
                              self._df, container, blob_path, mode, partition_cols, opts),
            'text':       lambda: writer.write_text_files(
                              self._df, container, blob_path, mode, partition_cols, opts),
            'binaryfile': lambda: writer.write_binary_files(
                              self._df, container, blob_path, mode, partition_cols, opts),
            'parquet':    lambda: writer.write_parquet_files(
                              self._df, container, blob_path, mode, partition_cols, opts),
            'orc':        lambda: writer.write_orc_files(
                              self._df, container, blob_path, mode, partition_cols, opts),
            'avro':       lambda: writer.write_avro_files(
                              self._df, container, blob_path, mode, partition_cols, opts),
        }

        handler = dispatch.get(fmt)
        if handler is None:
            logger.warning(
                f"Format '{fmt}' not supported for direct ADLS write, falling back to UC"
            )
            self._write_via_unity_catalog(path)
            return

        try:
            handler()
        except Exception as e:
            raise RuntimeError(f"ADLS direct write failed for {path}: {e}")

    # ── helpers ───────────────────────────────────────────────────────────────

    def _user_options(self) -> Dict[str, Any]:
        """Strip internal uc_passthrough_* keys before passing to Spark or the writer."""
        return {k: v for k, v in self._write_options.items()
                if not k.startswith('uc_passthrough_')}

    def _parse_adls_path(self, path: str):
        """
        Parse abfss://container@account.dfs.core.windows.net/path
        into (storage_account_url, container, blob_path).
        """
        if not path.startswith('abfss://'):
            raise ValueError(f"Expected abfss:// path for ADLS direct write, got: {path}")

        parsed = urlparse(path)
        parts = parsed.netloc.split('@')
        if len(parts) != 2:
            raise ValueError(f"Invalid abfss path format: {path}")

        container = parts[0]
        account_host = parts[1]
        storage_account_url = f"https://{account_host}"
        blob_path = parsed.path.lstrip('/')
        return storage_account_url, container, blob_path


# ────────────────────────────────────────────────────────────────────────────────
#  UCPassthroughWriterProxy
#  Returned by df.write or spark.write — mirrors DataFrameWriter completely
# ────────────────────────────────────────────────────────────────────────────────

class UCPassthroughWriterProxy:
    """
    Mirrors spark.DataFrameWriter exactly.  Created from a DataFrame and delegates
    all builder calls to an internal UCPassthroughFormatWriter.

    Supports:
        .format(fmt)
        .option(k, v) / .options(**kwargs)
        .mode(m)
        .partitionBy(*cols)
        .bucketBy(n, *cols)
        .sortBy(*cols)
        .save(path)
        .saveAsTable(name)
        .insertInto(name, overwrite=False)
        .csv / .json / .parquet / .orc / .avro / .text  (shorthands)
    """

    def __init__(self, dataframe: DataFrame,
                 spark_session: SparkSession,
                 auth_manager: AuthenticationManager,
                 path_analyzer: PathAnalyzer):
        self._writer = UCPassthroughFormatWriter(
            dataframe=dataframe,
            format_type='parquet',        # sensible default; overridden by format() or shorthands
            spark_session=spark_session,
            auth_manager=auth_manager,
            path_analyzer=path_analyzer,
        )

    def format(self, source: str) -> 'UCPassthroughWriterProxy':
        self._writer._format_type = source
        return self

    def option(self, key: str, value: Any) -> 'UCPassthroughWriterProxy':
        self._writer.option(key, value)
        return self

    def options(self, **kwargs) -> 'UCPassthroughWriterProxy':
        self._writer.options(**kwargs)
        return self

    def mode(self, save_mode: str) -> 'UCPassthroughWriterProxy':
        self._writer.mode(save_mode)
        return self

    def partitionBy(self, *cols) -> 'UCPassthroughWriterProxy':
        self._writer.partitionBy(*cols)
        return self

    def bucketBy(self, num_buckets: int, *cols) -> 'UCPassthroughWriterProxy':
        self._writer.bucketBy(num_buckets, *cols)
        return self

    def sortBy(self, *cols) -> 'UCPassthroughWriterProxy':
        self._writer.sortBy(*cols)
        return self

    def save(self, path: str) -> None:
        self._writer.save(path)

    def saveAsTable(self, table_name: str) -> None:
        self._writer.saveAsTable(table_name)

    def insertInto(self, table_name: str, overwrite: bool = False) -> None:
        self._writer.insertInto(table_name, overwrite=overwrite)

    def csv(self, path: str, **kwargs) -> None:
        self._writer.csv(path, **kwargs)

    def json(self, path: str, **kwargs) -> None:
        self._writer.json(path, **kwargs)

    def parquet(self, path: str, **kwargs) -> None:
        self._writer.parquet(path, **kwargs)

    def orc(self, path: str, **kwargs) -> None:
        self._writer.orc(path, **kwargs)

    def avro(self, path: str, **kwargs) -> None:
        self._writer.avro(path, **kwargs)

    def text(self, path: str, **kwargs) -> None:
        self._writer.text(path, **kwargs)

    def __repr__(self) -> str:
        return (
            f"UCPassthroughWriterProxy("
            f"format={self._writer._format_type}, "
            f"mode={self._writer._write_mode}, "
            f"options={self._writer._write_options})"
        )


# ────────────────────────────────────────────────────────────────────────────────
#  _UCWriteDataFrame
#  Thin wrapper around a DataFrame that replaces .write with the proxy
# ────────────────────────────────────────────────────────────────────────────────

class _UCWriteDataFrame:
    """
    Wraps a Spark DataFrame so that .write returns a UCPassthroughWriterProxy
    instead of the native DataFrameWriter.

    All other DataFrame attributes/methods are passed through unchanged,
    so this is safe to use as a drop-in replacement.

    Example::

        df = spark.read.parquet('abfss://...')          # UCPassthroughDataFrameReader
        df = UCWriteDataFrame(df, spark, auth, analyzer)
        df.write.mode('overwrite').parquet('abfss://other/path')
    """

    def __init__(self, dataframe: DataFrame,
                 spark_session: SparkSession,
                 auth_manager: AuthenticationManager,
                 path_analyzer: PathAnalyzer):
        object.__setattr__(self, '_df', dataframe)
        object.__setattr__(self, '_spark', spark_session)
        object.__setattr__(self, '_auth_manager', auth_manager)
        object.__setattr__(self, '_path_analyzer', path_analyzer)

    @property
    def write(self) -> UCPassthroughWriterProxy:
        """Returns a write proxy instead of the native DataFrameWriter."""
        return UCPassthroughWriterProxy(
            dataframe=object.__getattribute__(self, '_df'),
            spark_session=object.__getattribute__(self, '_spark'),
            auth_manager=object.__getattribute__(self, '_auth_manager'),
            path_analyzer=object.__getattribute__(self, '_path_analyzer'),
        )

    def __getattr__(self, name: str):
        df = object.__getattribute__(self, '_df')
        return getattr(df, name)

    def __repr__(self) -> str:
        df = object.__getattribute__(self, '_df')
        return f"_UCWriteDataFrame(wrapping={repr(df)})"
