"""
Shared pytest fixtures for UC Passthrough tests.

All tests mock DataLakeServiceClient, FileSystemClient, DataLakeFileClient,
and SparkSession so that no real ADLS or Spark calls are made.
"""

import io
import sys
import types
import importlib
from unittest.mock import MagicMock, patch, PropertyMock
from functools import wraps

import pytest
import pandas as pd


# ---------------------------------------------------------------------------
# Minimal PySpark stubs so tests run without a real Spark cluster
# ---------------------------------------------------------------------------

def _build_pyspark_stub():
    """Create a minimal pyspark module stub for testing."""
    pyspark = types.ModuleType("pyspark")
    pyspark_sql = types.ModuleType("pyspark.sql")
    pyspark_sql_types = types.ModuleType("pyspark.sql.types")
    pyspark_sql_functions = types.ModuleType("pyspark.sql.functions")

    class _BaseType:
        def simpleString(self):
            return self.__class__.__name__

    class StringType(_BaseType):
        pass

    class BinaryType(_BaseType):
        pass

    class LongType(_BaseType):
        pass

    class TimestampType(_BaseType):
        pass

    class IntegerType(_BaseType):
        pass

    class StructField:
        def __init__(self, name, dataType, nullable=True):
            self.name = name
            self.dataType = dataType
            self.nullable = nullable

    class StructType:
        def __init__(self, fields=None):
            self.fields = fields or []

    pyspark_sql_types.StringType = StringType
    pyspark_sql_types.BinaryType = BinaryType
    pyspark_sql_types.LongType = LongType
    pyspark_sql_types.TimestampType = TimestampType
    pyspark_sql_types.IntegerType = IntegerType
    pyspark_sql_types.StructField = StructField
    pyspark_sql_types.StructType = StructType

    pyspark_sql_functions.col = MagicMock()
    pyspark_sql_functions.lit = MagicMock()

    class DataFrame:
        def __init__(self, pandas_df=None, schema=None):
            self._pdf = pandas_df if pandas_df is not None else pd.DataFrame()
            self._schema = schema
            self.columns = list(self._pdf.columns)

        @property
        def schema(self):
            return self._schema

        @property
        def dtypes(self):
            return [(col, 'string') for col in self.columns]

        def toPandas(self):
            return self._pdf

        def count(self):
            return len(self._pdf)

    class SparkSession:
        def createDataFrame(self, data, schema=None):
            if isinstance(data, pd.DataFrame):
                return DataFrame(data, schema)
            elif isinstance(data, list):
                return DataFrame(pd.DataFrame(data), schema)
            return DataFrame(pd.DataFrame(), schema)

    pyspark_sql.DataFrame = DataFrame
    pyspark_sql.SparkSession = SparkSession

    pyspark.sql = pyspark_sql
    sys.modules["pyspark"] = pyspark
    sys.modules["pyspark.sql"] = pyspark_sql
    sys.modules["pyspark.sql.types"] = pyspark_sql_types
    sys.modules["pyspark.sql.functions"] = pyspark_sql_functions

    return SparkSession, DataFrame, pyspark_sql_types


SparkSession, DataFrame, pyspark_types = _build_pyspark_stub()


# ---------------------------------------------------------------------------
# Patch Azure stubs and neutralise _protect_adls_method BEFORE import
# ---------------------------------------------------------------------------

# Force-replace these mocks regardless of prior imports so that patch() resolves
# dotted names (e.g. "pyarrow.parquet.read_table") against our mocks on all
# Python versions. Using setdefault here is insufficient because pyarrow/azure
# are installed packages that may already be in sys.modules by the time conftest
# runs. In Python <3.11, patch() uses getattr() on the parent module object and
# does NOT fall back to sys.modules["pyarrow.parquet"] if the real pyarrow
# module doesn't expose .parquet as an attribute yet.
_azure_mock = MagicMock()
_azure_storage_mock = MagicMock()
_azure_filedatalake_mock = MagicMock()
_azure_core_mock = MagicMock()
_azure_core_exceptions_mock = MagicMock()
_azure_storage_mock.filedatalake = _azure_filedatalake_mock
_azure_core_mock.exceptions = _azure_core_exceptions_mock
_azure_mock.storage = _azure_storage_mock
_azure_mock.core = _azure_core_mock

_pyarrow_mock = MagicMock()
_pyarrow_parquet_mock = MagicMock()
_pyarrow_orc_mock = MagicMock()
_pyarrow_mock.parquet = _pyarrow_parquet_mock
_pyarrow_mock.orc = _pyarrow_orc_mock

sys.modules["azure"] = _azure_mock
sys.modules["azure.storage"] = _azure_storage_mock
sys.modules["azure.storage.filedatalake"] = _azure_filedatalake_mock
sys.modules["azure.core"] = _azure_core_mock
sys.modules["azure.core.exceptions"] = _azure_core_exceptions_mock
sys.modules["pyarrow"] = _pyarrow_mock
sys.modules["pyarrow.parquet"] = _pyarrow_parquet_mock
sys.modules["pyarrow.orc"] = _pyarrow_orc_mock
sys.modules.setdefault("chardet", MagicMock())
sys.modules.setdefault("fastavro", MagicMock())

# Add source path — resolved relative to this file so it works in CI and locally
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "UC passthrough"))

# Import the writer module and unwrap all protected methods on DirectADLSWriter
# so tests can call them directly without frame-inspection blocking.
import direct_adls_writer as _writer_mod

_DirectADLSWriter = _writer_mod.DirectADLSWriter
for _attr_name in dir(_DirectADLSWriter):
    _attr = getattr(_DirectADLSWriter, _attr_name)
    # The decorator uses functools.wraps, so __wrapped__ points to the original
    if callable(_attr) and hasattr(_attr, "__wrapped__"):
        setattr(_DirectADLSWriter, _attr_name, _attr.__wrapped__)

# Also import reader (no decorator issue, but ensure it's loaded)
import direct_adls_reader  # noqa: F401


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_file_properties():
    props = MagicMock()
    props.size = 1024
    props.last_modified = None
    return props


@pytest.fixture
def mock_file_client(mock_file_properties):
    client = MagicMock()
    client.get_file_properties.return_value = mock_file_properties
    client.upload_data = MagicMock()
    client.flush_data = MagicMock()
    return client


@pytest.fixture
def mock_file_system_client(mock_file_client):
    fs_client = MagicMock()
    fs_client.get_file_client.return_value = mock_file_client
    fs_client.get_paths.return_value = []
    return fs_client


@pytest.fixture
def mock_adls_client(mock_file_system_client):
    client = MagicMock()
    client.account_name = "teststorage"
    client.get_file_system_client.return_value = mock_file_system_client
    return client


@pytest.fixture
def spark():
    return SparkSession()


def make_download_response(content: bytes):
    """Create a mock download response that supports chunked streaming."""
    download = MagicMock()
    download.readall.return_value = content
    download.chunks.return_value = iter([content])
    return download


class MockField:
    """A mock schema field with a proper .name attribute (MagicMock's name= is special)."""
    def __init__(self, name, dataType):
        self.name = name
        self.dataType = dataType


class MockSchema:
    """A mock DataFrame schema."""
    def __init__(self, fields):
        self.fields = fields
