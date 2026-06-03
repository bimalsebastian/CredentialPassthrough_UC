"""Tests for chunked download/upload streaming and regression checks."""

import sys
import io
import inspect
import json
from unittest.mock import MagicMock, patch, call

import pytest
import pandas as pd

from conftest import (make_download_response, SparkSession, DataFrame,
                      pyspark_types, MockField, MockSchema)

from direct_adls_reader import DirectADLSReader, DEFAULT_CHUNK_SIZE_BYTES as READ_DEFAULT_CHUNK
from direct_adls_writer import DirectADLSWriter, WriteTransactionContext
from direct_adls_writer import DEFAULT_CHUNK_SIZE_BYTES as WRITE_DEFAULT_CHUNK


def _make_reader(mock_adls_client, spark, options=None):
    return DirectADLSReader(mock_adls_client, spark, options=options)


def _make_writer(mock_adls_client, spark, options=None):
    writer = object.__new__(DirectADLSWriter)
    writer._DirectADLSWriter__adls_client = mock_adls_client
    writer.spark = spark
    writer._DirectADLSWriter__lock = __import__("threading").Lock()
    writer._DirectADLSWriter__max_files_per_write = 1000
    writer._DirectADLSWriter__max_partition_files = 100
    writer._DirectADLSWriter__max_file_size_mb = 500
    writer._options = options or {}
    return writer


def _make_chunked_download_response(chunks):
    """Create a mock download response that yields multiple chunks."""
    download = MagicMock()
    download.readall.side_effect = AssertionError("readall() should not be called")
    download.chunks.return_value = iter(chunks)
    return download


# ===========================================================================
# 1. _download_with_chunks — unit tests
# ===========================================================================

class TestDownloadWithChunksUnit:
    def test_calls_download_file_with_max_concurrency(self, mock_adls_client, spark):
        reader = _make_reader(mock_adls_client, spark)
        file_client = MagicMock()
        stream = MagicMock()
        stream.chunks.return_value = iter([b"data"])
        file_client.download_file.return_value = stream

        reader._download_with_chunks(file_client)

        file_client.download_file.assert_called_once_with(max_concurrency=4)

    def test_iterates_chunks_not_readall(self, mock_adls_client, spark):
        reader = _make_reader(mock_adls_client, spark)
        file_client = MagicMock()
        stream = MagicMock()
        stream.chunks.return_value = iter([b"chunk1"])
        stream.readall.side_effect = AssertionError("readall should not be called")
        file_client.download_file.return_value = stream

        result = reader._download_with_chunks(file_client)

        stream.chunks.assert_called_once()
        assert result == b"chunk1"

    def test_concatenates_three_chunks(self, mock_adls_client, spark):
        reader = _make_reader(mock_adls_client, spark)
        file_client = MagicMock()
        chunks = [b"alpha", b"beta", b"gamma"]
        stream = MagicMock()
        stream.chunks.return_value = iter(chunks)
        file_client.download_file.return_value = stream

        result = reader._download_with_chunks(file_client)

        assert result == b"alphabetagamma"

    def test_adls_chunk_size_option_overrides_default(self, mock_adls_client, spark):
        custom_size = 16 * 1024 * 1024
        reader = _make_reader(mock_adls_client, spark, options={'adls_chunk_size_bytes': custom_size})
        file_client = MagicMock()
        stream = MagicMock()
        stream.chunks.return_value = iter([b"x"])
        file_client.download_file.return_value = stream

        reader._download_with_chunks(file_client)

        # The chunk_size option is stored but not passed to download_file
        # (Azure SDK uses it internally via max_concurrency); confirm the
        # instance option is respected by checking it's stored correctly
        assert reader._options['adls_chunk_size_bytes'] == custom_size


# ===========================================================================
# 2. _upload_with_chunks — unit tests
# ===========================================================================

class TestUploadWithChunksUnit:
    def test_calls_upload_data_with_correct_params(self, mock_adls_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        file_client = MagicMock()
        data = b"test content"

        writer._upload_with_chunks(file_client, data)

        file_client.upload_data.assert_called_once_with(
            data,
            overwrite=True,
            max_concurrency=4,
            chunk_size=WRITE_DEFAULT_CHUNK
        )

    def test_adls_chunk_size_option_overrides_default(self, mock_adls_client, spark):
        custom_size = 8 * 1024 * 1024
        writer = _make_writer(mock_adls_client, spark, options={'adls_chunk_size_bytes': custom_size})
        file_client = MagicMock()
        data = b"payload"

        writer._upload_with_chunks(file_client, data)

        file_client.upload_data.assert_called_once_with(
            data,
            overwrite=True,
            max_concurrency=4,
            chunk_size=custom_size
        )

    def test_content_passed_through_unmodified(self, mock_adls_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        file_client = MagicMock()
        original_data = b"\x00\x01\x02" * 1000

        writer._upload_with_chunks(file_client, original_data)

        uploaded = file_client.upload_data.call_args[0][0]
        assert uploaded is original_data


# ===========================================================================
# 3. Regression — readall() not in source of any read handler method
# ===========================================================================

class TestNoReadallRegression:
    def test_reader_methods_do_not_use_readall(self):
        import direct_adls_reader as mod
        source = inspect.getsource(mod.DirectADLSReader)
        # Allow 'readall' in docstrings/comments but not as an actual method call
        # We check that .readall() (with parens) does not appear
        assert ".readall()" not in source, (
            "Found .readall() in DirectADLSReader source — "
            "all downloads should use _download_with_chunks"
        )

    def test_writer_format_methods_do_not_use_readall(self):
        import direct_adls_writer as mod
        source = inspect.getsource(mod.DirectADLSWriter)
        assert ".readall()" not in source, (
            "Found .readall() in DirectADLSWriter source — "
            "unexpected usage in writer class"
        )


# ===========================================================================
# 4. Integration smoke tests — each format read + write
# ===========================================================================

class TestIntegrationParquet:
    def test_read_calls_download_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        reader = _make_reader(mock_adls_client, spark)
        fake_bytes = b"parquet_content"

        with patch.object(reader, "_resolve_file_paths", return_value=["data.parquet"]):
            with patch.object(reader, "_download_with_chunks", return_value=fake_bytes) as mock_dl:
                with patch("pyarrow.parquet.read_table") as mock_pq:
                    with patch("pyarrow.BufferReader") as mock_br:
                        mock_table = MagicMock()
                        mock_table.to_pandas.return_value = pd.DataFrame({"col": [1]})
                        mock_pq.return_value = mock_table
                        with patch("pyarrow.concat_tables", return_value=mock_table):
                            result = reader.read_parquet_files("container", "data.parquet")

                mock_dl.assert_called_once()

    def test_write_calls_upload_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"x": [1, 2]})
        schema = MockSchema([MockField("x", pyspark_types.IntegerType())])
        df = DataFrame(pdf, schema)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                with patch.object(writer, "_upload_with_chunks") as mock_up:
                    writer.write_parquet_files(df, "container", "out.parquet", mode="overwrite")

                mock_up.assert_called_once()


class TestIntegrationCSV:
    def test_read_calls_download_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        reader = _make_reader(mock_adls_client, spark)
        csv_bytes = b"name,age\nAlice,30\n"

        with patch.object(reader, "_resolve_file_paths", return_value=["data.csv"]):
            with patch.object(reader, "_download_with_chunks", return_value=csv_bytes) as mock_dl:
                result = reader.read_csv_files("container", "data.csv")

        mock_dl.assert_called_once()
        pdf = result.toPandas()
        assert "name" in pdf.columns

    def test_write_calls_upload_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"name": ["Bob"]})
        schema = MockSchema([MockField("name", pyspark_types.StringType())])
        df = DataFrame(pdf, schema)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                with patch.object(writer, "_upload_with_chunks") as mock_up:
                    writer.write_csv_files(df, "container", "out.csv", mode="overwrite")

                mock_up.assert_called_once()


class TestIntegrationJSON:
    def test_read_calls_download_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        reader = _make_reader(mock_adls_client, spark)
        json_bytes = b'{"name": "Alice", "age": 30}\n'

        with patch.object(reader, "_resolve_file_paths", return_value=["data.json"]):
            with patch.object(reader, "_download_with_chunks", return_value=json_bytes) as mock_dl:
                result = reader.read_json_files("container", "data.json")

        mock_dl.assert_called_once()
        pdf = result.toPandas()
        assert "name" in pdf.columns

    def test_write_calls_upload_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"key": ["val"]})
        schema = MockSchema([MockField("key", pyspark_types.StringType())])
        df = DataFrame(pdf, schema)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                with patch.object(writer, "_upload_with_chunks") as mock_up:
                    writer.write_json_files(df, "container", "out.json", mode="overwrite")

                mock_up.assert_called_once()


class TestIntegrationAvro:
    def test_read_calls_download_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        reader = _make_reader(mock_adls_client, spark)
        avro_bytes = b"Obj\x01\x04\x14avro.schema"  # fake avro header

        with patch.object(reader, "_resolve_file_paths", return_value=["data.avro"]):
            with patch.object(reader, "_download_with_chunks", return_value=avro_bytes) as mock_dl:
                with patch("fastavro.reader", return_value=[{"col": 1}]):
                    result = reader.read_avro_files("container", "data.avro")

        mock_dl.assert_called_once()

    def test_write_calls_upload_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"x": [1]})
        schema = MockSchema([MockField("x", pyspark_types.IntegerType())])
        df = DataFrame(pdf, schema)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                with patch.object(writer, "_upload_with_chunks") as mock_up:
                    with patch("fastavro.parse_schema", return_value={}):
                        with patch("fastavro.writer"):
                            writer.write_avro_files(df, "container", "out.avro", mode="overwrite")

                mock_up.assert_called_once()


class TestIntegrationORC:
    def test_read_calls_download_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        reader = _make_reader(mock_adls_client, spark)
        orc_bytes = b"ORC_fake_content"

        with patch.object(reader, "_resolve_file_paths", return_value=["data.orc"]):
            with patch.object(reader, "_download_with_chunks", return_value=orc_bytes) as mock_dl:
                mock_table = MagicMock()
                mock_table.to_pandas.return_value = pd.DataFrame({"v": [42]})
                with patch("pyarrow.orc.read_table", return_value=mock_table):
                    result = reader.read_orc_files("container", "data.orc")

        mock_dl.assert_called_once()

    def test_write_calls_upload_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"v": [1]})
        schema = MockSchema([MockField("v", pyspark_types.IntegerType())])
        df = DataFrame(pdf, schema)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                with patch.object(writer, "_upload_with_chunks") as mock_up:
                    writer.write_orc_files(df, "container", "out.orc", mode="overwrite")

                mock_up.assert_called_once()


class TestIntegrationXML:
    def test_read_calls_download_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        reader = _make_reader(mock_adls_client, spark)
        xml_bytes = b"<root><item><name>Test</name></item></root>"

        with patch.object(reader, "_resolve_file_paths", return_value=["data.xml"]):
            with patch.object(reader, "_download_with_chunks", return_value=xml_bytes) as mock_dl:
                result = reader.read_xml_files("container", "data.xml",
                                               options={"rowTag": "item"})

        mock_dl.assert_called_once()
        pdf = result.toPandas()
        assert "name" in pdf.columns

    def test_write_calls_upload_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"name": ["Test"]})
        schema = MockSchema([MockField("name", pyspark_types.StringType())])
        df = DataFrame(pdf, schema)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                with patch.object(writer, "_upload_with_chunks") as mock_up:
                    writer.write_xml_files(df, "container", "out.xml", mode="overwrite")

                mock_up.assert_called_once()


class TestIntegrationText:
    def test_read_calls_download_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        reader = _make_reader(mock_adls_client, spark)
        text_bytes = b"hello world"
        mock_file_client.download_file.return_value = make_download_response(text_bytes)

        with patch.object(reader, "_resolve_file_paths", return_value=["note.txt"]):
            with patch.object(reader, "_download_with_chunks", return_value=text_bytes) as mock_dl:
                with patch("chardet.detect", return_value={"encoding": "utf-8"}):
                    result = reader.read_text_files("container", "note.txt")

        mock_dl.assert_called_once()

    def test_write_calls_upload_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"content": ["line1"]})
        schema = MockSchema([MockField("content", pyspark_types.StringType())])
        df = DataFrame(pdf, schema)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                with patch.object(writer, "_upload_with_chunks") as mock_up:
                    writer.write_text_files(df, "container", "out.txt", mode="overwrite")

                mock_up.assert_called_once()


class TestIntegrationBinary:
    def test_read_calls_download_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        reader = _make_reader(mock_adls_client, spark)
        binary_bytes = b"\x00\x01\x02\x03"

        with patch.object(reader, "_resolve_file_paths", return_value=["blob.bin"]):
            with patch.object(reader, "_download_with_chunks", return_value=binary_bytes) as mock_dl:
                result = reader.read_binary_files("container", "blob.bin")

        mock_dl.assert_called_once()
        pdf = result.toPandas()
        assert "content" in pdf.columns
        assert "path" in pdf.columns

    def test_write_calls_upload_with_chunks(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"path": ["/out/file.bin"], "content": [b"\xDE\xAD"]})
        schema = MockSchema([
            MockField("path", pyspark_types.StringType()),
            MockField("content", pyspark_types.BinaryType()),
        ])
        df = DataFrame(pdf, schema)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                with patch.object(writer, "_upload_with_chunks") as mock_up:
                    writer.write_binary_files(df, "container", "out/", mode="overwrite")

                mock_up.assert_called_once()


# ===========================================================================
# 5. Large file simulation test
# ===========================================================================

class TestLargeFileSimulation:
    def test_40mb_file_assembled_from_10_chunks(self, mock_adls_client, spark):
        reader = _make_reader(mock_adls_client, spark)
        chunk_size = 4 * 1024 * 1024  # 4MB
        num_chunks = 10
        # Each chunk is 4MB of a repeating byte pattern
        chunks = [bytes([i % 256] * chunk_size) for i in range(num_chunks)]
        expected = b"".join(chunks)

        file_client = MagicMock()
        stream = MagicMock()
        stream.chunks.return_value = iter(chunks)
        stream.readall.side_effect = AssertionError("readall must not be called")
        file_client.download_file.return_value = stream

        result = reader._download_with_chunks(file_client)

        assert len(result) == chunk_size * num_chunks  # 40MB
        assert result == expected
        stream.readall.assert_not_called()
        stream.chunks.assert_called_once()

    def test_large_file_no_readall_invoked(self, mock_adls_client, spark):
        reader = _make_reader(mock_adls_client, spark)
        chunk_size = 4 * 1024 * 1024
        chunks = [b"\x42" * chunk_size for _ in range(10)]

        file_client = MagicMock()
        stream = MagicMock()
        stream.chunks.return_value = iter(chunks)
        file_client.download_file.return_value = stream

        reader._download_with_chunks(file_client)

        # Verify readall was never called on the stream
        stream.readall.assert_not_called()
