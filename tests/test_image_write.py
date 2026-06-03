"""Tests for DirectADLSWriter.write_image_files."""

import os
import sys
import io
from unittest.mock import MagicMock, patch

import pytest
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from conftest import (make_download_response, SparkSession, DataFrame,
                      pyspark_types, MockField, MockSchema)

from direct_adls_writer import DirectADLSWriter, WriteTransactionContext


def _make_writer(mock_adls_client, spark):
    writer = object.__new__(DirectADLSWriter)
    writer._DirectADLSWriter__adls_client = mock_adls_client
    writer.spark = spark
    writer._DirectADLSWriter__lock = __import__("threading").Lock()
    writer._DirectADLSWriter__max_files_per_write = 1000
    writer._DirectADLSWriter__max_partition_files = 100
    writer._DirectADLSWriter__max_file_size_mb = 500
    writer._options = {}
    return writer


def _make_image_dataframe(filenames_and_bytes):
    pdf = pd.DataFrame({
        "path": [f"/images/{fn}" for fn in filenames_and_bytes.keys()],
        "content": [b for b in filenames_and_bytes.values()],
    })
    schema = MockSchema([
        MockField("path", pyspark_types.StringType()),
        MockField("content", pyspark_types.BinaryType()),
    ])
    return DataFrame(pdf, schema)


class TestWriteImageFilesHappyPath:
    def test_writes_png_files(self, mock_adls_client, mock_file_system_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        df = _make_image_dataframe({"photo.png": b"\x89PNG\r\n"})

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "target_temp_abc")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                writer.write_image_files(df, "container", "images/output", mode="overwrite")

        mock_file_system_client.get_file_client.assert_called()

    def test_supports_all_extensions(self, mock_adls_client, mock_file_system_client, spark):
        extensions = ["png", "jpg", "jpeg", "tiff", "bmp", "gif"]
        files = {f"file.{ext}": b"\x00" * 10 for ext in extensions}
        writer = _make_writer(mock_adls_client, spark)
        df = _make_image_dataframe(files)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp_path")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                writer.write_image_files(df, "container", "images/", mode="overwrite")

        assert mock_file_system_client.get_file_client.call_count >= len(extensions)


class TestWriteImageFilesSchemaValidation:
    def test_missing_content_column_raises_valueerror(self, mock_adls_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"path": ["/img/test.png"]})
        schema = MockSchema([MockField("path", pyspark_types.StringType())])
        df = DataFrame(pdf, schema)

        with pytest.raises(ValueError, match="content"):
            writer.write_image_files(df, "container", "images/", mode="overwrite")

    def test_wrong_content_type_raises_valueerror(self, mock_adls_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"path": ["/img/test.png"], "content": ["not binary"]})
        schema = MockSchema([
            MockField("path", pyspark_types.StringType()),
            MockField("content", pyspark_types.StringType()),
        ])
        df = DataFrame(pdf, schema)

        with pytest.raises(ValueError, match="BinaryType"):
            writer.write_image_files(df, "container", "images/", mode="overwrite")

    def test_missing_path_column_raises_valueerror(self, mock_adls_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"content": [b"\x00"]})
        schema = MockSchema([MockField("content", pyspark_types.BinaryType())])
        df = DataFrame(pdf, schema)

        with pytest.raises(ValueError, match="path"):
            writer.write_image_files(df, "container", "images/", mode="overwrite")


class TestWriteImageFilesExtensionValidation:
    def test_unsupported_extension_raises_valueerror(self, mock_adls_client, mock_file_system_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        df = _make_image_dataframe({"document.pdf": b"\x00"})

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                with pytest.raises(ValueError, match="Unsupported image extension"):
                    writer.write_image_files(df, "container", "images/", mode="overwrite")


class TestWriteImageFilesEmptyInput:
    def test_empty_dataframe_no_error(self, mock_adls_client, mock_file_system_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"path": pd.Series(dtype=str), "content": pd.Series(dtype=object)})
        schema = MockSchema([
            MockField("path", pyspark_types.StringType()),
            MockField("content", pyspark_types.BinaryType()),
        ])
        df = DataFrame(pdf, schema)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                writer.write_image_files(df, "container", "images/", mode="overwrite")

        mock_file_system_client.get_file_client.return_value.upload_data.assert_not_called()
