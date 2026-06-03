"""Tests for YAML read and write handlers."""

import os
import sys
import io
import json
from unittest.mock import MagicMock, patch

import pytest
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from conftest import (make_download_response, SparkSession, DataFrame,
                      pyspark_types, MockField, MockSchema)

from direct_adls_reader import DirectADLSReader
from direct_adls_writer import DirectADLSWriter, WriteTransactionContext


def _make_reader(mock_adls_client, spark):
    return DirectADLSReader(mock_adls_client, spark)


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


# ===========================================================================
# READ TESTS
# ===========================================================================

class TestReadYamlHappyPath:
    def test_reads_simple_yaml(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        yaml_content = b"name: Alice\nage: 30\ncity: Portland\n"
        mock_file_client.download_file.return_value = make_download_response(yaml_content)

        reader = _make_reader(mock_adls_client, spark)
        with patch.object(reader, "_resolve_file_paths", return_value=["data/config.yaml"]):
            result = reader.read_yaml_files("container", "data/config.yaml")

        pdf = result.toPandas()
        assert "name" in pdf.columns
        assert pdf["name"].iloc[0] == "Alice"

    def test_reads_nested_yaml_with_dot_notation(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        yaml_content = b"database:\n  host: localhost\n  port: 5432\n  credentials:\n    user: admin\n"
        mock_file_client.download_file.return_value = make_download_response(yaml_content)

        reader = _make_reader(mock_adls_client, spark)
        with patch.object(reader, "_resolve_file_paths", return_value=["config.yaml"]):
            result = reader.read_yaml_files("container", "config.yaml")

        pdf = result.toPandas()
        assert "database.host" in pdf.columns
        assert "database.port" in pdf.columns
        assert "database.credentials.user" in pdf.columns

    def test_depth_beyond_3_serialised_as_json(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        yaml_content = b"level1:\n  level2:\n    level3:\n      level4:\n        deep_key: deep_value\n"
        mock_file_client.download_file.return_value = make_download_response(yaml_content)

        reader = _make_reader(mock_adls_client, spark)
        with patch.object(reader, "_resolve_file_paths", return_value=["deep.yaml"]):
            result = reader.read_yaml_files("container", "deep.yaml")

        pdf = result.toPandas()
        assert "level1.level2.level3" in pdf.columns
        value = pdf["level1.level2.level3"].iloc[0]
        assert isinstance(value, str)
        parsed = json.loads(value)
        assert parsed == {"level4": {"deep_key": "deep_value"}}


class TestReadYamlSafeLoadOnly:
    def test_uses_safe_load_not_load(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        yaml_content = b"key: value\n"
        mock_file_client.download_file.return_value = make_download_response(yaml_content)

        reader = _make_reader(mock_adls_client, spark)

        with patch.object(reader, "_resolve_file_paths", return_value=["test.yaml"]):
            with patch("yaml.safe_load", return_value={"key": "value"}) as mock_safe_load:
                with patch("yaml.load") as mock_load:
                    reader.read_yaml_files("container", "test.yaml")

                    mock_safe_load.assert_called_once()
                    mock_load.assert_not_called()


class TestReadYamlEmptyInput:
    def test_empty_yaml_file_raises(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        mock_file_client.download_file.return_value = make_download_response(b"")

        reader = _make_reader(mock_adls_client, spark)
        with patch.object(reader, "_resolve_file_paths", return_value=["empty.yaml"]):
            with pytest.raises(RuntimeError, match="Failed to read YAML file"):
                reader.read_yaml_files("container", "empty.yaml")

    def test_yaml_with_null_document_skips(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        mock_file_client.download_file.return_value = make_download_response(b"---\n")

        reader = _make_reader(mock_adls_client, spark)
        with patch.object(reader, "_resolve_file_paths", return_value=["null.yaml"]):
            with pytest.raises(RuntimeError, match="Failed to read YAML file"):
                reader.read_yaml_files("container", "null.yaml")


# ===========================================================================
# WRITE TESTS
# ===========================================================================

class TestWriteYamlHappyPath:
    def test_writes_yaml_content(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"name": ["Alice", "Bob"], "age": [30, 25]})
        schema = MockSchema([
            MockField("name", pyspark_types.StringType()),
            MockField("age", pyspark_types.IntegerType()),
        ])
        df = DataFrame(pdf, schema)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp_yaml")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                writer.write_yaml_files(df, "container", "output.yaml", mode="overwrite")

        mock_file_client.upload_data.assert_called()
        uploaded_bytes = mock_file_client.upload_data.call_args[0][0]

        import yaml
        parsed = yaml.safe_load(uploaded_bytes)
        assert len(parsed) == 2
        assert parsed[0]["name"] == "Alice"


class TestWriteYamlEmptyInput:
    def test_empty_dataframe_writes_empty_list(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"name": pd.Series(dtype=str)})
        schema = MockSchema([MockField("name", pyspark_types.StringType())])
        df = DataFrame(pdf, schema)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                writer.write_yaml_files(df, "container", "empty.yaml", mode="overwrite")

        mock_file_client.upload_data.assert_called()
        uploaded = mock_file_client.upload_data.call_args[0][0]
        import yaml
        parsed = yaml.safe_load(uploaded)
        assert parsed == []
