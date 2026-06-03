"""Tests for audio read (binary + metadata modes) and write handlers."""

import sys
import io
from unittest.mock import MagicMock, patch

import pytest
import pandas as pd

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
    return writer


def _import_blocker(blocked_module):
    _real_import = __import__

    def _blocker(name, *args, **kwargs):
        if name == blocked_module or name.startswith(blocked_module + "."):
            raise ImportError(f"Mocked: {blocked_module} not installed")
        return _real_import(name, *args, **kwargs)

    return _blocker


# ===========================================================================
# READ — BINARY MODE
# ===========================================================================

class TestReadAudioBinaryHappyPath:
    def test_reads_wav_as_binary(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        wav_bytes = b"RIFF" + b"\x00" * 100
        mock_file_client.download_file.return_value = make_download_response(wav_bytes)

        reader = _make_reader(mock_adls_client, spark)
        with patch.object(reader, "_resolve_file_paths", return_value=["audio/song.wav"]):
            result = reader.read_audio_files("container", "audio/song.wav")

        pdf = result.toPandas()
        assert "path" in pdf.columns
        assert "content" in pdf.columns
        assert "filename" in pdf.columns
        assert pdf["filename"].iloc[0] == "song.wav"
        assert pdf["content"].iloc[0] == bytearray(wav_bytes)

    def test_supports_all_audio_extensions(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        audio_bytes = b"\x00" * 50
        mock_file_client.download_file.return_value = make_download_response(audio_bytes)

        reader = _make_reader(mock_adls_client, spark)
        extensions = ["wav", "mp3", "flac", "aac", "ogg", "m4a"]

        for ext in extensions:
            with patch.object(reader, "_resolve_file_paths", return_value=[f"audio/file.{ext}"]):
                result = reader.read_audio_files("container", f"audio/file.{ext}")
            pdf = result.toPandas()
            assert pdf["filename"].iloc[0] == f"file.{ext}"

    def test_skips_non_audio_extensions(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        mock_file_client.download_file.return_value = make_download_response(b"\x00")

        reader = _make_reader(mock_adls_client, spark)
        with patch.object(reader, "_resolve_file_paths", return_value=["docs/readme.txt"]):
            with pytest.raises(RuntimeError, match="No audio files could be read"):
                reader.read_audio_files("container", "docs/readme.txt")


class TestReadAudioBinaryEmptyInput:
    def test_no_files_raises(self, mock_adls_client, mock_file_system_client, spark):
        reader = _make_reader(mock_adls_client, spark)
        with patch.object(reader, "_resolve_file_paths", return_value=[]):
            with pytest.raises(RuntimeError, match="No audio files could be read"):
                reader.read_audio_files("container", "empty/")


# ===========================================================================
# READ — METADATA MODE
# ===========================================================================

class TestReadAudioMetadataHappyPath:
    def test_extracts_metadata_fields(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        audio_bytes = b"\x00" * 100
        mock_file_client.download_file.return_value = make_download_response(audio_bytes)

        mock_audio_info = MagicMock()
        mock_audio_info.info.length = 180.5
        mock_audio_info.info.sample_rate = 44100
        mock_audio_info.info.channels = 2
        mock_audio_info.info.bitrate = 320000

        mock_mutagen = MagicMock()
        mock_mutagen.File.return_value = mock_audio_info

        reader = _make_reader(mock_adls_client, spark)
        with patch.object(reader, "_resolve_file_paths", return_value=["music/track.mp3"]):
            with patch.dict(sys.modules, {"mutagen": mock_mutagen}):
                result = reader.read_audio_files("container", "music/track.mp3",
                                                  options={"audio_mode": "metadata"})

        pdf = result.toPandas()
        assert pdf["filename"].iloc[0] == "track.mp3"
        assert pdf["format"].iloc[0] == "MP3"
        assert pdf["duration_seconds"].iloc[0] == 180.5
        assert pdf["sample_rate"].iloc[0] == 44100
        assert pdf["channels"].iloc[0] == 2
        assert pdf["bitrate"].iloc[0] == 320000
        assert pdf["file_size_bytes"].iloc[0] == 1024


class TestReadAudioMetadataMissingDependency:
    def test_import_error_message(self, mock_adls_client, mock_file_system_client, spark):
        reader = _make_reader(mock_adls_client, spark)

        with patch("builtins.__import__", side_effect=_import_blocker("mutagen")):
            with pytest.raises(RuntimeError, match="mutagen is required for audio metadata mode"):
                reader.read_audio_files("container", "music/track.mp3",
                                        options={"audio_mode": "metadata"})

    def test_error_message_suggests_binary_fallback(self, mock_adls_client, mock_file_system_client, spark):
        reader = _make_reader(mock_adls_client, spark)

        with patch("builtins.__import__", side_effect=_import_blocker("mutagen")):
            with pytest.raises(RuntimeError, match="audio_mode='binary'"):
                reader.read_audio_files("container", "x.mp3",
                                        options={"audio_mode": "metadata"})


class TestReadAudioMetadataEmptyInput:
    def test_no_files_raises(self, mock_adls_client, mock_file_system_client, spark):
        mock_mutagen = MagicMock()
        reader = _make_reader(mock_adls_client, spark)

        with patch.object(reader, "_resolve_file_paths", return_value=[]):
            with patch.dict(sys.modules, {"mutagen": mock_mutagen}):
                with pytest.raises(RuntimeError, match="No audio metadata could be extracted"):
                    reader.read_audio_files("container", "empty/",
                                            options={"audio_mode": "metadata"})


# ===========================================================================
# WRITE TESTS
# ===========================================================================

class TestWriteAudioHappyPath:
    def test_writes_audio_binary_passthrough(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"path": ["/audio/output.wav"], "content": [b"RIFF" + b"\x00" * 100]})
        schema = MockSchema([
            MockField("path", pyspark_types.StringType()),
            MockField("content", pyspark_types.BinaryType()),
        ])
        df = DataFrame(pdf, schema)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp_audio")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                writer.write_audio_files(df, "container", "audio/out", mode="overwrite")

        mock_file_system_client.get_file_client.assert_called()
        mock_file_client.upload_data.assert_called()

    def test_validates_audio_extension(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"path": ["/audio/not_audio.exe"], "content": [b"\x00"]})
        schema = MockSchema([
            MockField("path", pyspark_types.StringType()),
            MockField("content", pyspark_types.BinaryType()),
        ])
        df = DataFrame(pdf, schema)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                with pytest.raises(ValueError, match="Unsupported audio extension"):
                    writer.write_audio_files(df, "container", "audio/", mode="overwrite")


class TestWriteAudioSchemaValidation:
    def test_missing_content_raises_valueerror(self, mock_adls_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"path": ["/audio/song.mp3"]})
        schema = MockSchema([MockField("path", pyspark_types.StringType())])
        df = DataFrame(pdf, schema)

        with pytest.raises(ValueError, match="content"):
            writer.write_audio_files(df, "container", "audio/", mode="overwrite")

    def test_wrong_content_type_raises_valueerror(self, mock_adls_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"path": ["/audio/song.mp3"], "content": ["not binary"]})
        schema = MockSchema([
            MockField("path", pyspark_types.StringType()),
            MockField("content", pyspark_types.StringType()),
        ])
        df = DataFrame(pdf, schema)

        with pytest.raises(ValueError, match="BinaryType"):
            writer.write_audio_files(df, "container", "audio/", mode="overwrite")

    def test_missing_path_raises_valueerror(self, mock_adls_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"content": [b"\x00"]})
        schema = MockSchema([MockField("content", pyspark_types.BinaryType())])
        df = DataFrame(pdf, schema)

        with pytest.raises(ValueError, match="path"):
            writer.write_audio_files(df, "container", "audio/", mode="overwrite")


class TestWriteAudioEmptyInput:
    def test_empty_dataframe_no_error(self, mock_adls_client, mock_file_system_client, mock_file_client, spark):
        writer = _make_writer(mock_adls_client, spark)
        pdf = pd.DataFrame({"path": pd.Series(dtype=str), "content": pd.Series(dtype=object)})
        schema = MockSchema([
            MockField("path", pyspark_types.StringType()),
            MockField("content", pyspark_types.BinaryType()),
        ])
        df = DataFrame(pdf, schema)

        with patch.object(WriteTransactionContext, "__enter__", return_value=MagicMock(committed=False, get_temp_path=lambda: "tmp")):
            with patch.object(WriteTransactionContext, "__exit__", return_value=False):
                writer.write_audio_files(df, "container", "audio/", mode="overwrite")

        mock_file_client.upload_data.assert_not_called()
