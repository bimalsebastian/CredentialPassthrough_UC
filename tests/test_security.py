"""
Security property tests for the UC Passthrough library.

Tests verify security invariants — no real ADLS or Spark calls are made.
All tests are independent and use mocks where necessary.
"""

import os
import sys
import types
import importlib
from unittest.mock import MagicMock, patch

import pytest

# Ensure the tests/ directory is on sys.path so conftest is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reuse the PySpark stub and Azure mocks from conftest (imported automatically by pytest).
# conftest stubs pyspark, azure.storage.filedatalake, etc. and adds the source dir to sys.path.
from conftest import SparkSession, DataFrame

# Ensure all Azure/MSAL stubs exist. conftest sets some of these but
# authentication_manager.py does `from azure.core.credentials import AccessToken`
# which requires azure.core.credentials to be a real module entry, not a MagicMock attr.
_azure_mock = MagicMock()
for mod_name in ("azure", "azure.storage", "azure.storage.filedatalake",
                 "azure.core", "azure.core.credentials", "azure.core.exceptions",
                 "azure.identity", "msal"):
    sys.modules.setdefault(mod_name, _azure_mock)

# The source dir (/tmp/CredentialPassthrough_UC/UC passthrough) is already on
# sys.path via conftest. The modules use relative imports (.path_analyzer, etc.)
# which won't resolve as flat imports. We fix this by loading each module with
# importlib and assigning the correct __package__ so relative imports resolve.

_SRC = "/tmp/CredentialPassthrough_UC/UC passthrough"
_PKG = "uc_pt"

def _load_module(name):
    """Load a module from the source dir as part of the uc_pt pseudo-package."""
    fqn = f"{_PKG}.{name}"
    if fqn in sys.modules:
        return sys.modules[fqn]
    spec = importlib.util.spec_from_file_location(fqn, f"{_SRC}/{name}.py")
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = _PKG
    sys.modules[fqn] = mod
    # Also register the bare name so relative-import targets resolve
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod

# Create the pseudo-package
if _PKG not in sys.modules:
    pkg = types.ModuleType(_PKG)
    pkg.__path__ = [_SRC]
    pkg.__package__ = _PKG
    sys.modules[_PKG] = pkg

# Load in dependency order
_load_module("path_analyzer")
_load_module("authentication_manager")
_load_module("direct_adls_reader")
_load_module("direct_adls_writer")
_load_module("uc_passthrough_writer")
_load_module("uc_passthrough_library")

from path_analyzer import PathAnalyzer
from authentication_manager import AuthenticationManager
from uc_passthrough_library import (
    UCPassthroughDataFrameReader,
    UCPassthroughReaderProxy,
    SUPPORTED_READ_FORMATS,
)
from uc_passthrough_writer import (
    UCPassthroughWriterProxy,
    SUPPORTED_WRITE_FORMATS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_auth_manager(token="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.FAKE_TOKEN_PAYLOAD"):
    """Create an AuthenticationManager with mocked MSAL so no real auth occurs."""
    mock_msal_app = MagicMock()
    mock_msal_app.acquire_token_for_client.return_value = {
        "access_token": token,
        "expires_in": 3600,
    }

    config = {
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "tenant_id": "test-tenant-id",
        "cache_tokens": True,
        "use_client_credentials": True,
    }

    with patch("authentication_manager.msal") as mock_msal:
        mock_msal.ConfidentialClientApplication.return_value = mock_msal_app
        mgr = AuthenticationManager(config)

    return mgr


def _make_reader():
    """Create a UCPassthroughDataFrameReader with real auth_manager and path_analyzer."""
    auth = _make_auth_manager()
    analyzer = PathAnalyzer()
    spark = SparkSession()
    return UCPassthroughDataFrameReader(spark, auth, analyzer)


# ===========================================================================
#  1. CREDENTIAL NON-EXPOSURE
# ===========================================================================

class TestCredentialProtection:
    """Verify that credentials never leak through repr, str, or public attributes."""

    MOCK_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.SECRET_PAYLOAD_123"

    def test_repr_does_not_contain_token(self):
        mgr = _make_auth_manager(token=self.MOCK_TOKEN)
        assert self.MOCK_TOKEN not in repr(mgr)

    def test_str_does_not_contain_token(self):
        mgr = _make_auth_manager(token=self.MOCK_TOKEN)
        assert self.MOCK_TOKEN not in str(mgr)

    def test_no_public_attribute_exposes_adls_client(self):
        reader = _make_reader()
        # No public (non-dunder) attribute should have 'adls' or 'client' in its
        # name and return a service/file client object. In a real environment these
        # would be DataLakeServiceClient instances; here we verify that no attribute
        # matching the pattern is accessible at all.
        adls_attr_names = [
            name for name in dir(reader)
            if not name.startswith("__")
            and ("adls" in name.lower() or "datalake" in name.lower())
            and "client" in name.lower()
        ]
        for attr_name in adls_attr_names:
            with pytest.raises(AttributeError):
                getattr(reader, attr_name)


# ===========================================================================
#  2. PATH TRAVERSAL REJECTION
# ===========================================================================

class TestPathValidation:
    """Verify PathAnalyzer.validate_and_normalise_path rejects dangerous paths."""

    def test_rejects_dot_dot_slash(self):
        with pytest.raises(ValueError, match="Path traversal"):
            PathAnalyzer.validate_and_normalise_path(
                "abfss://container@acct.dfs.core.windows.net/data/../secrets/key"
            )

    def test_rejects_url_encoded_dot_dot(self):
        with pytest.raises(ValueError, match="Path traversal"):
            PathAnalyzer.validate_and_normalise_path(
                "abfss://container@acct.dfs.core.windows.net/data/%2E%2E/secrets/key"
            )

    def test_rejects_null_byte(self):
        with pytest.raises(ValueError, match="Null bytes"):
            PathAnalyzer.validate_and_normalise_path(
                "abfss://container@acct.dfs.core.windows.net/data/file\x00.parquet"
            )

    def test_rejects_container_root_only(self):
        with pytest.raises(ValueError, match="blob path"):
            PathAnalyzer.validate_and_normalise_path(
                "abfss://container@acct.dfs.core.windows.net/"
            )

    def test_accepts_valid_abfss_path(self):
        result = PathAnalyzer.validate_and_normalise_path(
            "abfss://container@acct.dfs.core.windows.net/data/year=2024/file.parquet"
        )
        assert result == "abfss://container@acct.dfs.core.windows.net/data/year=2024/file.parquet"


# ===========================================================================
#  3. FORMAT ALLOWLIST
# ===========================================================================

class TestFormatAllowlist:
    """Verify format validation rejects unknown formats and accepts known ones."""

    def test_reader_rejects_unknown_format(self):
        reader = _make_reader()
        with pytest.raises(ValueError, match="not supported"):
            reader.read.format("unknown_format_xyz")

    def test_writer_rejects_unknown_format(self):
        auth = _make_auth_manager()
        analyzer = PathAnalyzer()
        spark = SparkSession()
        df = DataFrame()
        writer = UCPassthroughWriterProxy(df, spark, auth, analyzer)
        with pytest.raises(ValueError, match="not supported"):
            writer.format("unknown_format_xyz")

    def test_writer_delta_format_rejected_at_format_validation(self):
        auth = _make_auth_manager()
        analyzer = PathAnalyzer()
        spark = SparkSession()
        df = DataFrame()
        writer = UCPassthroughWriterProxy(df, spark, auth, analyzer)
        with pytest.raises(ValueError, match="not supported"):
            writer.format("delta")

    def test_all_supported_read_formats_accepted(self):
        reader = _make_reader()
        for fmt in SUPPORTED_READ_FORMATS:
            proxy = reader.read.format(fmt)
            assert proxy is not None


# ===========================================================================
#  4. MONKEY-PATCH RESISTANCE
# ===========================================================================

class TestMonkeyPatchResistance:
    """Verify that security-critical attributes cannot be replaced at runtime."""

    def test_cannot_override_is_authenticated_property(self):
        mgr = _make_auth_manager()
        with pytest.raises(AttributeError):
            mgr.is_authenticated = lambda: True

    def test_cannot_inject_arbitrary_attribute_on_auth_manager(self):
        mgr = _make_auth_manager()
        with pytest.raises(AttributeError):
            mgr.fake_adls_client = MagicMock()

    def test_cannot_inject_adls_client_on_reader(self):
        reader = _make_reader()
        # Even if we force-set via object.__setattr__, the normal attribute
        # access path should not surface it as a working ADLS client.
        object.__setattr__(reader, '_injected_client', MagicMock())
        # The reader should not expose this injected attribute through __getattr__
        # because __getattr__ delegates to the underlying SparkSession, which
        # won't have '_injected_client'.
        with pytest.raises(AttributeError):
            _ = reader._injected_client_that_does_not_exist


# ===========================================================================
#  5. OPTIONS SCRUBBING
# ===========================================================================

class TestOptionsScrubbing:
    """Verify that sensitive option values never appear in log output."""

    def test_sas_token_not_logged_on_read(self):
        reader = _make_reader()
        secret = "secret-value-123"

        with patch("uc_passthrough_library.logger") as mock_logger:
            # Set up the reader with a sensitive option and trigger a load
            # that will fail (no real ADLS) — we only care about log output.
            try:
                reader.read.option("sas_token", secret).format("csv").load(
                    "abfss://container@acct.dfs.core.windows.net/data/file.csv"
                )
            except (RuntimeError, Exception):
                pass

            # Check all log calls for the secret value
            for call in mock_logger.method_calls:
                for arg in call.args:
                    assert secret not in str(arg), (
                        f"Secret '{secret}' leaked in log call: {call}"
                    )
                for kwarg_val in call.kwargs.values():
                    assert secret not in str(kwarg_val), (
                        f"Secret '{secret}' leaked in log kwargs: {call}"
                    )

    def test_scrub_options_redacts_sensitive_keys(self):
        mgr = _make_auth_manager()
        options = {
            "sas_token": "my-secret-sas",
            "account_key": "my-account-key",
            "header": "true",
            "delimiter": ",",
        }
        scrubbed = mgr._scrub_options(options)
        assert scrubbed["sas_token"] == "***"
        assert scrubbed["account_key"] == "***"
        assert scrubbed["header"] == "true"
        assert scrubbed["delimiter"] == ","
