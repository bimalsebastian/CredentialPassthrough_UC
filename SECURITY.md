# UC Passthrough Library — Security Posture

## Threat model

The attacker is an authenticated Databricks user running code on a Unity Catalog passthrough cluster. They have a valid notebook session, full Python execution, and access to the library's public API. Their goals may include: bypassing the credential routing logic to access ADLS paths outside their UC-granted permissions, exfiltrating ADLS access tokens from the library's internal state, manipulating path resolution to reach storage containers they should not touch, or injecting mock objects to replace the authentication layer.

The library's defence boundary is narrow and explicit: it is a **routing enforcer**, not a security boundary. It ensures that reads and writes are correctly dispatched — structured data through Unity Catalog governance, unstructured data through direct ADLS with the user's scoped credential. UC cluster-level governance (workspace permissions, IP ACLs, cluster policies, Azure AD conditional access) remains the authoritative control layer.

## Controls implemented

| Control | Where implemented | What it prevents |
|---------|-------------------|------------------|
| Credential name mangling | `authentication_manager.py` — all sensitive attributes use `__` prefix (e.g. `__client_secret`, `__msal_app`, `__token_cache`) | Casual attribute access from notebook code; `obj.client_secret` raises `AttributeError` |
| `__slots__` freeze | `AuthenticationManager.__slots__` (13 mangled slots) | Dynamic attribute injection — `mgr.fake_client = ...` raises `AttributeError` |
| `isinstance` guard | `UCPassthroughDataFrameReader.__init__` | Blocks dependency injection of a fake `AuthenticationManager` or `PathAnalyzer` subclass/duck-type |
| `is_authenticated` as read-only property | `AuthenticationManager.is_authenticated` (`@property`, no setter) | Prevents `mgr.is_authenticated = lambda: True` monkey-patch |
| Private ADLS client accessor | `AuthenticationManager._get_adls_client` (single-underscore, not in public API) | Discourages direct use; no public `get_adls_client()` method exposed |
| `repr`/`str` sanitisation | `AuthenticationManager.__repr__`, `CustomCredential.__repr__`, `TokenCache.__repr__` | Token values, secrets, and user details never appear in notebook output, tracebacks, or logging of objects |
| Options scrubbing | `AuthenticationManager._scrub_options`, `UCPassthroughFormatReader._scrub_options` | Redacts `sas_token`, `account_key`, `credential`, `token`, `client_secret`, `client_id`, `tenant_id` from any log line that includes user-supplied options |
| Path safe-logging | `AuthenticationManager._safe_path`, `UCPassthroughFormatReader._safe_path` | Only logs container + first path segment — full blob paths (which may contain PII or business-sensitive names) are truncated |
| Path traversal validation | `PathAnalyzer.validate_and_normalise_path` | Rejects `..`, URL-encoded `%2E%2E`, null bytes (`\x00`), and container-root-only paths before any ADLS operation |
| Blob-level path validation | `DirectADLSReader._validate_blob_path`, `DirectADLSWriter._validate_blob_path` | Same traversal checks applied at the blob-path component level inside every public read/write method (12 read entry points, 12 write entry points) |
| Format allowlist (read) | `SUPPORTED_READ_FORMATS` frozenset in `uc_passthrough_library.py` | Unknown or dangerous format strings rejected before reaching Spark or ADLS dispatch |
| Format allowlist (write) | `SUPPORTED_WRITE_FORMATS` frozenset in `uc_passthrough_writer.py` | Same for write path; `delta` is excluded from direct ADLS writes (must go through UC governance via `saveAsTable`) |
| Chunked stream non-logging | `DirectADLSReader` / `DirectADLSWriter` streaming paths | File content bytes are never passed to `logger.*` calls; only byte counts and path metadata are logged |
| ADLS method caller-frame check | `_protect_adls_method` decorator in `direct_adls_writer.py` | Blocks external callers from invoking protected writer methods directly — only trusted package modules pass the frame-inspection check |
| Exception message sanitisation | All `raise RuntimeError(...)` paths in auth and reader/writer | Error messages in both reader and writer contain only exception type and safe path prefix. Full Azure SDK exception detail captured at DEBUG log level only. Fully implemented in v1.2.1 — reader fixed in v1.2.0, writer fixed in v1.2.1. |

## Known limitations

- **Cluster admin bypass.** A user with cluster admin rights (or access to the cluster's environment variables / init scripts) can read `PASSTHROUGH_CLIENT_SECRET` and acquire tokens directly using MSAL, completely outside this library.
- **Name-mangling is not a secret.** Python's name-mangling convention (`_ClassName__attr`) is documented in the language specification and taught in introductory courses. A user does not need to decompile anything — `mgr._AuthenticationManager__token_cache` is directly accessible to anyone who knows the class name. Name mangling prevents accidental access, not deliberate access.
- **`_protect_adls_method` is a no-op in notebook contexts.** The frame-inspection decorator trusts `__main__` as a calling module. In Databricks, every notebook runs as `__main__`. This means the decorator does not prevent notebook users from calling protected writer methods directly. It provides protection only against calls from unrelated Python modules. This is documented here for transparency — do not rely on this control as a security boundary.
- **Out-of-library client instantiation.** Nothing prevents a user from calling `DataLakeServiceClient(account_url, credential=...)` themselves if they already hold a valid credential or manage to extract one.
- **No runtime integrity verification.** The library does not verify its own bytecode or module hash at load time. A sophisticated attacker could patch `sys.modules` entries before the library is imported.
- **UC governance is authoritative.** This library routes traffic to UC — it does not replicate UC's permission model. If UC permissions are misconfigured, the library will faithfully send the request through and UC will grant it.
- **Token lifetime.** Tokens cached by `TokenCache` remain valid for their Azure AD lifetime (typically 60–90 minutes). The library refreshes within 5 minutes of expiry but cannot revoke tokens mid-session if user permissions change server-side.
- **No structured audit trail for SIEM integration.** The library logs routing decisions and authentication events via Python's standard logging module. There is no structured audit output (JSON lines with timestamp, user identity, operation type, path prefix, and access method) that a security team could ingest into Splunk, Microsoft Sentinel, or Azure Monitor. For regulated environments requiring operation-level audit trails, this is a gap. Structured audit logging is planned as a v1.3 feature — in the interim, cluster-level ADLS diagnostic logging in Azure Monitor provides the authoritative audit record.

## Test coverage

| Test class | What it covers |
|------------|----------------|
| `TestCredentialProtection` | Token strings absent from `repr()`/`str()`; no public attribute on the reader exposes ADLS client objects |
| `TestPathValidation` | `../` rejected; URL-encoded `%2E%2E` rejected; null bytes rejected; container-root-only rejected; valid paths accepted |
| `TestFormatAllowlist` | Unknown formats raise `ValueError` (reader and writer); `delta` blocked for write; all supported formats pass validation |
| `TestMonkeyPatchResistance` | `is_authenticated` property cannot be overwritten; arbitrary attributes cannot be injected on `AuthenticationManager` (via `__slots__`); injected attributes on reader not accessible |
| `TestOptionsScrubbing` | `sas_token` value never appears in log calls during a read operation; `_scrub_options` correctly redacts all sensitive keys |

## Dependency notes

The library uses the following third-party packages beyond the Databricks Runtime standard set. Each should be pinned to a specific version in `requirements.txt` to prevent supply-chain substitution attacks via dependency confusion or typosquatting:

| Package | Used for | Risk note |
|---------|----------|-----------|
| `msal` | Azure AD token acquisition (MSAL confidential/public client) | Microsoft-maintained; pin to major version |
| `azure-storage-file-datalake` | ADLS Gen2 file operations | Microsoft-maintained; pin to major version |
| `azure-identity` | `DefaultAzureCredential` fallback | Microsoft-maintained; pin to major version |
| `pyarrow` | Parquet/ORC read and write without Spark token injection | Apache project; pin exact version |
| `fastavro` | Avro file read/write | Community-maintained; pin exact version, verify signatures |
| `openpyxl` | Excel (.xlsx) read/write | Community-maintained; pin exact version |
| `PyYAML` | YAML file read/write (uses `safe_load` only) | Well-established; pin exact version |
| `mutagen` | Audio metadata extraction (optional, audio_mode='metadata') | Community-maintained; pin exact version |
| `chardet` | Character encoding detection for text files | Community-maintained; pin exact version |
| `pandas` | DataFrame conversion between Spark and Python-native formats | NumFOCUS-governed; pin to major version |

**Status: not yet implemented.** Hash-pinned dependency installation has not been applied to this repository. The recommendation stands — generate a `requirements.txt` with `--require-hashes` and verify against a known-good lockfile in CI — but until this is implemented it should be treated as a documented gap, not an active control. The customer platform team should implement hash pinning as part of cluster onboarding before production deployment.

## Revision history

| Version | Change |
|---------|--------|
| v1.2.1 | Writer exception sanitisation completed (missed in v1.2.0). Audit trail gap added to known limitations. |
| v1.2.0 | Reader exception sanitisation only — writer fix missed, corrected in v1.2.1. Updated known limitations: name-mangling triviality, `__main__` frame-check no-op in notebooks, hash-pinning status changed from recommendation to documented gap. |
| v1.1.0 | Initial security hardening release — __slots__, path traversal validation, format allowlists, repr sanitisation, options scrubbing. |
| v1.0.0 | No formal security controls documented. |
