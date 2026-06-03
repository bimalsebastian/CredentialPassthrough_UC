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
| Exception message sanitisation | All `raise RuntimeError(...)` paths in auth and reader/writer | Error messages contain only safe path prefixes and generic failure descriptions — never tokens, full paths, or config values |

## Known limitations

- **Cluster admin bypass.** A user with cluster admin rights (or access to the cluster's environment variables / init scripts) can read `PASSTHROUGH_CLIENT_SECRET` and acquire tokens directly using MSAL, completely outside this library.
- **Decompilation.** Name mangling is obfuscation, not encryption. A user who decompiles the library `.whl` (or reads the source on a shared volume) can find `_AuthenticationManager__client_secret` and access it via the mangled name.
- **Out-of-library client instantiation.** Nothing prevents a user from calling `DataLakeServiceClient(account_url, credential=...)` themselves if they already hold a valid credential or manage to extract one.
- **No runtime integrity verification.** The library does not verify its own bytecode or module hash at load time. A sophisticated attacker could patch `sys.modules` entries before the library is imported.
- **UC governance is authoritative.** This library routes traffic to UC — it does not replicate UC's permission model. If UC permissions are misconfigured, the library will faithfully send the request through and UC will grant it.
- **Token lifetime.** Tokens cached by `TokenCache` remain valid for their Azure AD lifetime (typically 60–90 minutes). The library refreshes within 5 minutes of expiry but cannot revoke tokens mid-session if user permissions change server-side.

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

**Recommendation:** Generate a `requirements.txt` with hash-pinned versions (`--require-hashes`) and verify against a known-good lockfile in CI. Consider vendoring `fastavro`, `openpyxl`, `mutagen`, and `chardet` if the deployment environment supports it, as these are the least-governed packages in the dependency tree.
