# Changelog

All notable changes to the UC Passthrough Library are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.2.1] — Current

### Fixed
- Writer exception leakage: `direct_adls_writer.py` now applies the same exception sanitisation pattern as the reader. Raw Azure SDK exception messages (which may contain storage account URLs, container names, or request correlation IDs) are no longer surfaced in user-facing `RuntimeError` messages. Full detail available at DEBUG log level.

### Documentation
- SECURITY.md: Corrected v1.2.0 claim that exception sanitisation covered "reader/writer" — writer fix was missed in v1.2.0 and is now complete in v1.2.1.
- SECURITY.md: Added known limitation for structured audit trail / SIEM integration gap.

---

## [1.2.0]

### Fixed
- Azure SDK exception messages are no longer surfaced in raised exceptions. Only exception type and safe path prefix are included in user-facing errors. Full detail available at DEBUG log level.
- Write path now emits a clear warning log when `patch_dataframe_write()` has not been called and native Spark write is invoked, preventing silent credential failures.

### Added
- `validate_config()` method on `UCPassthroughDataFrameReader` for startup configuration validation. Catches misconfigured or misspelled environment variables at import time rather than at first ADLS operation.
- `PASSTHROUGH_VALIDATE_ON_INIT` environment variable for cluster-level enforcement of startup validation via init script.

### Security
- Updated SECURITY.md to accurately reflect exception sanitisation coverage and clarify known limitations around Python name-mangling and `__main__` trust in notebook contexts.

---

## [1.1.0]

### Fixed
- Avro read: Azure SDK `readall()` return type handling; explicit `seek(0)` before fastavro parsing.
- Avro write: `hasattr(.item)` replaced with `isinstance(np.generic)` for scalar detection; numpy arrays converted via `.tolist()`.
- ORC write: `pa.null()` columns sanitised to `pa.string()` before serialisation.
- Delta read: fallback log message changed from WARNING to INFO to clarify UC routing is intentional.

### Added
- XML write handler using Python's built-in `ElementTree` (no spark-xml JAR required).
- Chunked streaming for all reads and writes via Azure SDK `StorageStreamDownloader.chunks()`. Removes previous ~99MB read and ~2.25GB write ceilings.
- `adls_chunk_size_bytes` option for caller-controlled chunk size tuning.
- Format handlers for Image (write), YAML (read/write), XLSX (read/write), Audio (read/write with binary and metadata modes).
- Security hardening: `__slots__` on AuthenticationManager, path traversal validation, format allowlists, `repr`/`str` sanitisation, options scrubbing.
- `test_security.py` — independent security property test suite.
- `SECURITY.md` — threat model, controls, known limitations, dependency notes.
- `FORMAT_SCOPE.md` — format matrix, unsupported formats, ML workload guidance.

---

## [1.0.0]

### Added
- Initial release. Read support for Parquet, ORC, Avro, CSV, JSON, Text, Binary, Image via direct ADLS credential passthrough.
- PathAnalyzer routing: structured formats to Unity Catalog, unstructured to direct ADLS.
- AuthenticationManager with MSAL interactive device flow and client credentials flow.
- Token caching with configurable TTL.
- WriteTransactionContext for safe write operations.
- UCPassthroughDataFrameReader mirroring spark.read API.
- UCPassthroughDataFrameWriter / UCPassthroughFormatWriter mirroring df.write API.
