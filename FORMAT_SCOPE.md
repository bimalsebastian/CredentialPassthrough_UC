# UC Passthrough Library — Format Scope & Limitations

This document covers what the library supports for file format read and write operations, what it does not support, and guidance for workloads that fall outside its scope.

For security controls see [SECURITY.md](./SECURITY.md). For installation and usage see [README.md](./README.md).

---

## Supported formats

### Read and write

The following formats support both read and write operations via direct ADLS access with user credential passthrough:

| Format | Extensions | Notes |
|--------|-----------|-------|
| Parquet | .parquet | Null-type column sanitisation applied automatically |
| ORC | .orc | Null-type column sanitisation applied automatically |
| Avro | .avro | Full dtype-to-schema mapping including dates, timestamps, decimals |
| CSV | .csv | Standard Spark CSV options supported via .option() |
| JSON | .json | Single and multiline supported |
| JSONL | .jsonl | Handled as JSON alias — no additional methods |
| TSV | .tsv | Handled as CSV alias with tab delimiter |
| Text | .txt | UTF-8 default; encoding override via .option('encoding', ...) |
| XML | .xml | Python ElementTree — no spark-xml JAR dependency required |
| Binary | .bin and others | Returns path + content (BinaryType) columns |
| Image | .png .jpg .jpeg .tiff .bmp .gif | Read returns path + content columns. Write accepts same schema |
| YAML | .yaml .yml | Nested keys flattened to dot notation up to depth 3. Keys beyond depth 3 serialised as JSON string. Uses safe_load only |
| XLSX | .xlsx | Read: active sheet by default, override with .option('sheet_name', ...). Write: single sheet. Requires openpyxl — see dependency note below |
| Audio | .wav .mp3 .flac .aac .ogg .m4a | Two modes: binary (default, no extra deps) and metadata (requires mutagen). See audio mode note below |

### Read only (Unity Catalog routing — by design)

| Format | Behaviour |
|--------|-----------|
| Delta | Always routed to Unity Catalog. Read works via UC. Write to raw abfss:// paths is deliberately blocked — use saveAsTable() |
| Iceberg | Always routed to Unity Catalog via foreign table registration. External Iceberg tables on ADLS should be registered as UC foreign tables, not accessed as raw paths |

---

## Dependency notes for non-standard formats

**XLSX** requires openpyxl, which is not included in the Databricks Runtime by default:
```python
%pip install openpyxl
```
If openpyxl is not installed, any XLSX read or write call will raise a clear ImportError with installation instructions.

**Audio metadata mode** requires mutagen:
```python
%pip install mutagen
```
Audio binary mode (the default) requires no additional packages and works on any cluster. Only switch to metadata mode if your workload needs to query duration, sample rate, channels, or bitrate as DataFrame columns.

---

## Unsupported formats

The library does not support formats beyond those listed above. The following categories were assessed during scoping and are explicitly out of scope for this version:

### Formats requiring unvalidated dependencies

The following formats are technically feasible but require third-party libraries that have not been validated in the customer cluster environment. Installing unvalidated libraries on production clusters carries dependency, compatibility, and security risk that is outside the scope of this library. Domain teams working with these formats should implement their own handlers using native Spark capabilities:

| Format category | Examples | Typical library required |
|----------------|----------|--------------------------|
| Scientific / statistical | HDF5, NetCDF, SAS (.sas7bdat), SPSS (.sav) | h5py, netCDF4, pyreadstat |
| Statistical (R) | RData, RDS | rpy2 (heavy dependency, not recommended on shared clusters) |
| Document extraction | PDF text, DOCX text, PPTX text | pdfplumber, python-docx, python-pptx |
| Video | MP4, MKV, AVI | cv2, ffprobe |
| Archive / compressed containers | ZIP, TAR, GZ (non-CSV/JSON) | Python stdlib zipfile/tarfile |

Note: PDF, DOCX, and video files can be read and written as raw binary today using format('binary') or format('binaryFile'). The limitation is structured extraction — the library does not parse document content or video metadata.

### Formats with open-ended complexity

The following formats involve sufficiently variable schema structures, encoding variants, or proprietary specifications that a general-purpose routing library cannot account for all scenarios. Domain teams are best placed to implement format-specific handling:

- Fixed-width text files (require user-supplied schema definition)
- Proprietary clinical instrument formats (HL7, FHIR bundles, DICOM — see ML section below)
- Multi-sheet XLSX with complex merged cell hierarchies beyond standard tabular structure
- Nested YAML beyond depth 3 with recursive or self-referencing structures

---

## File size behaviour

The library uses chunked streaming for all reads and writes via the Azure Data Lake Storage Gen2 SDK. There is no hard file size ceiling imposed by the library itself.

| Operation | Chunk default | Override option | Practical limit |
|-----------|--------------|-----------------|-----------------|
| Read | 4 MB | adls_chunk_size_bytes | Executor memory |
| Write | 4 MB | adls_chunk_size_bytes | ADLS account limit (~190 GB per file) |

For files larger than 500 MB, consider increasing the chunk size to reduce round trips:
```python
df = spark_passthrough.read.format('parquet') \
    .option('adls_chunk_size_bytes', 16 * 1024 * 1024) \
    .load('abfss://container@storage/large/file.parquet')
```

---

## ML workload guidance

The library is designed for governed file access and ETL movement. It is not optimised for ML training data loading at scale. Domain teams running ML workloads should be aware of the following constraints.

### What the library does for ML workloads

For image and audio formats, the library returns a DataFrame with path (StringType) and content (BinaryType) columns. This is sufficient for:
- Governed ingest of raw files into UC Volumes
- File existence checks and metadata queries
- Small-scale preprocessing pipelines on the driver

### What the library does not do

The library does not perform any ML-specific preprocessing. After reading bytes from ADLS, domain teams are responsible for:
- Tensor conversion (PyTorch torchvision.io, PIL/Pillow, OpenCV for images)
- Audio resampling, mono conversion, and normalisation (torchaudio, librosa)
- Feature extraction, augmentation, and batching

### Pharma-specific format limitations

Common pharma and life sciences ML formats are outside the library's scope:

| Format | Use case | Recommended approach |
|--------|----------|----------------------|
| DICOM (.dcm) | Radiology, pathology imaging | Use pydicom directly on executor via mapInPandas; store raw files in UC Volumes as binary |
| WSI (.svs, .ndpi, .czi) | Whole slide imaging | Files are multi-GB pyramidal — use openslide on dedicated GPU clusters; not suitable for driver-side reads |
| FCS | Flow cytometry | Use FlowCytometryTools or fcsparser; read as binary via this library then parse on executor |
| HL7 / FHIR | Clinical data exchange | Structured clinical data — should be registered as UC tables, not raw file access |

### Recommended pattern for ML at scale

For ML training datasets stored as binary files in ADLS, the recommended pattern is:

1. Use this library for **governed ingest** — move files from raw ADLS paths into UC Volumes with proper access control
2. Once in UC Volumes, use **native Spark binaryFile** format for distributed reads across the cluster
3. For training pipelines, use **Mosaic Streaming (MDS format)** for shuffled, batched, distributed data loading — this is Databricks-native and handles the ML data loading concerns that this library deliberately does not

```python
# Step 1 — governed ingest via passthrough library (driver-side, small batches)
df = spark_passthrough.read.format('image').load('abfss://raw@storage/images/')
df.write.format('delta').saveAsTable('catalog.schema.raw_images')

# Step 2 — distributed reads from UC Volume (executor-side, at scale)
df = spark.read.format('binaryFile').load('/Volumes/catalog/schema/images/')
```

This separation keeps the library in its lane as a governance bridge and delegates scale to the appropriate Databricks-native tooling.

---

## What to do if your format is not listed

1. Check whether raw binary access via format('binary') meets your need — if your workload only requires storing and retrieving files without querying their content, binary passthrough works today for any file type
2. If you need structured extraction, implement a format-specific handler in your own pipeline code using native Python libraries on the executor via mapInPandas
3. For formats that are widely used across multiple data domains and could justify a library extension, raise a request with the platform team — include the format name, typical file sizes, read/write requirement, and the Python library you would use

---


