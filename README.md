# Unity Catalog Credential Passthrough Library

A secure credential passthrough solution for Databricks Unity Catalog clusters that enables direct access to unstructured data while maintaining proper governance for structured data.

## Overview

This library solves the challenge of accessing file-based data from Unity Catalog clusters by intelligently routing data access:

- **Structured data** (Delta, Iceberg) → Unity Catalog governance — always, by design
- **Unstructured / file-based data** (Parquet, ORC, Avro, CSV, JSON, JSONL, TSV, Text, XML, Binary, Image, YAML, XLSX, Audio) → Direct ADLS access with user credentials, via chunked streaming

See [FORMAT_SCOPE.md](./FORMAT_SCOPE.md) for the full read/write matrix.

## Key Features

- **Intelligent Path Routing**: Automatically determines whether to use UC governance or direct ADLS access
- **Secure Authentication**: Maintains user identity and audit trails
- **Token Caching**: Optimized performance with secure token management
- **Chunked Streaming**: Large file support for reads and writes via configurable chunk size — removes the previous 100MB read and 2.25GB write ceilings
- **Format Handlers**: Native read and write support for 14 file formats without requiring Spark format drivers or JARs
- **Thread-Safe Operations**: Production-ready with proper concurrency handling
- **Flexible Configuration**: Environment variables and runtime configuration support

## Installation

```python
# Install required dependencies
pip install msal azure-storage-file-datalake azure-identity \
            pandas pyarrow fastavro chardet \
            openpyxl PyYAML
```

> **Optional dependency:** `mutagen` is required only if using audio_mode='metadata' for audio files. Install separately with `pip install mutagen` if needed. Raw audio file access (audio_mode='binary', the default) requires no additional packages.

## Quick Start

```python
from uc_passthrough_library import UCPassthroughDataFrameReader

# Initialize the passthrough reader
spark_passthrough = UCPassthroughDataFrameReader(spark)
spark_passthrough.validate_config()  # Catch misconfiguration early

# Read unstructured data (routes to direct ADLS access)
df_csv = spark_passthrough.read.format('csv').load('abfss://container@storage.dfs.core.windows.net/data/file.csv')

# Read structured data (routes to UC governance) 
df_delta = spark_passthrough.read.format('delta').load('abfss://container@storage.dfs.core.windows.net/delta/table')
```

## Configuration

### Environment Variables

Configure the library using environment variables in your Databricks init script or notebook:

```python
import os

# Required: Azure AD Service Principal credentials
os.environ['PASSTHROUGH_CLIENT_ID'] = 'your-service-principal-client-id'
os.environ['PASSTHROUGH_CLIENT_SECRET'] = 'your-service-principal-secret'  
os.environ['PASSTHROUGH_TENANT_ID'] = 'your-azure-tenant-id'

# Authentication method flags (use ONE, not both)
os.environ['PASSTHROUGH_USE_CLIENT_CREDENTIALS'] = 'True'    # For automated/job clusters
os.environ['PASSTHROUGH_USE_INTERACTIVE_FLOW'] = 'False'    # For interactive user sessions

# Optional: Performance and caching
os.environ['PASSTHROUGH_CACHE_TOKENS'] = 'True'
os.environ['PASSTHROUGH_STORAGE_URL'] = 'https://yourstorageaccount.dfs.core.windows.net'
```

### Security Recommendations

**IMPORTANT**: Environment variables can be modified at runtime by user code, potentially compromising security. For production deployments, consider these approaches:

#### Option 1: Hardcode Configuration (Recommended for Production)
```python
from uc_passthrough_library import UCPassthroughDataFrameReader

# Hardcode secure configuration to prevent runtime tampering
config = {
    'client_id': 'your-service-principal-client-id',
    'client_secret': 'your-service-principal-secret',
    'tenant_id': 'your-azure-tenant-id',
    'use_client_credentials': True,
    'cache_tokens': True
}

# Pass config directly to prevent environment variable manipulation
auth_manager = AuthenticationManager(config)
spark_passthrough = UCPassthroughDataFrameReader(spark, auth_manager)
```

#### Option 2: Environment Variable Protection
Use Databricks secrets or other secure configuration management:

```python
import os

# Use Databricks secrets (more secure than plain environment variables)
os.environ['PASSTHROUGH_CLIENT_ID'] = dbutils.secrets.get(scope="your-scope", key="client-id")
os.environ['PASSTHROUGH_CLIENT_SECRET'] = dbutils.secrets.get(scope="your-scope", key="client-secret")
os.environ['PASSTHROUGH_TENANT_ID'] = dbutils.secrets.get(scope="your-scope", key="tenant-id")

# Lock authentication method to prevent runtime changes
os.environ['PASSTHROUGH_USE_CLIENT_CREDENTIALS'] = 'True'
os.environ['PASSTHROUGH_USE_INTERACTIVE_FLOW'] = 'False'
```

#### Option 3: Init Script Configuration
Place configuration in cluster init scripts where user code cannot modify it:

```bash
#!/bin/bash
# In cluster init script
export PASSTHROUGH_CLIENT_ID="your-service-principal-client-id"
export PASSTHROUGH_CLIENT_SECRET="your-service-principal-secret" 
export PASSTHROUGH_TENANT_ID="your-azure-tenant-id"
export PASSTHROUGH_USE_CLIENT_CREDENTIALS="True"
export PASSTHROUGH_CACHE_TOKENS="True"
```

### Authentication Modes

**IMPORTANT**: Use only ONE authentication method at a time.

#### Interactive Device Flow (Interactive Clusters)
For development and interactive user sessions:

```python
os.environ['PASSTHROUGH_USE_INTERACTIVE_FLOW'] = 'True'
os.environ['PASSTHROUGH_USE_CLIENT_CREDENTIALS'] = 'False'
```

This will prompt users to authenticate via browser when first accessing data:
```
AZURE AD AUTHENTICATION REQUIRED
==================================================
1. Go to: https://microsoft.com/devicelogin
2. Enter code: ABC123XYZ
3. Complete authentication in the browser
==================================================
```

#### Client Credentials Flow (Automated/Job Clusters)
For automated jobs and production workloads:

```python
os.environ['PASSTHROUGH_USE_CLIENT_CREDENTIALS'] = 'True'
os.environ['PASSTHROUGH_USE_INTERACTIVE_FLOW'] = 'False'
```

Requires the Service Principal to have admin consent and appropriate ADLS permissions.

### Azure Service Principal Setup

The Service Principal used for authentication requires specific Azure permissions:

#### Required Azure AD API Permissions
1. **Azure Storage API**: `https://storage.azure.com/user_impersonation`
   - **Permission Type**: Delegated
   - **Admin Consent**: Required
   - **Purpose**: Allows the application to access Azure Storage on behalf of the signed-in user

To configure in Azure Portal:
```
1. Navigate to Azure AD > App registrations > [Your Service Principal]
2. Go to "API permissions" 
3. Click "Add a permission"
4. Select "Azure Storage"
5. Choose "Delegated permissions"
6. Select "user_impersonation"
7. Click "Add permissions"
8. Click "Grant admin consent for [Your Organization]" (requires Global Admin)
```
2. **Allow public client flows**: 

To configure in Azure Portal:
```
1. Navigate to Azure AD > App registrations > [Your Service Principal]
2. Go to "Authentication" 
3. Go to tab "Settings"
4. Toggle "Allow public client flows" to enabled
```
<img width="871" height="239" alt="image" src="https://github.com/user-attachments/assets/190ff201-483a-4e2c-9d0e-ccd68e5ee66f" />
#### Required ADLS Permissions
The Service Principal also needs appropriate RBAC roles on the ADLS storage account:
- **Storage Blob Data Contributor** (or higher) on the storage account
- Permissions should be granted at the appropriate scope (subscription, resource group, or storage account level)

## Path Routing Configuration

### Force Patterns

Override automatic routing with custom regex patterns:

```python
# Force specific paths to use Unity Catalog
os.environ['PASSTHROUGH_FORCE_UC_PATTERNS'] = '/governed/,/sensitive/,/audit/'

# Force specific paths to use direct ADLS access  
os.environ['PASSTHROUGH_FORCE_ADLS_PATTERNS'] = '/raw/,/landing/,/unstructured/'
```

### Custom Format Mappings

Define custom format classifications:

```python
# Treat these formats as structured (route to UC)
os.environ['PASSTHROUGH_CUSTOM_UC_FORMATS'] = 'iceberg,delta,parquet'

# Treat these formats as unstructured (route to ADLS)
os.environ['PASSTHROUGH_CUSTOM_ADLS_FORMATS'] = 'log,raw,pdf,image'
```

## Usage Examples

### Unity Catalog vs ADLS Routing

The library automatically routes based on path and format analysis:

#### Unity Catalog Routing Examples

```python
# Volume paths (always UC)
df = spark_passthrough.read.format('parquet').load('/Volumes/catalog/schema/volume/data/')

# Catalog table references (always UC)
df = spark_passthrough.read.format('delta').load('catalog.schema.table_name')

# Structured formats (default UC)
df = spark_passthrough.read.format('delta').load('abfss://container@storage/data/delta_table/')
df = spark_passthrough.read.format('parquet').load('abfss://container@storage/data/parquet_files/')

# Force UC with patterns
df = spark_passthrough.read.format('csv').load('abfss://container@storage/governed/sensitive.csv')
```

#### Direct ADLS Routing Examples

```python
# Unstructured formats (default ADLS)
df = spark_passthrough.read.format('csv').load('abfss://container@storage/raw/data.csv')
df = spark_passthrough.read.format('json').load('abfss://container@storage/logs/events.json')
df = spark_passthrough.read.format('text').load('abfss://container@storage/documents/readme.txt')
df = spark_passthrough.read.format('binaryFile').load('abfss://container@storage/images/photo.jpg')

# Force ADLS with patterns
df = spark_passthrough.read.format('parquet').load('abfss://container@storage/raw/landing_data/')
```

### Path Pattern Examples

Configure path-based routing with regex patterns:

```python
# Example force patterns configuration
os.environ['PASSTHROUGH_FORCE_UC_PATTERNS'] = '/governed/,/warehouse/,.*_managed/.*'
os.environ['PASSTHROUGH_FORCE_ADLS_PATTERNS'] = '/raw/,/landing/,/temp/,.*_unmanaged/.*'

# These paths will always route to UC regardless of format:
# - abfss://storage/governed/any_file.csv → UC
# - abfss://storage/warehouse/data.json → UC  
# - abfss://storage/project_managed/file.txt → UC

# These paths will always route to ADLS regardless of format:
# - abfss://storage/raw/structured.parquet → ADLS
# - abfss://storage/landing/delta_table/ → ADLS
# - abfss://storage/temp/data.delta → ADLS
# - abfss://storage/project_unmanaged/file.parquet → ADLS
```

### Reading Options

Support standard Spark reading options:

```python
# CSV with options
df = spark_passthrough.read.format('csv').options(
    header=True,
    inferSchema=True,
    sep=','
).load('abfss://container@storage/data/file.csv')

# JSON with multiline option  
df = spark_passthrough.read.format('json').option(
    'multiLine', True
).load('abfss://container@storage/data/config.json')
```

## Architecture

```
User Request
     ↓
UCPassthroughDataFrameReader
     ↓
PathAnalyzer + Format Allowlist Validation
     ↓
┌─────────────────────────┬──────────────────────────────────────┐
│    Unity Catalog        │         Direct ADLS                  │
│    (always routed)      │   (chunked streaming, user creds)    │
│                         │                                      │
│  Delta, Iceberg         │  Parquet, ORC, Avro                  │
│  Volume paths           │  CSV, JSON, JSONL, TSV               │
│  Table references       │  Text, XML, Binary, Image            │
│                         │  YAML, XLSX, Audio                   │
└─────────────────────────┴──────────────────────────────────────┘
```

## Format-specific options

```python
# XLSX — read a specific sheet (default: active sheet)
df = spark_passthrough.read.format('xlsx') \
    .option('sheet_name', 'Q3 Results') \
    .load('abfss://container@storage/reports/quarterly.xlsx')

# Audio — raw binary access (default, no extra dependencies)
df = spark_passthrough.read.format('audio') \
    .load('abfss://container@storage/recordings/call.wav')

# Audio — metadata DataFrame (requires mutagen)
df = spark_passthrough.read.format('audio') \
    .option('audio_mode', 'metadata') \
    .load('abfss://container@storage/recordings/call.wav')

# Chunked streaming — override default 4MB chunk size for large files
df = spark_passthrough.read.format('parquet') \
    .option('adls_chunk_size_bytes', 16 * 1024 * 1024) \
    .load('abfss://container@storage/large/file.parquet')
```

## Security Considerations

Security controls, threat model, known limitations, and dependency pinning guidance are documented in [SECURITY.md](./SECURITY.md).

In brief: credentials are name-mangled and never appear in logs or repr output. Paths are validated against traversal attacks before any ADLS operation. Format strings are validated against an allowlist. The library is a routing enforcer — Unity Catalog cluster governance (workspace permissions, IP ACLs, cluster policies) is the authoritative security boundary.

## Troubleshooting

### Common Issues

**Authentication Failed**: 
- Verify Service Principal credentials are correct
- Ensure proper Azure AD permissions and admin consent
- Check that only one authentication method is enabled

**Access Denied**:
- Verify user has appropriate ADLS RBAC permissions
- Check storage account firewall settings
- Ensure Service Principal has necessary permissions for token acquisition

**Path Not Found**:
- Verify ADLS path format and container exists
- Check path pattern configurations
- Ensure file permissions allow listing

### Debug Mode

Enable detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Check authentication status
auth_manager = AuthenticationManager()
print(auth_manager.get_current_user())
print(auth_manager.get_configuration_info())

# Test ADLS access
result = auth_manager.test_adls_access(
    storage_account_url='https://storage.dfs.core.windows.net',
    container='container-name'
)
print(result)
```

## Limitations

For full detail on format coverage, unsupported formats, file size behaviour, and ML workload constraints, see [FORMAT_SCOPE.md](./FORMAT_SCOPE.md).

**File size**
Reads and writes use chunked streaming via the Azure SDK. There is no hard ceiling imposed by the library. Practical limits are determined by executor memory and ADLS account configuration.

**Format scope**
14 formats are supported natively. Formats outside this set are not handled by the library — see FORMAT_SCOPE.md for the complete list and guidance for domain teams working with unsupported formats.

**Delta and Iceberg**
Delta and Iceberg are always routed through Unity Catalog. Raw abfss:// Delta writes are deliberately blocked — use saveAsTable() instead. This is by design, not a limitation.

**UC governance is authoritative**
This library is a routing enforcer. If UC permissions are misconfigured, the library will faithfully route the request and UC will grant or deny it. The library does not replicate or shadow UC's permission model.

## Contributing

This library maintains strict security boundaries. All authentication and ADLS access methods are protected from external manipulation to ensure data governance and security compliance.
