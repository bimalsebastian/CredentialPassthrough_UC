# Unity Catalog Passthrough Library

A secure credential passthrough solution for Databricks Unity Catalog clusters that enables direct access to unstructured data while maintaining proper governance for structured data.

## Overview

This library solves the challenge of accessing unstructured files (CSV, JSON, images, text files) from Unity Catalog clusters by intelligently routing data access:

- **Structured data** (Delta, Parquet) → Unity Catalog governance
- **Unstructured data** (CSV, JSON, text, binary) → Direct ADLS access with user credentials

## Key Features

- **Intelligent Path Routing**: Automatically determines whether to use UC governance or direct ADLS access
- **Secure Authentication**: Maintains user identity and audit trails
- **Token Caching**: Optimized performance with secure token management  
- **Thread-Safe Operations**: Production-ready with proper concurrency handling
- **Flexible Configuration**: Environment variables and runtime configuration support

## Installation

```python
# Install required dependencies
pip install msal azure-storage-file-datalake azure-identity pandas chardet
```

## Quick Start

```python
from uc_passthrough_library import UCPassthroughDataFrameReader

# Initialize the passthrough reader
spark_passthrough = UCPassthroughDataFrameReader(spark)

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
PathAnalyzer (Route Decision)
     ↓
┌─────────────────────┬─────────────────────┐
│   Unity Catalog     │    Direct ADLS      │
│   (Structured)      │   (Unstructured)    │
│                     │                     │
│ - Delta tables      │ - CSV files         │
│ - Parquet files     │ - JSON files        │
│ - Volume paths      │ - Text files        │
│ - Table references  │ - Binary files      │
└─────────────────────┴─────────────────────┘
```

## Security Considerations

- **User Identity Preservation**: All operations maintain the original user's identity for audit trails
- **Token Protection**: Access tokens are stored in protected, private variables
- **Permission Validation**: User's ADLS RBAC permissions are validated at runtime  
- **Secure Configuration**: Sensitive configuration is isolated from user code manipulation

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

- Maximum 1000 files per read operation (configurable)
- Maximum 100MB per individual file (configurable)
- Requires Unity Catalog cluster with proper network connectivity
- Service Principal requires appropriate Azure AD and ADLS permissions

## Contributing

This library maintains strict security boundaries. All authentication and ADLS access methods are protected from external manipulation to ensure data governance and security compliance.
