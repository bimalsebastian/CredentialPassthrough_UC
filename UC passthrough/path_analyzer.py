"""
UC Passthrough Library - Path Analyzer Module

This module provides deterministic path classification to determine whether data access
should route through Unity Catalog governance or direct ADLS access with user credentials.

Key principle: If a path references a UC object (schema, table, volume), use UC governance.
Otherwise, use direct ADLS access with user credentials.
"""

import re
import os
from typing import Optional, Dict, List, Tuple
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class PathAnalyzer:
    """
    Analyzes file paths to determine the appropriate access method using deterministic logic:
    - UC objects (schemas, tables, volumes) -> Unity Catalog governance
    - Direct paths not tied to UC objects -> Direct ADLS access with user credentials
    """
    
    # Unity Catalog object patterns
    UC_VOLUME_PATTERN = r'^/[Vv]olumes/[^/]+/[^/]+/[^/]+(/.*)?$'
    UC_CATALOG_TABLE_PATTERN = r'^[a-zA-Z][a-zA-Z0-9_]*\.[a-zA-Z][a-zA-Z0-9_]*\.[a-zA-Z][a-zA-Z0-9_]*$'
    UC_SYSTEM_SCHEMA_PATTERNS = [
        r'^system\.',
        r'^information_schema\.'
    ]
    
    # Structured data formats that typically use UC governance
    UC_MANAGED_FORMATS = {
        'delta', 'parquet', 'orc', 'avro', 'jdbc', 'table'
    }
    
    # Unstructured data formats that typically use direct ADLS access
    ADLS_DIRECT_FORMATS = {
        'text', 'binaryfile', 'image', 'json', 'csv', 'xml', 'binary'
    }
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize PathAnalyzer with optional custom configuration.
        
        Args:
            config: Optional configuration dictionary with custom patterns and overrides
        """
        self.config = config or {}
        
        # Override patterns for explicit organizational control
        self.force_uc_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.config.get('force_uc_patterns', [])
        ]
        self.force_adls_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.config.get('force_adls_patterns', [])
        ]
        
        # Custom format mappings
        self.custom_uc_formats = set(self.config.get('custom_uc_formats', []))
        self.custom_adls_formats = set(self.config.get('custom_adls_formats', []))
        
        # Compile UC patterns
        self.uc_volume_regex = re.compile(self.UC_VOLUME_PATTERN)
        self.uc_catalog_table_regex = re.compile(self.UC_CATALOG_TABLE_PATTERN)
        self.uc_system_schema_regexes = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.UC_SYSTEM_SCHEMA_PATTERNS
        ]
        
        logger.info("PathAnalyzer initialized with deterministic routing logic")
    
    def analyze_path(self, path: str, format_type: Optional[str] = None, 
                    explicit_override: Optional[str] = None) -> Tuple[str, Dict]:
        """
        Analyze a path to determine the appropriate access method using deterministic logic.
        
        Args:
            path: The file/directory path to analyze
            format_type: Optional Spark format type (e.g., 'delta', 'parquet', 'text')
            explicit_override: Optional explicit override ('uc' or 'adls')
            
        Returns:
            Tuple of (access_method, analysis_details) where:
            - access_method: 'uc' for Unity Catalog, 'adls' for direct ADLS access
            - analysis_details: Dictionary with analysis reasoning
            
        Raises:
            ValueError: If format_type is not recognized and no explicit override provided
        """
        analysis = {
            'path': path,
            'format_type': format_type,
            'explicit_override': explicit_override,
            'reasoning': [],
            'is_deterministic': True
        }
        
        # Handle explicit overrides first
        if explicit_override:
            if explicit_override.lower() in ('uc', 'unity_catalog'):
                analysis['reasoning'].append(f"Explicit override: {explicit_override}")
                return 'uc', analysis
            elif explicit_override.lower() in ('adls', 'direct'):
                analysis['reasoning'].append(f"Explicit override: {explicit_override}")
                return 'adls', analysis
            else:
                raise ValueError(f"Invalid explicit_override: {explicit_override}. Must be 'uc' or 'adls'")
        
        # Check force patterns first (highest priority after explicit overrides)
        for pattern in self.force_uc_patterns:
            if pattern.search(path):
                analysis['reasoning'].append(f"Matches force UC pattern: {pattern.pattern}")
                return 'uc', analysis
                
        for pattern in self.force_adls_patterns:
            if pattern.search(path):
                analysis['reasoning'].append(f"Matches force ADLS pattern: {pattern.pattern}")
                return 'adls', analysis
        
        # Check if it's a Unity Catalog object path
        uc_object_type = self._detect_uc_object(path)
        if uc_object_type:
            analysis['reasoning'].append(f"Unity Catalog {uc_object_type} detected")
            return 'uc', analysis
        
        # For direct paths (abfss://, /mnt/, etc.), use format-based routing
        if format_type:
            format_lower = format_type.lower()
            
            # Check custom format mappings first
            if format_lower in self.custom_uc_formats:
                analysis['reasoning'].append(f"Custom UC format: {format_type}")
                return 'uc', analysis
            elif format_lower in self.custom_adls_formats:
                analysis['reasoning'].append(f"Custom ADLS format: {format_type}")
                return 'adls', analysis
            
            # Check built-in format mappings
            if format_lower in self.UC_MANAGED_FORMATS:
                analysis['reasoning'].append(f"UC-managed format: {format_type}")
                return 'uc', analysis
            elif format_lower in self.ADLS_DIRECT_FORMATS:
                analysis['reasoning'].append(f"ADLS-direct format: {format_type}")
                return 'adls', analysis
            else:
                # Unknown format - require explicit configuration
                raise ValueError(
                    f"Unknown format '{format_type}' for path '{path}'. "
                    f"Please add to custom_uc_formats or custom_adls_formats in configuration, "
                    f"or use explicit_override parameter."
                )
        else:
            # No format specified for direct path
            raise ValueError(
                f"No format specified for direct path '{path}'. "
                f"Either specify format_type or use explicit_override parameter."
            )
    
    def is_unstructured_data(self, path: str, format_type: Optional[str] = None, 
                           explicit_override: Optional[str] = None) -> bool:
        """
        Deterministic check for unstructured data routing.
        
        Args:
            path: The file/directory path to check
            format_type: Optional Spark format type
            explicit_override: Optional explicit override
            
        Returns:
            True if data should be treated as unstructured (use ADLS direct access)
            
        Raises:
            ValueError: If path/format cannot be deterministically classified
        """
        access_method, _ = self.analyze_path(path, format_type, explicit_override)
        return access_method == 'adls'
    
    def is_structured_data(self, path: str, format_type: Optional[str] = None,
                          explicit_override: Optional[str] = None) -> bool:
        """
        Deterministic check for structured data routing.
        
        Args:
            path: The file/directory path to check
            format_type: Optional Spark format type
            explicit_override: Optional explicit override
            
        Returns:
            True if data should be treated as structured (use UC governance)
            
        Raises:
            ValueError: If path/format cannot be deterministically classified
        """
        access_method, _ = self.analyze_path(path, format_type, explicit_override)
        return access_method == 'uc'
    
    def _detect_uc_object(self, path: str) -> Optional[str]:
        """
        Detect if path references a Unity Catalog object.
        
        Args:
            path: Path to analyze
            
        Returns:
            Type of UC object detected ('volume', 'table', 'system_schema') or None
        """
        # Check for UC volume pattern: /Volumes/catalog/schema/volume/...
        if self.uc_volume_regex.match(path):
            return 'volume'
        
        # Check for three-part catalog table name: catalog.schema.table
        if self.uc_catalog_table_regex.match(path):
            return 'table'
        
        # Check for system schemas
        for regex in self.uc_system_schema_regexes:
            if regex.match(path):
                return 'system_schema'
        
        return None
    
    def get_supported_formats(self) -> Dict[str, List[str]]:
        """Return supported formats for each routing method."""
        return {
            'uc_formats': sorted(list(self.UC_MANAGED_FORMATS | self.custom_uc_formats)),
            'adls_formats': sorted(list(self.ADLS_DIRECT_FORMATS | self.custom_adls_formats))
        }
    
    def get_configuration_summary(self) -> Dict:
        """Return summary of current configuration for debugging."""
        return {
            'force_uc_patterns': [p.pattern for p in self.force_uc_patterns],
            'force_adls_patterns': [p.pattern for p in self.force_adls_patterns],
            'custom_uc_formats': sorted(list(self.custom_uc_formats)),
            'custom_adls_formats': sorted(list(self.custom_adls_formats)),
            'built_in_uc_formats': sorted(list(self.UC_MANAGED_FORMATS)),
            'built_in_adls_formats': sorted(list(self.ADLS_DIRECT_FORMATS))
        }
    
    def validate_configuration(self) -> List[str]:
        """Validate current configuration and return any warnings."""
        warnings = []
        
        # Check for overlapping custom formats
        overlap = self.custom_uc_formats & self.custom_adls_formats
        if overlap:
            warnings.append(f"Overlapping custom formats found: {overlap}")
        
        # Check for conflicts with built-in formats
        uc_conflicts = self.custom_adls_formats & self.UC_MANAGED_FORMATS
        if uc_conflicts:
            warnings.append(f"Custom ADLS formats conflict with built-in UC formats: {uc_conflicts}")
        
        adls_conflicts = self.custom_uc_formats & self.ADLS_DIRECT_FORMATS
        if adls_conflicts:
            warnings.append(f"Custom UC formats conflict with built-in ADLS formats: {adls_conflicts}")
        
        # Check regex pattern validity
        for pattern_list, name in [
            (self.force_uc_patterns, 'force_uc_patterns'),
            (self.force_adls_patterns, 'force_adls_patterns')
        ]:
            for pattern in pattern_list:
                try:
                    pattern.search("")  # Test the regex
                except Exception as e:
                    warnings.append(f"Invalid regex in {name}: {pattern.pattern} - {str(e)}")
        
        return warnings


# # Example usage and testing
# if __name__ == "__main__":
#     # Configure logging
#     logging.basicConfig(level=logging.INFO)
    
#     # Create analyzer with some custom configuration
#     config = {
#         'custom_uc_formats': ['iceberg'],
#         'custom_adls_formats': ['log', 'raw'],
#         'force_uc_patterns': [r'/managed/'],
#         'force_adls_patterns': [r'/external_only/']
#     }
#     analyzer = PathAnalyzer(config)
    
#     # Test cases - all should be deterministic
#     test_cases = [
#         # UC objects (always UC governance)
#         ("/Volumes/catalog/schema/volume/data.parquet", "parquet", "volume"),
#         ("catalog.schema.table", None, "table"),
#         ("system.information_schema.tables", None, "system_schema"),
        
#         # Direct paths with structured formats (UC governance)
#         ("abfss://container@storage.dfs.core.windows.net/data/sales.delta", "delta", "uc"),
#         ("abfss://container@storage.dfs.core.windows.net/warehouse/customers.parquet", "parquet", "uc"),
        
#         # Direct paths with unstructured formats (ADLS direct)
#         ("abfss://container@storage.dfs.core.windows.net/raw/logs/app.log", "text", "adls"),
#         ("abfss://container@storage.dfs.core.windows.net/documents/report.pdf", "binaryfile", "adls"),
        
#         # Force patterns
#         ("abfss://container@storage.dfs.core.windows.net/managed/data.txt", "text", "uc"),
#         ("abfss://container@storage.dfs.core.windows.net/external_only/data.delta", "delta", "adls"),
        
#         # Custom formats
#         ("abfss://container@storage.dfs.core.windows.net/lakehouse/table.iceberg", "iceberg", "uc"),
#         ("abfss://container@storage.dfs.core.windows.net/files/data.raw", "raw", "adls"),
#     ]
    
#     print("=== Deterministic Path Analysis Test Results ===")
#     for path, format_type, expected in test_cases:
#         try:
#             access_method, analysis = analyzer.analyze_path(path, format_type)
#             status = "✓" if access_method == expected else "✗"
#             print(f"{status} Path: {path}")
#             print(f"  Format: {format_type}")
#             print(f"  Expected: {expected}, Got: {access_method}")
#             print(f"  Reasoning: {'; '.join(analysis['reasoning'])}")
#             print()
#         except ValueError as e:
#             print(f"✗ Path: {path}")
#             print(f"  Format: {format_type}")
#             print(f"  Error: {str(e)}")
#             print()
    
#     # Test error cases
#     print("=== Error Cases (Should Raise ValueError) ===")
#     error_cases = [
#         ("abfss://container@storage.dfs.core.windows.net/data/file.unknown", "unknown"),
#         ("abfss://container@storage.dfs.core.windows.net/data/file.txt", None),
#     ]
    
#     for path, format_type in error_cases:
#         try:
#             access_method, analysis = analyzer.analyze_path(path, format_type)
#             print(f"✗ Should have raised error for: {path} with format {format_type}")
#         except ValueError as e:
#             print(f"✓ Correctly raised error: {str(e)}")
#         print()
    
#     # Show supported formats
#     print("=== Supported Formats ===")
#     formats = analyzer.get_supported_formats()
#     print(f"UC Formats: {formats['uc_formats']}")
#     print(f"ADLS Formats: {formats['adls_formats']}")
    
#     # Validate configuration
#     warnings = analyzer.validate_configuration()
#     if warnings:
#         print(f"\n=== Configuration Warnings ===")
#         for warning in warnings:
#             print(f"WARNING: {warning}")
#     else:
#         print(f"\n=== Configuration Valid ===")
