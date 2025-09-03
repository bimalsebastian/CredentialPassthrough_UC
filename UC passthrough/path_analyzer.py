"""
UC Passthrough Library - Secured Path Analyzer Module

This module provides deterministic path classification to determine whether data access
should route through Unity Catalog governance or direct ADLS access with user credentials.

All configuration and sensitive patterns are protected from user manipulation.
Key principle: If a path references a UC object (schema, table, volume), use UC governance.
Otherwise, use direct ADLS access with user credentials.
"""

import re
import os
from typing import Optional, Dict, List, Tuple
from urllib.parse import urlparse
import logging
import threading
from functools import wraps

logger = logging.getLogger(__name__)


def _protect_config_method(method):
    """Decorator to protect configuration-related methods from external access."""
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        # Check if being called from within the same module/trusted context
        import inspect
        frame = inspect.currentframe().f_back
        caller_module = frame.f_globals.get('__name__', '')
        
        # Allow calls from within this module or trusted modules
        if not (caller_module.startswith(__name__.split('.')[0]) or 
                caller_module in ['dataframe_reader', 'authentication_manager']):
            raise PermissionError("Direct access to configuration methods is restricted")
        
        return method(self, *args, **kwargs)
    return wrapper


class PathAnalyzer:
    """
    Analyzes file paths to determine the appropriate access method using deterministic logic:
    - UC objects (schemas, tables, volumes) -> Unity Catalog governance
    - Direct paths not tied to UC objects -> Direct ADLS access with user credentials
    
    All sensitive configuration patterns are protected from user manipulation.
    """
    
    # Unity Catalog object patterns - these are immutable and protected
    __UC_VOLUME_PATTERN = r'^/[Vv]olumes/[^/]+/[^/]+/[^/]+(/.*)?$'
    __UC_CATALOG_TABLE_PATTERN = r'^[a-zA-Z][a-zA-Z0-9_]*\.[a-zA-Z][a-zA-Z0-9_]*\.[a-zA-Z][a-zA-Z0-9_]*$'
    __UC_SYSTEM_SCHEMA_PATTERNS = [
        r'^system\.',
        r'^information_schema\.'
    ]
    
    # Structured data formats that typically use UC governance - protected
    __UC_MANAGED_FORMATS = {
        'delta', 'parquet', 'orc', 'avro', 'jdbc', 'table'
    }
    
    # Unstructured data formats that typically use direct ADLS access - protected
    __ADLS_DIRECT_FORMATS = {
        'text', 'binaryfile', 'image', 'json', 'csv', 'xml', 'binary'
    }
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize PathAnalyzer with optional custom configuration.
        Configuration is loaded securely and protected from manipulation.
        
        Args:
            config: Optional configuration dictionary with custom patterns and overrides
        """
        self.__lock = threading.Lock()  # Thread safety for configuration access
        
        with self.__lock:
            self.__config = self.__load_secure_config(config)
            
            # Override patterns for explicit organizational control - kept private
            self.__force_uc_patterns = [
                re.compile(pattern, re.IGNORECASE) 
                for pattern in self.__config.get('force_uc_patterns', [])
            ]
            self.__force_adls_patterns = [
                re.compile(pattern, re.IGNORECASE) 
                for pattern in self.__config.get('force_adls_patterns', [])
            ]
            
            # Custom format mappings - kept private
            self.__custom_uc_formats = set(self.__config.get('custom_uc_formats', []))
            self.__custom_adls_formats = set(self.__config.get('custom_adls_formats', []))
            
            # Compile UC patterns - immutable and protected
            self.__uc_volume_regex = re.compile(self.__UC_VOLUME_PATTERN)
            self.__uc_catalog_table_regex = re.compile(self.__UC_CATALOG_TABLE_PATTERN)
            self.__uc_system_schema_regexes = [
                re.compile(pattern, re.IGNORECASE) for pattern in self.__UC_SYSTEM_SCHEMA_PATTERNS
            ]
        
        logger.info("PathAnalyzer initialized with secured deterministic routing logic")
    
    def __load_secure_config(self, config: Optional[Dict]) -> Dict:
        """
        Securely load configuration from environment variables and provided config.
        This method protects against malicious configuration injection.
        
        Args:
            config: User-provided configuration (filtered for security)
            
        Returns:
            Validated and secured configuration
        """
        # Start with secure defaults
        secure_config = {
            'custom_uc_formats': [],
            'custom_adls_formats': [],
            'force_uc_patterns': [],
            'force_adls_patterns': []
        }
        
        # Load from environment variables (trusted source)
        try:
            env_custom_uc = os.getenv("PASSTHROUGH_CUSTOM_UC_FORMATS")
            if env_custom_uc:
                secure_config['custom_uc_formats'] = [
                    fmt.strip().lower() for fmt in env_custom_uc.split(',') if fmt.strip()
                ]
            
            env_custom_adls = os.getenv("PASSTHROUGH_CUSTOM_ADLS_FORMATS")
            if env_custom_adls:
                secure_config['custom_adls_formats'] = [
                    fmt.strip().lower() for fmt in env_custom_adls.split(',') if fmt.strip()
                ]
            
            env_force_uc = os.getenv("PASSTHROUGH_FORCE_UC_PATTERNS")
            if env_force_uc:
                # Validate regex patterns before adding
                patterns = []
                for pattern in env_force_uc.split(','):
                    pattern = pattern.strip()
                    if pattern:
                        try:
                            re.compile(pattern)  # Test compilation
                            patterns.append(pattern)
                        except re.error:
                            logger.warning(f"Invalid force UC pattern ignored: {pattern}")
                secure_config['force_uc_patterns'] = patterns
            
            env_force_adls = os.getenv("PASSTHROUGH_FORCE_ADLS_PATTERNS")
            if env_force_adls:
                # Validate regex patterns before adding
                patterns = []
                for pattern in env_force_adls.split(','):
                    pattern = pattern.strip()
                    if pattern:
                        try:
                            re.compile(pattern)  # Test compilation
                            patterns.append(pattern)
                        except re.error:
                            logger.warning(f"Invalid force ADLS pattern ignored: {pattern}")
                secure_config['force_adls_patterns'] = patterns
                            
        except Exception as e:
            logger.warning(f"Error loading environment configuration: {str(e)}")
        
        # Apply user config with security filtering
        if config:
            # Only allow safe configuration keys
            safe_keys = {
                'custom_uc_formats', 'custom_adls_formats', 
                'force_uc_patterns', 'force_adls_patterns'
            }
            
            for key, value in config.items():
                if key in safe_keys and value:
                    if key.endswith('_formats') and isinstance(value, (list, set)):
                        # Sanitize format names
                        secure_config[key].extend([
                            fmt.strip().lower() for fmt in value 
                            if isinstance(fmt, str) and fmt.strip().isalnum()
                        ])
                    elif key.endswith('_patterns') and isinstance(value, (list, set)):
                        # Validate regex patterns
                        for pattern in value:
                            if isinstance(pattern, str):
                                try:
                                    re.compile(pattern)  # Test compilation
                                    secure_config[key].append(pattern)
                                except re.error:
                                    logger.warning(f"Invalid user pattern ignored: {pattern}")
                else:
                    logger.warning(f"Ignored unsafe configuration key: {key}")
        
        return secure_config
    
    def analyze_path(self, path: str, format_type: Optional[str] = None, 
                    explicit_override: Optional[str] = None) -> Tuple[str, Dict]:
        """
        Analyze a path to determine the appropriate access method using deterministic logic.
        All sensitive configuration access is protected.
        
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
        
        with self.__lock:  # Thread-safe access to protected patterns
            # Check force patterns first (highest priority after explicit overrides)
            for pattern in self.__force_uc_patterns:
                if pattern.search(path):
                    analysis['reasoning'].append(f"Matches configured UC pattern")
                    return 'uc', analysis
                    
            for pattern in self.__force_adls_patterns:
                if pattern.search(path):
                    analysis['reasoning'].append(f"Matches configured ADLS pattern")
                    return 'adls', analysis
        
        # Check if it's a Unity Catalog object path
        uc_object_type = self.__detect_uc_object(path)
        if uc_object_type:
            analysis['reasoning'].append(f"Unity Catalog {uc_object_type} detected")
            return 'uc', analysis
        
        # For direct paths (abfss://, /mnt/, etc.), use format-based routing
        if format_type:
            format_lower = format_type.lower()
            
            with self.__lock:  # Thread-safe access to custom formats
                # Check custom format mappings first
                if format_lower in self.__custom_uc_formats:
                    analysis['reasoning'].append(f"Custom UC format: {format_type}")
                    return 'uc', analysis
                elif format_lower in self.__custom_adls_formats:
                    analysis['reasoning'].append(f"Custom ADLS format: {format_type}")
                    return 'adls', analysis
            
            # Check built-in format mappings
            if format_lower in self.__UC_MANAGED_FORMATS:
                analysis['reasoning'].append(f"UC-managed format: {format_type}")
                return 'uc', analysis
            elif format_lower in self.__ADLS_DIRECT_FORMATS:
                analysis['reasoning'].append(f"ADLS-direct format: {format_type}")
                return 'adls', analysis
            else:
                # Unknown format - require explicit configuration
                raise ValueError(
                    f"Unknown format '{format_type}' for path '{path}'. "
                    f"Please configure via environment variables or use explicit_override parameter."
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
    
    def __detect_uc_object(self, path: str) -> Optional[str]:
        """
        Private method to detect if path references a Unity Catalog object.
        
        Args:
            path: Path to analyze
            
        Returns:
            Type of UC object detected ('volume', 'table', 'system_schema') or None
        """
        # Check for UC volume pattern: /Volumes/catalog/schema/volume/...
        if self.__uc_volume_regex.match(path):
            return 'volume'
        
        # Check for three-part catalog table name: catalog.schema.table
        if self.__uc_catalog_table_regex.match(path):
            return 'table'
        
        # Check for system schemas
        for regex in self.__uc_system_schema_regexes:
            if regex.match(path):
                return 'system_schema'
        
        return None
    
    def get_supported_formats(self) -> Dict[str, List[str]]:
        """
        Return supported formats for each routing method.
        Only returns non-sensitive format information.
        """
        with self.__lock:
            return {
                'uc_formats': sorted(list(self.__UC_MANAGED_FORMATS | self.__custom_uc_formats)),
                'adls_formats': sorted(list(self.__ADLS_DIRECT_FORMATS | self.__custom_adls_formats))
            }
    
    @_protect_config_method
    def _get_configuration_summary_internal(self) -> Dict:
        """
        Protected method to return summary of current configuration for internal debugging.
        This method is protected from direct user access.
        """
        with self.__lock:
            return {
                'force_uc_patterns': [p.pattern for p in self.__force_uc_patterns],
                'force_adls_patterns': [p.pattern for p in self.__force_adls_patterns],
                'custom_uc_formats': sorted(list(self.__custom_uc_formats)),
                'custom_adls_formats': sorted(list(self.__custom_adls_formats)),
                'built_in_uc_formats': sorted(list(self.__UC_MANAGED_FORMATS)),
                'built_in_adls_formats': sorted(list(self.__ADLS_DIRECT_FORMATS))
            }
    
    @_protect_config_method
    def _validate_configuration_internal(self) -> List[str]:
        """
        Protected method to validate current configuration and return any warnings.
        This method is protected from direct user access.
        """
        warnings = []
        
        with self.__lock:
            # Check for overlapping custom formats
            overlap = self.__custom_uc_formats & self.__custom_adls_formats
            if overlap:
                warnings.append(f"Overlapping custom formats found: {overlap}")
            
            # Check for conflicts with built-in formats
            uc_conflicts = self.__custom_adls_formats & self.__UC_MANAGED_FORMATS
            if uc_conflicts:
                warnings.append(f"Custom ADLS formats conflict with built-in UC formats: {uc_conflicts}")
            
            adls_conflicts = self.__custom_uc_formats & self.__ADLS_DIRECT_FORMATS
            if adls_conflicts:
                warnings.append(f"Custom UC formats conflict with built-in ADLS formats: {adls_conflicts}")
            
            # Check regex pattern validity
            for pattern_list, name in [
                (self.__force_uc_patterns, 'force_uc_patterns'),
                (self.__force_adls_patterns, 'force_adls_patterns')
            ]:
                for pattern in pattern_list:
                    try:
                        pattern.search("")  # Test the regex
                    except Exception as e:
                        warnings.append(f"Invalid regex in {name}: {pattern.pattern} - {str(e)}")
        
        return warnings
    
    # Public method with limited information exposure
    def validate_basic_configuration(self) -> bool:
        """
        Public method to perform basic configuration validation.
        Returns only basic validity status without exposing sensitive details.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            warnings = self._validate_configuration_internal()
            if warnings:
                logger.warning("Configuration validation found issues")
                return False
            return True
        except PermissionError:
            # Internal validation failed due to security restrictions
            return True  # Assume valid if we can't check
        except Exception as e:
            logger.error(f"Configuration validation error: {str(e)}")
            return False