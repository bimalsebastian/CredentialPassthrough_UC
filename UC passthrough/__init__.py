"""
UC Credential Passthrough Library

Entry points:
    from uc_passthrough import create_uc_passthrough_interface
    from uc_passthrough import UCPassthroughDataFrameReader
"""

__version__ = "1.2.1"
__author__ = "Databricks Professional Services"
__description__ = "Unity Catalog credential passthrough library for direct ADLS access"

from .uc_passthrough_library import (
    UCPassthroughDataFrameReader,
    create_uc_passthrough_interface,
    ConfigurationError,
)
from .path_analyzer import PathAnalyzer
from .authentication_manager import AuthenticationManager

__all__ = [
    "UCPassthroughDataFrameReader",
    "create_uc_passthrough_interface",
    "ConfigurationError",
    "PathAnalyzer",
    "AuthenticationManager",
]
