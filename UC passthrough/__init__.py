"""
UC Credential Passthrough Library

Entry points:
    from uc_passthrough import create_uc_passthrough_interface
    from uc_passthrough import UCPassthroughDataFrameReader
"""
from .uc_passthrough_library import UCPassthroughDataFrameReader, create_uc_passthrough_interface
from .path_analyzer import PathAnalyzer
from .authentication_manager import AuthenticationManager

__all__ = [
    "UCPassthroughDataFrameReader",
    "create_uc_passthrough_interface",
    "PathAnalyzer",
    "AuthenticationManager",
]
