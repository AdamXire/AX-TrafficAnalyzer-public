"""
@fileoverview Plugin System - Extensibility framework for AX-TrafficAnalyzer
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Plugin system for extending traffic analysis capabilities.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from .base import Plugin, PluginMetadata
from .manager import PluginManager
from .exceptions import (
    PluginError,
    PluginLoadError,
    PluginValidationError,
    PluginSandboxError,
    PluginSignatureError
)

__all__ = [
    "Plugin",
    "PluginMetadata",
    "PluginManager",
    "PluginError",
    "PluginLoadError",
    "PluginValidationError",
    "PluginSandboxError",
    "PluginSignatureError"
]

