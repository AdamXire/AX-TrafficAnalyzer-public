"""
@fileoverview Plugin Exceptions - Error types for plugin system
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Plugin-specific exception types following fail-fast/fail-loud principles.
This file is part of AX-TrafficAnalyzer Community Edition.
"""


class PluginError(Exception):
    """Base exception for all plugin errors."""
    
    def __init__(self, message: str, plugin_name: str = None, details: dict = None):
        self.plugin_name = plugin_name
        self.details = details or {}
        super().__init__(message)


class PluginLoadError(PluginError):
    """Raised when a plugin fails to load."""
    pass


class PluginValidationError(PluginError):
    """Raised when plugin validation fails."""
    pass


class PluginSandboxError(PluginError):
    """
    Raised when sandbox initialization fails.
    
    FAIL-FAST: In production mode, this error should halt plugin loading.
    """
    pass


class PluginSignatureError(PluginError):
    """
    Raised when plugin GPG signature verification fails.
    
    FAIL-FAST: In production mode, unsigned plugins must not load.
    """
    pass

