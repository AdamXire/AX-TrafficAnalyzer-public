"""
@fileoverview Error Handling Framework
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education
@version 1.0.0
@created 2025-11-18
@modified 2025-11-18

Error handling framework with exit codes and structured context.
This file is part of AX-TrafficAnalyzer Community Edition.
Licensed under MIT License. See LICENSE-COMMUNITY for details.

INNOVATION:
- World-class error handling with exit codes
- Structured error context
- Backward compatible with existing errors
"""

import sys
from typing import Optional
from dataclasses import dataclass


# Exit codes
EXIT_SUCCESS = 0
EXIT_GENERAL_FAILURE = 1
EXIT_PLATFORM_ERROR = 20
EXIT_DEPENDENCY_ERROR = 21
EXIT_CONFIG_ERROR = 22
EXIT_RESOURCE_ERROR = 23
EXIT_NETWORK_ERROR = 24
EXIT_SECURITY_ERROR = 25


@dataclass
class ErrorContext:
    """Structured error context."""
    component: str
    found: str
    required: str
    reason: str
    solution: str
    platform: str
    documentation: Optional[str] = None


class AXTrafficError(Exception):
    """Base error for all AX-Traffic errors."""
    exit_code: int = EXIT_GENERAL_FAILURE
    
    def __init__(self, message: str, context: Optional[ErrorContext] = None):
        super().__init__(message)
        self.context = context


# Backward compatible - existing errors keep working
class PlatformDetectionError(AXTrafficError):
    """Raised when platform detection fails."""
    exit_code = EXIT_PLATFORM_ERROR


class DependencyValidationError(AXTrafficError):
    """Raised when dependency validation fails."""
    exit_code = EXIT_DEPENDENCY_ERROR


class ConfigurationError(AXTrafficError):
    """Raised when configuration validation fails."""
    exit_code = EXIT_CONFIG_ERROR


class ResourceError(AXTrafficError):
    """Raised when resource validation fails."""
    exit_code = EXIT_RESOURCE_ERROR


class NetworkError(AXTrafficError):
    """Raised when network validation fails."""
    exit_code = EXIT_NETWORK_ERROR


class SecurityError(AXTrafficError):
    """Raised when security validation fails."""
    exit_code = EXIT_SECURITY_ERROR

