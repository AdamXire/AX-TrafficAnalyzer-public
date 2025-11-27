"""
@fileoverview Core Module Package
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Core functionality package.
"""

from .platform import get_platform_info, PlatformInfo
from .dependencies import DependencyValidator, DependencyValidationError
from .errors import (
    AXTrafficError,
    PlatformDetectionError,
    DependencyValidationError as DepValidationError,
    ConfigurationError,
    ResourceError,
    NetworkError,
    SecurityError,
    EXIT_SUCCESS,
    EXIT_PLATFORM_ERROR,
    EXIT_DEPENDENCY_ERROR,
    EXIT_CONFIG_ERROR,
)
from .logging import setup_logging, get_logger
from .config import load_config, get_config, validate_config
from .orchestrator import StartupOrchestrator

# Phase 2a: Critical Infrastructure
from .security import KeyringManager, CertificateSecurityManager
from .memory import RingBuffer, BackpressureController, CircuitBreaker, MemoryWatermarkMonitor
from .concurrency import AsyncLockManager, RedisQueue, IdempotencyManager

__all__ = [
    "get_platform_info",
    "PlatformInfo",
    "DependencyValidator",
    "DependencyValidationError",
    "AXTrafficError",
    "PlatformDetectionError",
    "ConfigurationError",
    "ResourceError",
    "NetworkError",
    "SecurityError",
    "EXIT_SUCCESS",
    "EXIT_PLATFORM_ERROR",
    "EXIT_DEPENDENCY_ERROR",
    "EXIT_CONFIG_ERROR",
    "setup_logging",
    "get_logger",
    "load_config",
    "get_config",
    "validate_config",
    "StartupOrchestrator",
    # Phase 2a: Critical Infrastructure
    "KeyringManager",
    "CertificateSecurityManager",
    "RingBuffer",
    "BackpressureController",
    "CircuitBreaker",
    "MemoryWatermarkMonitor",
    "AsyncLockManager",
    "RedisQueue",
    "IdempotencyManager",
]

