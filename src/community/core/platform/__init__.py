"""
@fileoverview Platform Detection Module Package
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Platform detection and validation package.
"""

from .detector import PlatformDetector, PlatformInfo, PlatformDetectionError, get_platform_info

__all__ = [
    "PlatformDetector",
    "PlatformInfo",
    "PlatformDetectionError",
    "get_platform_info",
]

