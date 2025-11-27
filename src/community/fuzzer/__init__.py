"""
@fileoverview Fuzzer System - HTTP request fuzzing and mutation
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

HTTP fuzzing system for security testing.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from .http_fuzzer import HTTPFuzzer
from .mutation import MutationEngine

__all__ = [
    "HTTPFuzzer",
    "MutationEngine"
]

