"""
@fileoverview Analysis Module - Protocol analyzers and vulnerability scanning
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Traffic analysis module for AX-TrafficAnalyzer Community Edition.
"""

from .base import BaseAnalyzer, AnalysisResult, Finding, Severity
from .orchestrator import AnalysisOrchestrator
from .protocol import HTTPAnalyzer
from .scanner import PassiveScanner

__all__ = [
    "BaseAnalyzer",
    "AnalysisResult",
    "Finding",
    "Severity",
    "AnalysisOrchestrator",
    "HTTPAnalyzer",
    "PassiveScanner",
]

