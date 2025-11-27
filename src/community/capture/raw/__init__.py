"""
@fileoverview Raw Traffic Capture Module - tcpdump integration
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

tcpdump integration for UDP/DNS traffic capture.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from .tcpdump import TCPDumpManager

__all__ = ["TCPDumpManager"]

