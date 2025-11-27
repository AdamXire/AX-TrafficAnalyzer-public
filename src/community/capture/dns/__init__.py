"""
@fileoverview DNS Capture Module - DNS query processing
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

DNS query processing and analysis integration.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from .processor import DNSQueryProcessor
from .handler import DNSHandler

__all__ = ["DNSQueryProcessor", "DNSHandler"]
