"""
@fileoverview Threat Intelligence Integration - VirusTotal, OTX, etc.
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Threat intelligence API integrations.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from .virustotal import VirusTotalClient

__all__ = ["VirusTotalClient"]

