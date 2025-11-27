"""
@fileoverview Cloud Module - Cloud storage integration
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Cloud storage integration for PCAP backup.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from .backup import CloudBackupManager

__all__ = [
    "CloudBackupManager"
]

