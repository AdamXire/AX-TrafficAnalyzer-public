"""
@fileoverview Memory Management Module - Backpressure and Circuit Breakers
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Memory management infrastructure for PCAP export and traffic capture.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from .ring_buffer import RingBuffer
from .backpressure import BackpressureController
from .circuit_breaker import CircuitBreaker
from .watermarks import MemoryWatermarkMonitor

__all__ = ["RingBuffer", "BackpressureController", "CircuitBreaker", "MemoryWatermarkMonitor"]

