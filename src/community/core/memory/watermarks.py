"""
@fileoverview Memory Watermark Monitor - System memory monitoring
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Memory watermark monitoring (80% warning, 95% emergency).
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import psutil
from ..logging import get_logger
from ..errors import ResourceError

log = get_logger(__name__)

# Watermark thresholds
WARNING_THRESHOLD = 0.80  # 80% - warn
EMERGENCY_THRESHOLD = 0.95  # 95% - emergency cleanup


class MemoryWatermarkMonitor:
    """
    Memory watermark monitor for system memory.
    
    Monitors system memory usage and triggers warnings/emergency cleanup
    at configurable thresholds.
    """
    
    def __init__(self, warning_threshold: float = WARNING_THRESHOLD,
                 emergency_threshold: float = EMERGENCY_THRESHOLD):
        """
        Initialize memory watermark monitor.
        
        Args:
            warning_threshold: Memory usage threshold for warning (default: 0.80 = 80%)
            emergency_threshold: Memory usage threshold for emergency (default: 0.95 = 95%)
        """
        self.warning_threshold = warning_threshold
        self.emergency_threshold = emergency_threshold
        self.warning_triggered = False
        self.emergency_triggered = False
        log.debug("memory_watermark_monitor_initialized",
                 warning_threshold=warning_threshold,
                 emergency_threshold=emergency_threshold)
    
    def check_memory(self) -> dict:
        """
        Check current memory usage.
        
        Returns:
            Dictionary with memory metrics and status
            
        Raises:
            ResourceError: If memory usage exceeds emergency threshold
        """
        mem = psutil.virtual_memory()
        usage_percent = mem.percent / 100.0
        available_gb = mem.available / (1024 ** 3)
        total_gb = mem.total / (1024 ** 3)
        
        status = {
            "usage_percent": usage_percent,
            "available_gb": available_gb,
            "total_gb": total_gb,
            "used_gb": (mem.total - mem.available) / (1024 ** 3),
            "warning_threshold": self.warning_threshold,
            "emergency_threshold": self.emergency_threshold,
            "status": "normal"
        }
        
        # Check emergency threshold (fail-fast)
        if usage_percent >= self.emergency_threshold:
            if not self.emergency_triggered:
                self.emergency_triggered = True
                log.error("memory_emergency_threshold_exceeded",
                         usage_percent=usage_percent,
                         available_gb=available_gb)
            status["status"] = "emergency"
            raise ResourceError(
                f"System memory usage exceeds emergency threshold: {usage_percent*100:.1f}% "
                f"(threshold: {self.emergency_threshold*100:.1f}%). "
                f"Available: {available_gb:.2f}GB / {total_gb:.2f}GB. "
                f"Emergency cleanup required.",
                None
            )
        
        # Check warning threshold (fail-loud)
        if usage_percent >= self.warning_threshold:
            if not self.warning_triggered:
                self.warning_triggered = True
                log.warning("memory_warning_threshold_exceeded",
                           usage_percent=usage_percent,
                           available_gb=available_gb)
            status["status"] = "warning"
        else:
            # Reset flags if below threshold
            if self.warning_triggered:
                self.warning_triggered = False
                log.info("memory_warning_cleared", usage_percent=usage_percent)
            if self.emergency_triggered:
                self.emergency_triggered = False
                log.info("memory_emergency_cleared", usage_percent=usage_percent)
            status["status"] = "normal"
        
        return status
    
    def get_status(self) -> dict:
        """Get current memory status."""
        return self.check_memory()

