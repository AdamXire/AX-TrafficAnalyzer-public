"""
@fileoverview Backpressure Controller - Flow control for PCAP export
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Backpressure controller to signal when PCAP export should pause.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from .ring_buffer import RingBuffer
from ..logging import get_logger

log = get_logger(__name__)


class BackpressureController:
    """
    Backpressure controller for PCAP export flow control.
    
    Monitors ring buffer fill level and signals when capture should pause
    to prevent memory exhaustion.
    """
    
    def __init__(self, buffer: RingBuffer):
        """
        Initialize backpressure controller.
        
        Args:
            buffer: RingBuffer instance to monitor
        """
        self.buffer = buffer
        self.paused = False
        log.debug("backpressure_controller_initialized")
    
    def should_pause(self) -> bool:
        """
        Check if capture should pause due to backpressure.
        
        Returns:
            True if buffer is >80% full (backpressure threshold)
        """
        is_full = self.buffer.is_full()
        
        if is_full and not self.paused:
            self.paused = True
            log.warning("backpressure_pause_signal", 
                       buffer_size_mb=self.buffer.size_mb(),
                       max_size_mb=self.buffer.max_size_mb())
        elif not is_full and self.paused:
            self.paused = False
            log.info("backpressure_resume_signal",
                    buffer_size_mb=self.buffer.size_mb())
        
        return is_full
    
    def is_paused(self) -> bool:
        """Check if capture is currently paused."""
        return self.paused
    
    def get_buffer_status(self) -> dict:
        """
        Get current buffer status for monitoring.
        
        Returns:
            Dictionary with buffer metrics
        """
        return {
            "size_mb": self.buffer.size_mb(),
            "max_size_mb": self.buffer.max_size_mb(),
            "usage_percent": (self.buffer.size_mb() / self.buffer.max_size_mb()) * 100,
            "paused": self.paused,
            "threshold_mb": self.buffer.backpressure_threshold / (1024 * 1024)
        }

