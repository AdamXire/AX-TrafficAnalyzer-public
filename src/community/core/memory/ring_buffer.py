"""
@fileoverview Ring Buffer - Fixed-size FIFO buffer for PCAP export
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Fixed-size ring buffer with FIFO semantics for PCAP export.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from collections import deque
from typing import Optional
from ..logging import get_logger

log = get_logger(__name__)


class RingBuffer:
    """
    Fixed-size ring buffer with FIFO semantics.
    
    When full, oldest data is dropped (ring behavior).
    Used for PCAP export buffering with backpressure control.
    """
    
    def __init__(self, max_size_mb: int = 10):
        """
        Initialize ring buffer.
        
        Args:
            max_size_mb: Maximum size in megabytes (default: 10MB)
        """
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.current_size = 0
        self.buffer = deque()
        self.backpressure_threshold = int(self.max_size_bytes * 0.8)  # 80% threshold
        log.debug("ring_buffer_initialized", max_size_mb=max_size_mb, threshold_mb=self.backpressure_threshold / (1024*1024))
    
    def push(self, data: bytes) -> bool:
        """
        Add data to buffer.
        
        If buffer exceeds max_size, oldest data is dropped.
        
        Args:
            data: Data to add (bytes)
            
        Returns:
            True if added successfully, False if buffer is full (backpressure signal)
        """
        data_size = len(data)
        
        # Check if adding would exceed max size
        if self.current_size + data_size > self.max_size_bytes:
            # Drop oldest data until we have space
            while self.current_size + data_size > self.max_size_bytes and self.buffer:
                dropped = self.buffer.popleft()
                self.current_size -= len(dropped)
                log.warning("ring_buffer_overflow", dropped_bytes=len(dropped))
            
            # If still too large, drop this data
            if self.current_size + data_size > self.max_size_bytes:
                log.error("ring_buffer_data_too_large", data_size=data_size, max_size=self.max_size_bytes)
                return False
        
        # Add data
        self.buffer.append(data)
        self.current_size += data_size
        log.debug("ring_buffer_pushed", data_size=data_size, current_size_mb=self.current_size / (1024*1024))
        return True
    
    def pop(self) -> Optional[bytes]:
        """
        Remove and return oldest data from buffer.
        
        Returns:
            Oldest data (bytes) or None if buffer is empty
        """
        if not self.buffer:
            return None
        
        data = self.buffer.popleft()
        self.current_size -= len(data)
        log.debug("ring_buffer_popped", data_size=len(data), remaining_size_mb=self.current_size / (1024*1024))
        return data
    
    def is_full(self) -> bool:
        """
        Check if buffer is >80% full (backpressure threshold).
        
        Returns:
            True if buffer is at or above 80% capacity
        """
        return self.current_size >= self.backpressure_threshold
    
    def is_empty(self) -> bool:
        """Check if buffer is empty."""
        return len(self.buffer) == 0
    
    def size_mb(self) -> float:
        """Get current size in megabytes."""
        return self.current_size / (1024 * 1024)
    
    def max_size_mb(self) -> float:
        """Get maximum size in megabytes."""
        return self.max_size_bytes / (1024 * 1024)
    
    def clear(self) -> None:
        """Clear all data from buffer."""
        dropped_count = len(self.buffer)
        self.buffer.clear()
        self.current_size = 0
        log.info("ring_buffer_cleared", dropped_items=dropped_count)

