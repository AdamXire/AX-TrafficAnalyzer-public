"""
@fileoverview Circuit Breaker - Failure protection for PCAP export
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Circuit breaker to pause capture after consecutive PCAP export failures.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from ..logging import get_logger

log = get_logger(__name__)


class CircuitBreaker:
    """
    Circuit breaker for PCAP export failures.
    
    After N consecutive failures, circuit opens (pauses capture).
    Circuit can be manually reset after fixing the issue.
    """
    
    def __init__(self, failure_threshold: int = 3):
        """
        Initialize circuit breaker.
        
        Args:
            failure_threshold: Number of consecutive failures before opening circuit (default: 3)
        """
        self.failure_threshold = failure_threshold
        self.consecutive_failures = 0
        self.is_open = False
        log.debug("circuit_breaker_initialized", threshold=failure_threshold)
    
    def record_failure(self) -> None:
        """
        Record a failure.
        
        If failures reach threshold, circuit opens (pauses capture).
        """
        self.consecutive_failures += 1
        log.warning("circuit_breaker_failure_recorded",
                   consecutive_failures=self.consecutive_failures,
                   threshold=self.failure_threshold)
        
        if self.consecutive_failures >= self.failure_threshold:
            self.is_open = True
            log.error("circuit_breaker_opened",
                     consecutive_failures=self.consecutive_failures,
                     threshold=self.failure_threshold)
    
    def record_success(self) -> None:
        """
        Record a success.
        
        Resets failure count and closes circuit if open.
        """
        if self.consecutive_failures > 0:
            log.info("circuit_breaker_success_recorded",
                    previous_failures=self.consecutive_failures)
            self.consecutive_failures = 0
        
        if self.is_open:
            self.is_open = False
            log.info("circuit_breaker_closed")
    
    def should_open(self) -> bool:
        """
        Check if circuit should be open (pause capture).
        
        Returns:
            True if failures >= threshold
        """
        return self.is_open
    
    def reset(self) -> None:
        """Manually reset circuit breaker."""
        self.consecutive_failures = 0
        self.is_open = False
        log.info("circuit_breaker_reset")
    
    def get_status(self) -> dict:
        """
        Get circuit breaker status for monitoring.
        
        Returns:
            Dictionary with circuit breaker metrics
        """
        return {
            "is_open": self.is_open,
            "consecutive_failures": self.consecutive_failures,
            "threshold": self.failure_threshold,
            "remaining_until_open": max(0, self.failure_threshold - self.consecutive_failures)
        }

