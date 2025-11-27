"""
@fileoverview Disk space monitoring and emergency cleanup
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Monitor disk space and trigger cleanup when needed.
Fail-fast - no silent degradation or warnings.
"""

import os
import psutil
import threading
import time
from pathlib import Path
from typing import Optional, Callable, List
from ..core.errors import ResourceError
from ..core.logging import get_logger

log = get_logger(__name__)

# Thresholds
MIN_FREE_GB = 1.0  # Minimum free space in GB
WARNING_THRESHOLD_GB = 2.0  # Warn when below this
CRITICAL_THRESHOLD_GB = 0.5  # Critical when below this


class DiskSpaceManager:
    """
    Monitor disk space and manage cleanup.
    
    Fail-fast - no try-except that print warnings.
    Exceptions propagate to orchestrator.
    """
    
    def __init__(self, monitor_path: str = "/", check_interval: int = 60):
        """
        Initialize disk space manager.
        
        Args:
            monitor_path: Path to monitor disk space for
            check_interval: Check interval in seconds
        """
        self.monitor_path = Path(monitor_path)
        self.check_interval = check_interval
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.cleanup_callbacks: List[Callable] = []
        log.debug("disk_monitor_initialized", path=str(monitor_path), interval=check_interval)
    
    def register_cleanup_callback(self, callback: Callable) -> None:
        """Register a callback for emergency cleanup."""
        self.cleanup_callbacks.append(callback)
        log.debug("cleanup_callback_registered")
    
    def get_free_space_gb(self) -> float:
        """
        Get free disk space in GB.
        
        Raises:
            ResourceError: If disk check fails
        """
        stat = os.statvfs(str(self.monitor_path))
        free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
        return free_gb
    
    def get_disk_usage(self) -> dict:
        """
        Get disk usage information.
        
        Raises:
            ResourceError: If disk check fails
        """
        usage = psutil.disk_usage(str(self.monitor_path))
        return {
            "total_gb": usage.total / (1024**3),
            "used_gb": usage.used / (1024**3),
            "free_gb": usage.free / (1024**3),
            "percent": usage.percent
        }
    
    def check_disk_space(self) -> dict:
        """
        Check disk space and return status.
        
        Raises:
            ResourceError: If disk space below critical threshold or check fails
        """
        free_gb = self.get_free_space_gb()
        status = {
            "free_gb": free_gb,
            "status": "ok",
            "warning": False,
            "critical": False
        }
        
        if free_gb < CRITICAL_THRESHOLD_GB:
            status["status"] = "critical"
            status["critical"] = True
            log.error("disk_space_critical", free_gb=free_gb, threshold=CRITICAL_THRESHOLD_GB)
            self._emergency_cleanup()
            raise ResourceError(
                f"Critical: Disk space below threshold ({free_gb:.2f}GB < {CRITICAL_THRESHOLD_GB}GB). "
                f"Emergency cleanup triggered.",
                None
            )
        elif free_gb < WARNING_THRESHOLD_GB:
            status["status"] = "warning"
            status["warning"] = True
            log.warning("disk_space_low", free_gb=free_gb, threshold=WARNING_THRESHOLD_GB)
        elif free_gb < MIN_FREE_GB:
            status["status"] = "warning"
            status["warning"] = True
            log.warning("disk_space_below_minimum", free_gb=free_gb, minimum=MIN_FREE_GB)
        
        return status
    
    def _emergency_cleanup(self) -> None:
        """Trigger emergency cleanup callbacks."""
        log.warning("triggering_emergency_cleanup")
        for callback in self.cleanup_callbacks:
            try:
                callback()
            except Exception as e:
                log.error("cleanup_callback_failed", error=str(e), error_type=type(e).__name__)
    
    def _monitor_loop(self) -> None:
        """
        Main monitoring loop.
        
        Exceptions propagate - orchestrator handles them.
        """
        while self.monitoring:
            try:
                self.check_disk_space()
            except ResourceError as e:
                # Critical error - log and stop monitoring
                log.error("disk_monitor_critical_error", error=str(e))
                self.monitoring = False
                raise  # Propagate to orchestrator
            except Exception as e:
                # Unexpected error - log and re-raise
                log.error("disk_monitor_unexpected_error", error=str(e), error_type=type(e).__name__)
                self.monitoring = False
                raise  # Propagate to orchestrator
            
            # Sleep before next check
            time.sleep(self.check_interval)
    
    def start_monitoring(self) -> None:
        """
        Start disk space monitoring.
        
        Raises:
            ResourceError: If monitoring thread fails to start
        """
        if self.monitoring:
            log.warning("disk_monitoring_already_started")
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        log.info("disk_monitoring_started", interval=self.check_interval)
    
    def stop_monitoring(self) -> None:
        """
        Stop disk space monitoring.
        
        Blocks up to 5 seconds for thread to stop.
        Raises ResourceError if thread doesn't stop cleanly.
        """
        if not self.monitoring:
            log.debug("disk_monitoring_not_running")
            return
        
        self.monitoring = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
            if self.monitor_thread.is_alive():
                log.error("disk_monitor_thread_did_not_stop")
                raise ResourceError(
                    "Disk monitor thread did not stop within timeout",
                    None
                )
        
        log.info("disk_monitoring_stopped")

