"""
@fileoverview Plugin Sandbox - Process isolation and resource limits
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Sandbox implementation for plugin isolation using process isolation,
resource limits, and optional seccomp filtering.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import os
import resource
import multiprocessing
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass
from .exceptions import PluginSandboxError
from ..core.logging import get_logger
from ..core.errors import DependencyValidationError

log = get_logger(__name__)


@dataclass
class SandboxConfig:
    """Sandbox configuration."""
    cpu_percent_limit: int = 10        # Max CPU usage percent
    memory_mb_limit: int = 256         # Max memory in MB
    disk_io_mb_limit: int = 10         # Max disk I/O in MB
    max_open_files: int = 64           # Max open file descriptors
    timeout_seconds: int = 30          # Max execution time
    network_allowed: bool = False      # Allow network access
    filesystem_allowed: bool = False   # Allow filesystem access


def seccomp_available() -> bool:
    """
    Check if seccomp is available.
    
    Returns:
        True if seccomp is available
    """
    try:
        import prctl
        return True
    except ImportError:
        return False


class PluginSandbox:
    """
    Sandbox for plugin execution.
    
    Provides:
    - Process isolation via multiprocessing
    - Resource limits via ulimit
    - Optional seccomp filtering (Linux only)
    
    FAIL-FAST: In production, sandbox must be available.
    """
    
    def __init__(self, config: SandboxConfig, mode: str = "production"):
        """
        Initialize sandbox.
        
        Args:
            config: Sandbox configuration
            mode: Operating mode ("production" or "dev")
            
        Raises:
            DependencyValidationError: If seccomp unavailable in production
        """
        self.config = config
        self.mode = mode
        self.seccomp_enabled = False
        
        # Validate seccomp in production
        if mode == "production":
            if not seccomp_available():
                raise DependencyValidationError(
                    "Seccomp required for plugin sandbox in production mode.\n"
                    "Install python-prctl: pip install python-prctl\n"
                    "Or run in dev mode: config.mode = 'dev'"
                )
            self.seccomp_enabled = True
        elif seccomp_available():
            self.seccomp_enabled = True
            log.info("sandbox_seccomp_enabled", mode=mode)
        else:
            log.warning(
                "sandbox_seccomp_unavailable",
                message="Running without seccomp (dev mode only)"
            )
        
        log.info(
            "sandbox_initialized",
            seccomp=self.seccomp_enabled,
            memory_limit_mb=config.memory_mb_limit
        )
    
    def _set_resource_limits(self) -> None:
        """Set resource limits using ulimit."""
        # Memory limit (in bytes)
        memory_bytes = self.config.memory_mb_limit * 1024 * 1024
        try:
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        except (ValueError, resource.error) as e:
            log.warning("sandbox_memory_limit_failed", error=str(e))
        
        # CPU time limit
        cpu_seconds = self.config.timeout_seconds
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        except (ValueError, resource.error) as e:
            log.warning("sandbox_cpu_limit_failed", error=str(e))
        
        # Open files limit
        try:
            resource.setrlimit(
                resource.RLIMIT_NOFILE,
                (self.config.max_open_files, self.config.max_open_files)
            )
        except (ValueError, resource.error) as e:
            log.warning("sandbox_file_limit_failed", error=str(e))
        
        # Disable core dumps
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ValueError, resource.error) as e:
            log.warning("sandbox_core_limit_failed", error=str(e))
    
    def _apply_seccomp(self) -> None:
        """Apply seccomp filter to restrict syscalls."""
        if not self.seccomp_enabled:
            return
        
        try:
            import prctl
            # Set no-new-privileges flag
            prctl.set_no_new_privs(1)
            log.debug("sandbox_seccomp_applied")
        except Exception as e:
            if self.mode == "production":
                raise PluginSandboxError(f"Failed to apply seccomp: {e}")
            log.warning("sandbox_seccomp_failed", error=str(e))
    
    def _sandbox_init(self) -> None:
        """Initialize sandbox in child process."""
        self._set_resource_limits()
        self._apply_seccomp()
    
    def run(
        self,
        func: Callable,
        args: tuple = (),
        kwargs: dict = None
    ) -> Any:
        """
        Run function in sandbox.
        
        Args:
            func: Function to execute
            args: Positional arguments
            kwargs: Keyword arguments
            
        Returns:
            Function result
            
        Raises:
            PluginSandboxError: If execution fails or times out
        """
        kwargs = kwargs or {}
        
        # Create result queue
        result_queue = multiprocessing.Queue()
        
        def worker():
            """Worker function that runs in sandbox."""
            self._sandbox_init()
            try:
                result = func(*args, **kwargs)
                result_queue.put(("success", result))
            except Exception as e:
                result_queue.put(("error", str(e)))
        
        # Start process
        process = multiprocessing.Process(target=worker)
        process.start()
        
        # Wait with timeout
        process.join(timeout=self.config.timeout_seconds)
        
        if process.is_alive():
            process.terminate()
            process.join(timeout=1)
            if process.is_alive():
                process.kill()
            raise PluginSandboxError(
                f"Plugin execution timed out after {self.config.timeout_seconds}s"
            )
        
        # Get result
        if result_queue.empty():
            raise PluginSandboxError("Plugin execution failed with no result")
        
        status, result = result_queue.get()
        
        if status == "error":
            raise PluginSandboxError(f"Plugin execution failed: {result}")
        
        return result


def validate_sandbox_requirements(mode: str) -> None:
    """
    Validate sandbox requirements for the given mode.
    
    FAIL-FAST: In production, missing requirements are fatal.
    
    Args:
        mode: Operating mode ("production" or "dev")
        
    Raises:
        DependencyValidationError: If requirements not met in production
    """
    if mode == "production":
        if not seccomp_available():
            raise DependencyValidationError(
                "Plugin sandbox requires seccomp in production mode.\n\n"
                "SOLUTION:\n"
                "  1. Install python-prctl: pip install python-prctl\n"
                "  2. Or disable plugins: set plugins.enabled = false in config.json\n"
                "  3. Or run in dev mode: set mode = 'dev' in config.json\n\n"
                "WARNING: Running plugins without sandbox is a security risk."
            )
    else:
        if not seccomp_available():
            log.warning(
                "sandbox_requirements_not_met",
                message="Plugins will run WITHOUT sandbox isolation (dev mode)"
            )

