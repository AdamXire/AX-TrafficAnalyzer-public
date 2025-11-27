"""
@fileoverview Mitmproxy Manager - Transparent proxy lifecycle
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Manages mitmproxy subprocess with health monitoring.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import subprocess
import signal
import time
import os
from pathlib import Path
from typing import Optional, List
from ...core.errors import NetworkError
from ...core.logging import get_logger

log = get_logger(__name__)


class MitmproxyManager:
    """
    Manages mitmproxy subprocess for transparent HTTPS interception.
    
    Architecture: Subprocess (not systemd) for easier Python integration.
    """
    
    def __init__(self, port: int = 8080, cert_dir: str = "./certs", addons_dir: Optional[str] = None):
        """
        Initialize mitmproxy manager.
        
        Args:
            port: Port for mitmproxy to listen on (default: 8080)
            cert_dir: Directory containing CA certificate
            addons_dir: Directory containing custom addons (optional)
        """
        self.port = port
        self.cert_dir = Path(cert_dir)
        self.addons_dir = Path(addons_dir) if addons_dir else None
        self.process: Optional[subprocess.Popen] = None
        self.ca_cert = self.cert_dir / "ax-traffic-ca.pem"
        log.debug("mitmproxy_manager_initialized", port=port, cert_dir=str(cert_dir))
    
    def start(self) -> None:
        """
        Start mitmproxy subprocess in transparent mode.
        
        Raises:
            NetworkError: If mitmproxy fails to start
        """
        if self.process is not None:
            log.warning("mitmproxy_already_running")
            return
        
        # Validate CA certificate exists
        if not self.ca_cert.exists():
            raise NetworkError(
                f"CA certificate not found: {self.ca_cert}. "
                f"Certificate must be generated before starting mitmproxy.",
                None
            )
        
        # Build mitmproxy command
        cmd = [
            "mitmdump",
            "--mode", "transparent",
            "--listen-port", str(self.port),
            "--set", f"confdir={self.cert_dir}",
            "--set", "ssl_insecure=true",  # Accept all certificates
        ]
        
        # Add custom addons if specified
        if self.addons_dir and self.addons_dir.exists():
            addon_files = list(self.addons_dir.glob("*.py"))
            for addon in addon_files:
                cmd.extend(["--scripts", str(addon)])
                log.debug("mitmproxy_addon_loaded", addon=str(addon))
        
        log.info("starting_mitmproxy", port=self.port, cmd=" ".join(cmd))
        
        try:
            # Start subprocess
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid  # Create new process group
            )
            
            # Wait briefly to check if process started
            time.sleep(0.5)
            if self.process.poll() is not None:
                # Process exited immediately
                stdout, stderr = self.process.communicate()
                error_msg = stderr.decode() if stderr else stdout.decode()
                raise NetworkError(
                    f"mitmproxy failed to start: {error_msg}",
                    None
                )
            
            log.info("mitmproxy_started", pid=self.process.pid, port=self.port)
        except FileNotFoundError:
            raise NetworkError(
                "mitmproxy not found. Install with: pip install mitmproxy>=10.0.0,<11.0.0",
                None
            )
        except Exception as e:
            raise NetworkError(
                f"Failed to start mitmproxy: {e}",
                None
            )
    
    def stop(self) -> None:
        """Stop mitmproxy subprocess."""
        if self.process is None:
            log.debug("mitmproxy_not_running")
            return
        
        log.info("stopping_mitmproxy", pid=self.process.pid)
        
        try:
            # Send SIGTERM to process group
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            
            # Wait up to 5 seconds for graceful shutdown
            try:
                self.process.wait(timeout=5)
                log.info("mitmproxy_stopped", pid=self.process.pid)
            except subprocess.TimeoutExpired:
                # Force kill if not responding
                log.warning("mitmproxy_force_kill", pid=self.process.pid)
                os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                self.process.wait()
        except ProcessLookupError:
            log.debug("mitmproxy_already_stopped")
        except Exception as e:
            log.error("mitmproxy_stop_failed", error=str(e))
        finally:
            self.process = None
    
    def is_running(self) -> bool:
        """Check if mitmproxy is running."""
        if self.process is None:
            return False
        return self.process.poll() is None
    
    def get_status(self) -> dict:
        """
        Get mitmproxy status.
        
        Returns:
            Dictionary with status information
        """
        return {
            "running": self.is_running(),
            "port": self.port,
            "pid": self.process.pid if self.process else None,
            "ca_cert": str(self.ca_cert) if self.ca_cert.exists() else None
        }

