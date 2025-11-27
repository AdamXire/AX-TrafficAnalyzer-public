"""
@fileoverview TCPDump Manager - systemd service for UDP/DNS capture
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Manages tcpdump via systemd service (consistent with Phase 1 architecture).
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import subprocess
from pathlib import Path
from typing import Optional
from datetime import datetime
from ...core.errors import NetworkError
from ...core.logging import get_logger

log = get_logger(__name__)

SERVICE_NAME = "ax-traffic-tcpdump.service"
SERVICE_FILE = Path(f"/etc/systemd/system/{SERVICE_NAME}")


class TCPDumpManager:
    """
    Manages tcpdump via systemd service for UDP/DNS capture.
    
    Architecture: systemd service (consistent with Phase 1 hotspot).
    """
    
    def __init__(self, interface: str = "wlan0", output_dir: str = "./captures/raw", 
                 filter_expr: str = "udp or dns", pcap_monitor=None):
        """
        Initialize tcpdump manager.
        
        Args:
            interface: Network interface to capture on
            output_dir: Directory for PCAP output files
            filter_expr: tcpdump filter expression (default: "udp or dns")
            pcap_monitor: Optional PCAPFileMonitor for DNS processing
        """
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.filter_expr = filter_expr
        self.output_file = self.output_dir / f"tcpdump_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        self.pcap_monitor = pcap_monitor
        log.debug("tcpdump_manager_initialized", 
                 interface=interface, 
                 output_dir=str(output_dir),
                 has_monitor=pcap_monitor is not None)
    
    def _generate_systemd_service(self, exec_start: list, description: str) -> str:
        """
        Generate systemd service file content.
        
        Args:
            exec_start: Command and arguments for ExecStart
            description: Service description
            
        Returns:
            Service file content
        """
        exec_start_str = " ".join(f'"{arg}"' if " " in arg else arg for arg in exec_start)
        return f"""[Unit]
Description={description}
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start_str}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ax-traffic-tcpdump

[Install]
WantedBy=multi-user.target
"""
    
    def _create_systemd_service(self, service_file: Path, content: str) -> None:
        """
        Create systemd service file.
        
        Args:
            service_file: Path to service file
            content: Service file content
            
        Raises:
            NetworkError: If service file creation fails
        """
        try:
            service_file.write_text(content)
            log.debug("systemd_service_file_created", path=str(service_file))
            
            # Reload systemd
            result = subprocess.run(
                ["systemctl", "daemon-reload"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise NetworkError(
                    f"Failed to reload systemd: {result.stderr}",
                    None
                )
            log.debug("systemd_daemon_reloaded")
        except Exception as e:
            raise NetworkError(
                f"Failed to create systemd service file: {e}",
                None
            )
    
    def _ensure_output_dir(self) -> None:
        """Ensure output directory exists."""
        if not self.output_dir.exists():
            self.output_dir.mkdir(parents=True, mode=0o700)
            log.debug("output_directory_created", path=str(self.output_dir))
    
    def start(self) -> None:
        """
        Start tcpdump via systemd service.
        
        Raises:
            NetworkError: If tcpdump fails to start
        """
        log.info("starting_tcpdump", interface=self.interface, filter=self.filter_expr)
        
        # Ensure output directory exists
        self._ensure_output_dir()
        
        # Build tcpdump command
        exec_start = [
            "/usr/bin/tcpdump",
            "-i", self.interface,
            "-w", str(self.output_file),
            self.filter_expr
        ]
        
        # Generate and create service file
        service_content = self._generate_systemd_service(
            exec_start,
            "AX-Traffic tcpdump for UDP/DNS capture"
        )
        self._create_systemd_service(SERVICE_FILE, service_content)
        
        # Start service
        result = subprocess.run(
            ["systemctl", "start", SERVICE_NAME],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            raise NetworkError(
                f"Failed to start tcpdump service: {result.stderr}",
                None
            )
        log.info("tcpdump_service_started", service=SERVICE_NAME, output_file=str(self.output_file))
    
    def stop(self) -> None:
        """Stop tcpdump service."""
        log.info("stopping_tcpdump")
        
        result = subprocess.run(
            ["systemctl", "stop", SERVICE_NAME],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            log.warning("tcpdump_stop_failed", error=result.stderr)
        else:
            log.info("tcpdump_service_stopped")
    
    def is_running(self) -> bool:
        """Check if tcpdump service is running."""
        result = subprocess.run(
            ["systemctl", "is-active", SERVICE_NAME],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    
    def get_status(self) -> dict:
        """
        Get tcpdump status.
        
        Returns:
            Dictionary with status information
        """
        return {
            "running": self.is_running(),
            "interface": self.interface,
            "filter": self.filter_expr,
            "output_file": str(self.output_file),
            "service": SERVICE_NAME
        }
    
    def get_output_file(self) -> Path:
        """Get current output file path."""
        return self.output_file
    
    def get_output_dir(self) -> Path:
        """Get output directory."""
        return self.output_dir

