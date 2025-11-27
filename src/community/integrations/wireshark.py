"""
@fileoverview Wireshark Helper - Integration with Wireshark
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Wireshark integration for PCAP analysis and display filter generation.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from ..core.logging import get_logger
from ..core.errors import DependencyValidationError

log = get_logger(__name__)


def validate_tshark_available() -> bool:
    """
    Check if tshark is available.
    
    Returns:
        True if tshark is available
    """
    return shutil.which("tshark") is not None


class WiresharkHelper:
    """
    Wireshark integration helper.
    
    Features:
    - Generate display filters from sessions/flows
    - Launch Wireshark with filters
    - Extract packet data using tshark
    
    FAIL-FAST: Operations requiring tshark will fail if not available.
    """
    
    def __init__(self, pcap_dir: str = "./captures/pcap"):
        """
        Initialize Wireshark helper.
        
        Args:
            pcap_dir: Directory containing PCAP files
        """
        self.pcap_dir = Path(pcap_dir)
        self.tshark_available = validate_tshark_available()
        
        log.info(
            "wireshark_helper_initialized",
            pcap_dir=str(self.pcap_dir),
            tshark_available=self.tshark_available
        )
    
    def generate_filter_for_ip(self, ip_address: str) -> str:
        """
        Generate Wireshark display filter for IP address.
        
        Args:
            ip_address: IP address to filter
            
        Returns:
            Display filter string
        """
        return f"ip.addr == {ip_address}"
    
    def generate_filter_for_host(self, hostname: str) -> str:
        """
        Generate Wireshark display filter for hostname.
        
        Args:
            hostname: Hostname to filter
            
        Returns:
            Display filter string
        """
        return f'http.host == "{hostname}" or dns.qry.name == "{hostname}"'
    
    def generate_filter_for_session(
        self,
        client_ip: str,
        server_ips: Optional[List[str]] = None
    ) -> str:
        """
        Generate display filter for a session.
        
        Args:
            client_ip: Client IP address
            server_ips: Optional list of server IPs
            
        Returns:
            Display filter string
        """
        filters = [f"ip.src == {client_ip} or ip.dst == {client_ip}"]
        
        if server_ips:
            server_filter = " or ".join(
                f"ip.addr == {ip}" for ip in server_ips
            )
            filters.append(f"({server_filter})")
        
        return " and ".join(filters)
    
    def generate_filter_for_flow(
        self,
        method: str,
        host: str,
        path: str
    ) -> str:
        """
        Generate display filter for a specific HTTP flow.
        
        Args:
            method: HTTP method
            host: Target host
            path: URL path
            
        Returns:
            Display filter string
        """
        return (
            f'http.request.method == "{method}" and '
            f'http.host == "{host}" and '
            f'http.request.uri contains "{path}"'
        )
    
    def generate_filter_for_port(self, port: int) -> str:
        """
        Generate display filter for port.
        
        Args:
            port: Port number
            
        Returns:
            Display filter string
        """
        return f"tcp.port == {port} or udp.port == {port}"
    
    def launch_wireshark(
        self,
        pcap_file: str,
        display_filter: Optional[str] = None
    ) -> bool:
        """
        Launch Wireshark with PCAP file.
        
        Args:
            pcap_file: Path to PCAP file
            display_filter: Optional display filter
            
        Returns:
            True if launched successfully
            
        Raises:
            DependencyValidationError: If Wireshark not available
        """
        wireshark_path = shutil.which("wireshark")
        
        if not wireshark_path:
            raise DependencyValidationError(
                "Wireshark not found in PATH.\n"
                "Install with: sudo apt install wireshark"
            )
        
        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            log.error("pcap_file_not_found", path=str(pcap_path))
            return False
        
        cmd = [wireshark_path, "-r", str(pcap_path)]
        
        if display_filter:
            cmd.extend(["-Y", display_filter])
        
        try:
            subprocess.Popen(cmd, start_new_session=True)
            log.info("wireshark_launched", pcap=str(pcap_path))
            return True
        except Exception as e:
            log.error("wireshark_launch_failed", error=str(e))
            return False
    
    def extract_http_requests(self, pcap_file: str) -> List[Dict[str, Any]]:
        """
        Extract HTTP requests from PCAP using tshark.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            List of HTTP request dictionaries
            
        Raises:
            DependencyValidationError: If tshark not available
        """
        if not self.tshark_available:
            raise DependencyValidationError(
                "tshark required for HTTP extraction.\n"
                "Install with: sudo apt install tshark"
            )
        
        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            return []
        
        try:
            result = subprocess.run(
                [
                    "tshark", "-r", str(pcap_path),
                    "-Y", "http.request",
                    "-T", "fields",
                    "-e", "frame.time",
                    "-e", "ip.src",
                    "-e", "ip.dst",
                    "-e", "http.request.method",
                    "-e", "http.host",
                    "-e", "http.request.uri"
                ],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            requests = []
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                
                parts = line.split("\t")
                if len(parts) >= 6:
                    requests.append({
                        "timestamp": parts[0],
                        "src_ip": parts[1],
                        "dst_ip": parts[2],
                        "method": parts[3],
                        "host": parts[4],
                        "uri": parts[5]
                    })
            
            return requests
            
        except subprocess.TimeoutExpired:
            log.error("tshark_timeout", pcap=str(pcap_path))
            return []
        except Exception as e:
            log.error("tshark_extraction_failed", error=str(e))
            return []
    
    def get_pcap_statistics(self, pcap_file: str) -> Dict[str, Any]:
        """
        Get statistics for PCAP file using tshark.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Statistics dictionary
        """
        if not self.tshark_available:
            return {"error": "tshark not available"}
        
        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            return {"error": "File not found"}
        
        try:
            # Get packet count
            result = subprocess.run(
                ["tshark", "-r", str(pcap_path), "-q", "-z", "io,stat,0"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse output (simplified)
            stats = {
                "file": str(pcap_path),
                "file_size_bytes": pcap_path.stat().st_size,
                "raw_output": result.stdout
            }
            
            return stats
            
        except Exception as e:
            return {"error": str(e)}

