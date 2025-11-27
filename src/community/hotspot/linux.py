"""
@fileoverview Linux WiFi hotspot implementation using systemd (hostapd and dnsmasq)
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Linux-specific hotspot implementation using systemd service management.
Uses hostapd and dnsmasq managed as systemd services.
"""

import os
import subprocess
from pathlib import Path
from typing import List, Dict
from .base import HotspotBase, ClientInfo
from ..core.errors import NetworkError
from ..core.logging import get_logger

log = get_logger(__name__)

# Systemd service names
HOSTAPD_SERVICE = "ax-traffic-hostapd"
DNSMASQ_SERVICE = "ax-traffic-dnsmasq"
SYSTEMD_SERVICE_DIR = Path("/etc/systemd/system")
HOSTAPD_CONF_DIR = Path("/etc/ax-traffic")
DNSMASQ_CONF_DIR = Path("/etc/ax-traffic")
HOSTAPD_CONF_FILE = HOSTAPD_CONF_DIR / "hostapd.conf"
DNSMASQ_CONF_FILE = DNSMASQ_CONF_DIR / "dnsmasq.conf"
DNSMASQ_LEASES_FILE = Path("/var/lib/misc/dnsmasq.leases")


class LinuxHotspot(HotspotBase):
    """Linux hotspot implementation using systemd (hostapd and dnsmasq)."""
    
    def __init__(self, config: dict):
        """
        Initialize Linux hotspot.
        
        Args:
            config: Hotspot configuration from config.json
        
        Raises:
            NetworkError: If systemd not available or validation fails
        """
        self.config = config.get("hotspot", {})
        
        # Validate systemd availability
        result = subprocess.run(
            ["systemctl", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            raise NetworkError(
                "systemd not available - required for hotspot management. "
                "Ensure systemd is installed and running.",
                None
            )
        
        # Ensure directories exist
        HOSTAPD_CONF_DIR.mkdir(parents=True, exist_ok=True)
        DNSMASQ_CONF_DIR.mkdir(parents=True, exist_ok=True)
        
        log.debug("hotspot_initialized", interface=self.config.get("interface"))
    
    def _generate_hostapd_config(self) -> str:
        """Generate hostapd configuration file content."""
        interface = self.config.get("interface", "wlan0")
        ssid = self.config.get("ssid", "AX-Traffic-Analyzer")
        password = self.config.get("password", "")
        channel = self.config.get("channel", "auto")
        hide_ssid = self.config.get("hide_ssid", False)
        
        # Validate password length (WPA2 requires >= 8 chars)
        if len(password) < 8:
            raise NetworkError(
                f"WiFi password must be at least 8 characters (WPA2 requirement). "
                f"Found: {len(password)} characters.",
                None
            )
        
        config_lines = [
            f"interface={interface}",
            f"ssid={ssid}",
            f"hw_mode=g",  # 2.4GHz
            f"channel={channel}",
            f"macaddr_acl=0",
            f"auth_algs=1",
            f"ignore_broadcast_ssid={1 if hide_ssid else 0}",
            f"wpa=2",
            f"wpa_passphrase={password}",
            f"wpa_key_mgmt=WPA-PSK",
            f"wpa_pairwise=TKIP",
            f"rsn_pairwise=CCMP",
            f"ieee80211n=1",
            f"ieee80211ac=0",
        ]
        
        return "\n".join(config_lines) + "\n"
    
    def _generate_dnsmasq_config(self) -> str:
        """Generate dnsmasq configuration file content."""
        interface = self.config.get("interface", "wlan0")
        ip_range = self.config.get("ip_range", "192.168.4.0/24")
        
        # Parse IP range and gateway
        base_ip = ip_range.split("/")[0]
        gateway = self.config.get("gateway")
        if not gateway:
            # Calculate from IP range
            parts = base_ip.rsplit(".", 1)
            gateway = f"{parts[0]}.1"
        
        # Get DHCP range
        dhcp_range = self.config.get("dhcp_range", {})
        dhcp_start = dhcp_range.get("start")
        dhcp_end = dhcp_range.get("end")
        if not dhcp_start or not dhcp_end:
            # Calculate from IP range
            parts = base_ip.rsplit(".", 1)
            dhcp_start = f"{parts[0]}.10"
            dhcp_end = f"{parts[0]}.250"
        
        # Get DNS servers
        dns_config = self.config.get("dns", {})
        dns_primary = dns_config.get("primary", "8.8.8.8")
        dns_secondary = dns_config.get("secondary", "8.8.4.4")
        
        config_lines = [
            f"interface={interface}",
            f"bind-interfaces",
            f"dhcp-range={dhcp_start},{dhcp_end},12h",
            f"dhcp-option=option:router,{gateway}",
            f"dhcp-option=option:dns-server,{dns_primary},{dns_secondary}",
            f"server={dns_primary}",
            f"server={dns_secondary}",
            f"no-hosts",
            f"addn-hosts=/etc/ax-traffic/hosts",
            f"log-queries",
            f"log-dhcp",
        ]
        
        return "\n".join(config_lines) + "\n"
    
    def _generate_systemd_service(self, service_name: str, command: List[str], description: str) -> str:
        """Generate systemd service file content."""
        service_file = f"""[Unit]
Description={description}
After=network.target

[Service]
Type=simple
ExecStart={' '.join(command)}
Restart=on-failure
RestartSec=5s
WatchdogSec=30s

[Install]
WantedBy=multi-user.target
"""
        return service_file
    
    def _create_systemd_service(self, service_name: str, service_content: str) -> None:
        """Create systemd service file and enable it."""
        service_file_path = SYSTEMD_SERVICE_DIR / f"{service_name}.service"
        
        # Write service file
        service_file_path.write_text(service_content)
        log.debug("systemd_service_file_created", service=service_name, path=str(service_file_path))
        
        # Reload systemd
        result = subprocess.run(
            ["systemctl", "daemon-reload"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            raise NetworkError(
                f"Failed to reload systemd daemon: {result.stderr}",
                None
            )
        
        log.debug("systemd_daemon_reloaded")
    
    def _setup_interface(self) -> None:
        """Configure network interface for AP mode."""
        interface = self.config.get("interface", "wlan0")
        ip_range = self.config.get("ip_range", "192.168.4.0/24")
        gateway = self.config.get("gateway")
        
        if not gateway:
            # Calculate from IP range
            base_ip = ip_range.split("/")[0]
            parts = base_ip.rsplit(".", 1)
            gateway = f"{parts[0]}.1"
        
        # Check if interface already has IP configured
        result = subprocess.run(
            ["ip", "addr", "show", interface],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            raise NetworkError(
                f"Interface {interface} not found. Ensure WiFi adapter is connected.",
                None
            )
        
        # Check if IP already assigned
        if gateway in result.stdout:
            log.debug("interface_already_configured", interface=interface, ip=gateway)
        else:
            # Configure interface IP
            result = subprocess.run(
                ["ip", "addr", "add", f"{gateway}/24", "dev", interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                raise NetworkError(
                    f"Failed to configure interface {interface}: {result.stderr}",
                    None
                )
            log.debug("interface_configured", interface=interface, ip=gateway)
        
        # Bring interface up
        result = subprocess.run(
            ["ip", "link", "set", interface, "up"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            raise NetworkError(
                f"Failed to bring interface {interface} up: {result.stderr}",
                None
            )
        log.debug("interface_brought_up", interface=interface)
    
    def _is_service_running(self, service_name: str) -> bool:
        """Check if systemd service is running."""
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", service_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    
    def start(self) -> None:
        """Start the WiFi hotspot using systemd."""
        log.info("starting_hotspot", interface=self.config.get("interface"))
        
        # Validate interface state before configuration
        self._setup_interface()
        
        # Generate configuration files
        hostapd_config = self._generate_hostapd_config()
        dnsmasq_config = self._generate_dnsmasq_config()
        
        # Write configuration files
        HOSTAPD_CONF_FILE.write_text(hostapd_config)
        DNSMASQ_CONF_FILE.write_text(dnsmasq_config)
        log.debug("config_files_written")
        
        # Create and start hostapd service
        hostapd_service_content = self._generate_systemd_service(
            HOSTAPD_SERVICE,
            ["/usr/sbin/hostapd", str(HOSTAPD_CONF_FILE)],
            "AX Traffic Analyzer Hotspot (hostapd)"
        )
        self._create_systemd_service(HOSTAPD_SERVICE, hostapd_service_content)
        
        result = subprocess.run(
            ["systemctl", "start", HOSTAPD_SERVICE],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            raise NetworkError(
                f"Failed to start hostapd service: {result.stderr}",
                None
            )
        log.info("hostapd_service_started")
        
        # Create and start dnsmasq service
        dnsmasq_service_content = self._generate_systemd_service(
            DNSMASQ_SERVICE,
            ["/usr/sbin/dnsmasq", "--conf-file", str(DNSMASQ_CONF_FILE)],
            "AX Traffic Analyzer Hotspot (dnsmasq)"
        )
        self._create_systemd_service(DNSMASQ_SERVICE, dnsmasq_service_content)
        
        result = subprocess.run(
            ["systemctl", "start", DNSMASQ_SERVICE],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            # Stop hostapd if dnsmasq fails
            self._stop_service(HOSTAPD_SERVICE)
            raise NetworkError(
                f"Failed to start dnsmasq service: {result.stderr}",
                None
            )
        log.info("dnsmasq_service_started")
        log.info("hotspot_started", interface=self.config.get("interface"))
    
    def _stop_service(self, service_name: str) -> None:
        """Stop a systemd service."""
        result = subprocess.run(
            ["systemctl", "stop", service_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            # Log but don't raise - cleanup should not fail
            log.warning("service_stop_failed", service=service_name, error=result.stderr)
        else:
            log.debug("service_stopped", service=service_name)
    
    def stop(self) -> None:
        """Stop the WiFi hotspot using systemd."""
        log.info("stopping_hotspot")
        self._stop_service(DNSMASQ_SERVICE)
        self._stop_service(HOSTAPD_SERVICE)
        log.info("hotspot_stopped")
    
    def restart(self) -> None:
        """Restart the WiFi hotspot."""
        self.stop()
        import time
        time.sleep(1)
        self.start()
    
    def is_running(self) -> bool:
        """Check if hotspot is running."""
        return self._is_service_running(HOSTAPD_SERVICE) and self._is_service_running(DNSMASQ_SERVICE)
    
    def get_clients(self) -> List[ClientInfo]:
        """Get list of connected clients from dnsmasq leases."""
        clients = []
        if not DNSMASQ_LEASES_FILE.exists():
            return clients
        
        try:
            for line in DNSMASQ_LEASES_FILE.read_text().splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    lease_time = int(parts[0])
                    mac = parts[1]
                    ip = parts[2]
                    hostname = parts[3] if len(parts) > 3 else None
                    clients.append(ClientInfo(
                        mac_address=mac,
                        ip_address=ip,
                        hostname=hostname,
                        connected_at=lease_time
                    ))
        except Exception as e:
            log.warning("failed_to_parse_leases", error=str(e))
        
        return clients
    
    def get_status(self) -> Dict:
        """Get hotspot status information."""
        clients = self.get_clients()
        return {
            "running": self.is_running(),
            "interface": self.config.get("interface"),
            "ssid": self.config.get("ssid"),
            "clients_connected": len(clients),
            "clients": [{"mac": c.mac_address, "ip": c.ip_address, "hostname": c.hostname} for c in clients]
        }

