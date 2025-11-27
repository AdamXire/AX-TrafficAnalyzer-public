"""
AX-TrafficAnalyzer - Airmon-ng Manager
Copyright © 2025 MMeTech (Macau) Ltd.

Manages WiFi interface monitor mode using airmon-ng.
FAIL-FAST: Raises error if airmon-ng not available.
"""

import subprocess
import shutil
import re
from typing import Optional
from dataclasses import dataclass
import structlog

log = structlog.get_logger(__name__)


@dataclass
class WirelessInterface:
    """Wireless interface information."""
    name: str
    driver: str
    chipset: str
    monitor_mode: bool = False
    monitor_interface: Optional[str] = None


class AirmonManagerError(Exception):
    """Airmon manager error with actionable message."""
    pass


class AirmonManager:
    """
    Manages WiFi monitor mode using airmon-ng.
    
    FAIL-FAST: Constructor raises if airmon-ng not found.
    """
    
    def __init__(self, interface: str):
        """
        Initialize airmon manager.
        
        Args:
            interface: WiFi interface name (e.g., wlan0, wlan1)
            
        Raises:
            AirmonManagerError: If airmon-ng not found or interface invalid
        """
        log.info("[AIRMON] Initializing AirmonManager", interface=interface)
        
        # FAIL-FAST: Check airmon-ng exists
        if not shutil.which("airmon-ng"):
            raise AirmonManagerError(
                "airmon-ng not found in PATH.\n"
                "Install with: sudo apt install aircrack-ng\n"
                "Or disable wireless capture in config.json"
            )
        
        # FAIL-FAST: Check iwconfig exists
        if not shutil.which("iwconfig"):
            raise AirmonManagerError(
                "iwconfig not found in PATH.\n"
                "Install with: sudo apt install wireless-tools"
            )
        
        self.interface = interface
        self.monitor_interface: Optional[str] = None
        self._original_interface = interface
        
        # Validate interface exists
        if not self._interface_exists(interface):
            raise AirmonManagerError(
                f"Interface '{interface}' not found.\n"
                f"Available interfaces: {self._list_interfaces()}"
            )
        
        log.info("[AIRMON] AirmonManager initialized", interface=interface)
    
    def _interface_exists(self, interface: str) -> bool:
        """Check if interface exists."""
        try:
            result = subprocess.run(
                ["iwconfig", interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception as e:
            log.warning("[AIRMON] Interface check failed", error=str(e))
            return False
    
    def _list_interfaces(self) -> list[str]:
        """List available wireless interfaces."""
        try:
            result = subprocess.run(
                ["iwconfig"],
                capture_output=True,
                text=True,
                timeout=5
            )
            interfaces = []
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    iface = line.split()[0]
                    interfaces.append(iface)
            return interfaces
        except Exception:
            return []
    
    def start_monitor_mode(self) -> str:
        """
        Enable monitor mode on the interface.
        
        Returns:
            Monitor interface name (e.g., wlan0mon)
            
        Raises:
            AirmonManagerError: If monitor mode fails
        """
        log.info("[AIRMON] Starting monitor mode", interface=self.interface)
        
        try:
            # Kill interfering processes
            log.debug("[AIRMON] Killing interfering processes")
            subprocess.run(
                ["sudo", "airmon-ng", "check", "kill"],
                capture_output=True,
                timeout=10
            )
            
            # Start monitor mode
            result = subprocess.run(
                ["sudo", "airmon-ng", "start", self.interface],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                raise AirmonManagerError(
                    f"Failed to start monitor mode: {result.stderr}\n"
                    "Ensure you have root privileges and interface supports monitor mode."
                )
            
            # Parse monitor interface name from output
            # Usually "wlan0mon" or similar
            monitor_iface = self._parse_monitor_interface(result.stdout)
            if not monitor_iface:
                # Try common naming convention
                monitor_iface = f"{self.interface}mon"
                if not self._interface_exists(monitor_iface):
                    raise AirmonManagerError(
                        f"Could not determine monitor interface name.\n"
                        f"Output: {result.stdout}"
                    )
            
            self.monitor_interface = monitor_iface
            log.info("[AIRMON] Monitor mode started", monitor_interface=monitor_iface)
            return monitor_iface
            
        except subprocess.TimeoutExpired:
            raise AirmonManagerError("airmon-ng timed out. Check interface.")
        except Exception as e:
            raise AirmonManagerError(f"Monitor mode failed: {e}")
    
    def _parse_monitor_interface(self, output: str) -> Optional[str]:
        """Parse monitor interface name from airmon-ng output."""
        # Look for patterns like "wlan0mon" or "(monitor mode enabled on wlan0mon)"
        patterns = [
            r'\(monitor mode (?:vif )?enabled(?: on)? (\w+)\)',
            r'(\w+mon)\s+(?:IEEE|wlan)',
            r'monitor mode enabled on (\w+)'
        ]
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def stop_monitor_mode(self) -> None:
        """
        Disable monitor mode and restore interface.
        """
        if not self.monitor_interface:
            log.warning("[AIRMON] No monitor interface to stop")
            return
        
        log.info("[AIRMON] Stopping monitor mode", monitor_interface=self.monitor_interface)
        
        try:
            result = subprocess.run(
                ["sudo", "airmon-ng", "stop", self.monitor_interface],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                log.warning("[AIRMON] Stop failed", stderr=result.stderr)
            
            self.monitor_interface = None
            log.info("[AIRMON] Monitor mode stopped")
            
        except Exception as e:
            log.error("[AIRMON] Failed to stop monitor mode", error=str(e))
    
    def get_interface_info(self) -> WirelessInterface:
        """Get interface information."""
        try:
            result = subprocess.run(
                ["airmon-ng"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Parse output for interface info
            for line in result.stdout.split('\n'):
                if self.interface in line or (self.monitor_interface and self.monitor_interface in line):
                    parts = line.split()
                    if len(parts) >= 3:
                        return WirelessInterface(
                            name=parts[1] if len(parts) > 1 else self.interface,
                            driver=parts[2] if len(parts) > 2 else "unknown",
                            chipset=parts[3] if len(parts) > 3 else "unknown",
                            monitor_mode=self.monitor_interface is not None,
                            monitor_interface=self.monitor_interface
                        )
            
            return WirelessInterface(
                name=self.interface,
                driver="unknown",
                chipset="unknown",
                monitor_mode=self.monitor_interface is not None,
                monitor_interface=self.monitor_interface
            )
        except Exception as e:
            log.warning("[AIRMON] Failed to get interface info", error=str(e))
            return WirelessInterface(
                name=self.interface,
                driver="unknown",
                chipset="unknown"
            )
    
    async def start(self) -> None:
        """Async start for orchestrator compatibility."""
        self.start_monitor_mode()
    
    async def stop(self) -> None:
        """Async stop for orchestrator compatibility."""
        self.stop_monitor_mode()

