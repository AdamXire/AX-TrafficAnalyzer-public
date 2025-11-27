"""
@fileoverview Dependency Validation Module
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education
@version 1.0.0
@created 2025-11-18
@modified 2025-11-18

Validates ALL dependencies before any system changes.
This file is part of AX-TrafficAnalyzer Community Edition.
Licensed under MIT License. See LICENSE-COMMUNITY for details.

INNOVATION:
- World-class fail-fast dependency validation
- Actionable error messages with installation instructions
- Version bounds checking for all dependencies
- Platform-specific installation commands
"""

import subprocess
import sys
import shutil
import os
import importlib
import pkg_resources
import socket
import tempfile
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

import psutil  # Fail-fast if missing - validated in PYTHON_PACKAGES

from .platform.detector import get_platform_info, PlatformInfo
from .errors import DependencyValidationError


@dataclass
class DependencyCheck:
    """Result of a dependency check."""
    name: str
    required: bool
    found: bool
    version: Optional[str] = None
    version_required: Optional[str] = None
    path: Optional[str] = None
    error: Optional[str] = None


class DependencyValidator:
    """
    Dependency validator with fail-fast validation.
    
    Validates:
    - System tools (hostapd, dnsmasq, iptables, etc.)
    - Python packages (with version bounds)
    - System capabilities (root, WiFi adapter, etc.)
    - Resources (disk, memory, CPU, I/O)
    - Network capabilities
    - Security policies
    - Network state
    """
    
    # System tools with version requirements
    SYSTEM_TOOLS = {
        "hostapd": "2.9",
        "dnsmasq": "2.80",
        "iptables": "1.8",
        "ip6tables": "1.8",
        "tcpdump": "4.9",
        "tshark": "3.0",
        "redis-server": "6.0",
        "ip": None,  # iproute2 - version check not critical
        "systemctl": None,  # systemd - version check not critical
        "iw": "5.0",  # WiFi management tool (Phase 1)
        # Frontend build tools (conditional - only if ui.enabled)
        "node": "18.0.0",
        "npm": "9.0.0",
        "libsecret-tool": None,  # Linux keyring (Phase 2a, Linux only, skip on WSL2)
    }
    
    # NTP daemons (either one is acceptable)
    NTP_DAEMONS = ["ntpd", "chronyd"]
    
    # Python packages with version bounds
    PYTHON_PACKAGES = {
        "mitmproxy": ("10.0.0", "11.0.0"),
        "fastapi": ("0.104.0", "1.0.0"),
        "scapy": ("2.5.0", "3.0.0"),
        "sqlalchemy": ("2.0.0", "3.0.0"),
        "redis": ("4.5.0", "5.0.0"),
        "psutil": ("5.9.0", "6.0.0"),
        "uvicorn": ("0.20.0", "1.0.0"),  # ASGI server (Phase 1)
        "structlog": None,  # Any recent version
        "pydantic": None,  # Any recent version
        "keyring": ("24.0.0", "25.0.0"),  # Secure key storage (Phase 2a)
        "qrcode": ("7.4.0", "8.0.0"),  # QR code generation (Phase 2a)
        "Pillow": ("10.0.0", "11.0.0"),  # Image processing for QR codes (Phase 2a)
        "aioredis": ("2.0.0", "3.0.0"),  # Async Redis client (Phase 2a)
        "python-libpcap": ("0.5.0", "1.0.0"),  # Fast PCAP writing (Phase 2b)
        "alembic": ("1.12.0", "2.0.0"),  # Database migrations (Phase 3)
        "python-jose": ("3.3.0", "4.0.0"),  # JWT tokens (Phase 3, imports as 'jose')
        "passlib": ("1.7.4", "2.0.0"),  # Password hashing (Phase 3)
        "aiosqlite": ("0.19.0", "1.0.0"),  # Async SQLite driver (Phase 3)
        # Phase 5: Analysis Features
        "reportlab": ("4.0.0", "5.0.0"),  # PDF report generation
        "sklearn": ("1.3.0", "2.0.0"),  # ML traffic classification (scikit-learn imports as sklearn)
        "requests": ("2.31.0", "3.0.0"),  # HTTP client for threat intel APIs
        "magic": ("0.4.0", "1.0.0"),  # File type detection (python-magic imports as magic)
        "yaml": ("6.0", "7.0"),  # YAML parser for rule engine (PyYAML imports as yaml)
        "numpy": ("1.24.0", "2.0.0"),  # Numerical computing for ML
        "pandas": ("2.0.0", "3.0.0"),  # Data analysis for traffic stats
    }
    
    def __init__(self, platform_info: Optional[PlatformInfo] = None):
        self.platform_info = platform_info or get_platform_info()
        self._checked_tools: Dict[str, DependencyCheck] = {}
        self._checked_packages: Dict[str, DependencyCheck] = {}
    
    def validate_all(self, mode: str = "production", config: dict = None) -> None:
        """
        Validate all dependencies (fail-fast).
        
        Args:
            mode: "production" or "dev" - affects resource validation behavior
            config: Optional config dict for conditional validation
        
        Raises:
            DependencyValidationError: If any required dependency is missing
        """
        print("🔍 Validating system dependencies...")
        
        # 1. System tools (skip in dev mode if configured)
        if config and config.get("skip_system_tools", False):
            print("  ├─ System tools: SKIPPED (dev mode)")
        else:
            print("  ├─ Checking system tools...")
            self._validate_system_tools(config or {})
            print("  ├─ System tools: ✓")
        
        # 2. Python packages (skip in dev mode if configured)
        if config and config.get("skip_system_tools", False):
            print("  ├─ Python packages: SKIPPED (dev mode)")
        else:
            print("  ├─ Checking Python packages...")
            self._validate_python_packages(config or {})
            print("  ├─ Python packages: ✓")
        
        # Skip remaining checks in dev mode if configured
        if config and config.get("skip_system_tools", False):
            print("  ├─ System capabilities: SKIPPED (dev mode)")
            print("  ├─ Resources: SKIPPED (dev mode)")
            print("  ├─ Network capabilities: SKIPPED (dev mode)")
            print("  ├─ Security policies: SKIPPED (dev mode)")
            print("  └─ Network state: SKIPPED (dev mode)")
        else:
            # 3. System capabilities (root check)
            print("  ├─ Checking system capabilities...")
            self._validate_system_capabilities()
            print("  ├─ System capabilities: ✓")
            
            # 4. Resources (NEW)
            print(f"  ├─ Checking resources (mode: {mode})...")
            self._validate_resources(mode)
            print(f"  ├─ Resources: ✓")
            
            # 5. Network capabilities (NEW)
            print("  ├─ Checking network capabilities...")
            self._validate_network_capabilities()
            print("  ├─ Network capabilities: ✓")
            
            # 6. Security policies (NEW)
            print("  ├─ Checking security policies...")
            self._validate_security_policies()
            print("  ├─ Security policies: ✓")
            
            # 7. Network state (NEW)
            print("  └─ Checking network state...")
            self._validate_network_state()
        print("  └─ Network state: ✓")
        
        print("✅ All dependencies validated successfully!")
    
    def validate_directories(self, config: dict) -> None:
        """
        Validate and create required directories.
        
        Should be called after config is loaded.
        
        Args:
            config: Configuration dictionary
            
        Raises:
            ConfigurationError: If directory creation fails or is not writable
        """
        from pathlib import Path
        import os
        from .errors import ConfigurationError
        from .logging import get_logger
        
        log = get_logger(__name__)
        
        # Get directories from config or use defaults
        required_dirs = [
            "./certs",
            "./captures",
            "./captures/raw",
            "./captures/decrypted",
            "./logs",
        ]
        
        # Add pcap_dir from config if specified
        if "storage" in config and "pcap_dir" in config["storage"]:
            pcap_dir = config["storage"]["pcap_dir"]
            if pcap_dir not in required_dirs:
                required_dirs.append(pcap_dir)
        
        log.debug("validating_directories", count=len(required_dirs))
        
        for dir_path in required_dirs:
            path = Path(dir_path)
            try:
                if not path.exists():
                    path.mkdir(parents=True, mode=0o700)
                    log.info("directory_created", path=dir_path, mode="0700")
                else:
                    # Ensure correct permissions
                    os.chmod(path, 0o700)
                    log.debug("directory_permissions_set", path=dir_path, mode="0700")
                
                # Verify writable
                if not os.access(path, os.W_OK):
                    raise ConfigurationError(
                        f"Directory not writable: {dir_path}",
                        None
                    )
                log.debug("directory_validated", path=dir_path)
            except Exception as e:
                raise ConfigurationError(
                    f"Failed to create or validate directory '{dir_path}': {e}",
                    None
                )
        
        log.info("directories_validated", count=len(required_dirs))
    
    def _validate_system_tools(self, config: dict = None) -> None:
        """Validate all required system tools."""
        for tool, min_version in self.SYSTEM_TOOLS.items():
            # Skip frontend tools if UI disabled
            if tool in ["node", "npm"]:
                ui_enabled = config.get("ui", {}).get("enabled", False) if config else False
                if not ui_enabled:
                    log.debug("tool_validation_skipped", tool=tool, reason="ui_disabled")
                    continue
            
            # Skip libsecret-tool on WSL2 (uses Windows DPAPI instead)
            if tool == "libsecret-tool" and self.platform_info.is_wsl2:
                log.debug("skipping_libsecret_on_wsl2", tool=tool)
                continue
            
            check = self._check_system_tool(tool, min_version)
            self._checked_tools[tool] = check
            
            if not check.found:
                # libsecret-tool is optional (warning only)
                if tool == "libsecret-tool":
                    log.warning("libsecret_tool_not_found", 
                               note="Keyring will use default backend")
                else:
                    self._fail_fast_tool(tool, min_version, check)
        
        # Check for NTP daemon (either ntpd or chronyd)
        ntp_found = False
        for ntp_daemon in self.NTP_DAEMONS:
            if shutil.which(ntp_daemon):
                ntp_found = True
                break
        
        if not ntp_found:
            self._fail_fast_tool(
                "ntpd or chronyd",
                "any recent version",
                DependencyCheck(
                    name="ntpd/chronyd",
                    required=True,
                    found=False,
                    error="Neither ntpd nor chronyd found"
                )
            )
    
    def _check_system_tool(self, tool: str, min_version: Optional[str]) -> DependencyCheck:
        """Check if a system tool is available."""
        path = shutil.which(tool)
        
        if not path:
            return DependencyCheck(
                name=tool,
                required=True,
                found=False,
                version_required=min_version,
                error=f"{tool} not found in PATH"
            )
        
        # Get version if required
        version = None
        if min_version:
            version = self._get_tool_version(tool)
            if version and not self._version_meets_requirement(version, min_version):
                return DependencyCheck(
                    name=tool,
                    required=True,
                    found=True,
                    version=version,
                    version_required=min_version,
                    path=path,
                    error=f"Version {version} does not meet requirement >= {min_version}"
                )
        
        return DependencyCheck(
            name=tool,
            required=True,
            found=True,
            version=version,
            version_required=min_version,
            path=path
        )
    
    def _get_tool_version(self, tool: str) -> Optional[str]:
        """Get version of a system tool."""
        try:
            # Try --version first
            result = subprocess.run(
                [tool, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Extract version from output (first line, first number)
                import re
                match = re.search(r'(\d+\.\d+(?:\.\d+)?)', result.stdout)
                if match:
                    return match.group(1)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Try -V for some tools
        try:
            result = subprocess.run(
                [tool, "-V"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                import re
                match = re.search(r'(\d+\.\d+(?:\.\d+)?)', result.stdout)
                if match:
                    return match.group(1)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return None
    
    def _version_meets_requirement(self, version: str, min_version: str) -> bool:
        """Check if version meets minimum requirement."""
        try:
            v_parts = [int(x) for x in version.split(".")]
            min_parts = [int(x) for x in min_version.split(".")]
            
            # Pad to same length
            max_len = max(len(v_parts), len(min_parts))
            v_parts.extend([0] * (max_len - len(v_parts)))
            min_parts.extend([0] * (max_len - len(min_parts)))
            
            return v_parts >= min_parts
        except (ValueError, IndexError):
            return False
    
    def _should_validate_package(self, package_name: str, config: dict) -> bool:
        """
        Determine if package should be validated based on config.
        
        Args:
            package_name: Package name
            config: Configuration dict
            
        Returns:
            True if package should be validated
        """
        # Phase 3 database packages - only if database enabled
        phase3_db_packages = ["alembic", "aiosqlite", "python-jose", "passlib"]
        if package_name in phase3_db_packages:
            db_enabled = config.get("database", {}).get("enabled", True)
            if not db_enabled:
                log.debug("package_validation_skipped", package=package_name, reason="database_disabled")
                return False
        
        # python-libpcap only if capture enabled
        if package_name == "python-libpcap":
            capture_enabled = config.get("capture", {}).get("enabled", False)
            if not capture_enabled:
                log.debug("package_validation_skipped", package=package_name, reason="capture_disabled")
                return False
        
        return True  # Validate all others
    
    def _validate_python_packages(self, config: dict = None) -> None:
        """Validate all required Python packages."""
        config = config or {}
        for package, version_bounds in self.PYTHON_PACKAGES.items():
            # Skip validation if feature disabled
            if not self._should_validate_package(package, config):
                continue
            check = self._check_python_package(package, version_bounds)
            self._checked_packages[package] = check
            
            if not check.found:
                self._fail_fast_package(package, version_bounds, check)
            elif check.error:  # Version mismatch
                self._fail_fast_package(package, version_bounds, check)
    
    def _check_python_package(
        self,
        package: str,
        version_bounds: Optional[Tuple[str, str]]
    ) -> DependencyCheck:
        """Check if a Python package is installed with correct version."""
        try:
            dist = pkg_resources.get_distribution(package)
            version = dist.version
            
            if version_bounds:
                min_version, max_version = version_bounds
                if not self._version_in_bounds(version, min_version, max_version):
                    return DependencyCheck(
                        name=package,
                        required=True,
                        found=True,
                        version=version,
                        version_required=f">= {min_version}, < {max_version}",
                        error=f"Version {version} outside required range"
                    )
            
            return DependencyCheck(
                name=package,
                required=True,
                found=True,
                version=version,
                version_required=f">= {version_bounds[0]}, < {version_bounds[1]}" if version_bounds else None
            )
        except pkg_resources.DistributionNotFound:
            return DependencyCheck(
                name=package,
                required=True,
                found=False,
                version_required=f">= {version_bounds[0]}, < {version_bounds[1]}" if version_bounds else None,
                error=f"{package} not installed"
            )
    
    def _version_in_bounds(self, version: str, min_version: str, max_version: str) -> bool:
        """Check if version is within bounds."""
        try:
            v = self._parse_version(version)
            min_v = self._parse_version(min_version)
            max_v = self._parse_version(max_version)
            
            return min_v <= v < max_v
        except (ValueError, IndexError):
            return False
    
    def _parse_version(self, version_str: str) -> Tuple[int, ...]:
        """Parse version string to tuple."""
        parts = []
        for part in version_str.split("."):
            try:
                parts.append(int(part))
            except ValueError:
                break
        return tuple(parts)
    
    def _validate_system_capabilities(self) -> None:
        """Validate basic system capabilities."""
        # Check root/sudo access - FAIL IMMEDIATELY if not root
        if os.geteuid() != 0:
            self._fail_fast_capability(
                "Root access",
                "Required for network operations (iptables, hostapd, dnsmasq)",
                "Run with sudo: sudo python -m ax_traffic"
            )
        
        # Check SQLite version (Phase 3) - Need 3.35.0+ for JSON support
        try:
            import sqlite3
            version_info = sqlite3.sqlite_version_info
            if version_info < (3, 35, 0):
                self._fail_fast_capability(
                    "SQLite version",
                    f"SQLite {sqlite3.sqlite_version} too old. Minimum required: 3.35.0 (for JSON support)",
                    f"Upgrade SQLite: sudo apt install sqlite3"
                )
            log.debug("sqlite_version_validated", version=sqlite3.sqlite_version)
        except ImportError:
            # sqlite3 is part of Python stdlib, should always be available
            log.warning("sqlite3_module_not_available", note="This should not happen")
    
    def _validate_resources(self, mode: str = "production") -> None:
        """Validate system resources."""
        # 1. Disk space check
        try:
            stat = os.statvfs('/')
            available_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
            print(f"    ├─ Disk space: {available_gb:.2f}GB available")
            if available_gb < 1.0:
                self._fail_fast_resource("Disk space", ">= 1GB", f"{available_gb:.2f}GB", 
                                          "Free up disk space or use different partition")
        except Exception as e:
            print(f"    ⚠️  Warning: Could not check disk space: {e}")
        
        # 2. Disk I/O speed check (write test)
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                test_file = tmp.name
                test_size = 10 * 1024 * 1024  # 10MB
                test_data = b'0' * (1024 * 1024)  # 1MB chunks
                
                start_time = time.time()
                for _ in range(10):
                    tmp.write(test_data)
                tmp.flush()
                os.fsync(tmp.fileno())
                elapsed = time.time() - start_time
                
                speed_mbps = (test_size / (1024 * 1024)) / elapsed
                print(f"    ├─ Disk I/O speed: {speed_mbps:.2f}MB/s")
                
                if speed_mbps < 10.0:
                    self._fail_fast_resource("Disk write speed", ">= 10MB/s", f"{speed_mbps:.2f}MB/s",
                                              "Slow disk will affect PCAP export performance. Use faster storage.")
                os.unlink(test_file)
        except Exception as e:
            print(f"    ⚠️  Warning: Could not check disk I/O speed: {e}")
        
        # 3. Memory check
        try:
            mem = psutil.virtual_memory()
            mem_gb = mem.total / (1024**3)
            print(f"    ├─ Memory: {mem_gb:.2f}GB total")
            if mem_gb < 2.0:
                if mode == "production":
                    self._fail_fast_resource("Memory", ">= 2GB", f"{mem_gb:.2f}GB",
                                              "Increase system memory")
                else:
                    # WARN in dev mode
                    self._warn_resource("Memory", f"{mem_gb:.2f}GB", "< 2GB recommended")
        except Exception as e:
            print(f"    ⚠️  Warning: Could not check memory: {e}")
        
        # 4. CPU cores check
        try:
            cpu_count = psutil.cpu_count(logical=False)
            print(f"    └─ CPU cores: {cpu_count}")
            if cpu_count < 2:
                if mode == "production":
                    self._fail_fast_resource("CPU cores", ">= 2", str(cpu_count),
                                              "Use system with more CPU cores")
                else:
                    self._warn_resource("CPU cores", str(cpu_count), "< 2 recommended")
        except Exception as e:
            print(f"    ⚠️  Warning: Could not check CPU: {e}")
    
    def _validate_network_capabilities(self) -> None:
        """Validate network capabilities for hotspot creation."""
        # 1. Check for wireless interface
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=5)
        if result.returncode != 0 or 'Interface' not in result.stdout:
            # Try alternative: check for wlan interfaces
            result2 = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=5)
            if 'wlan' not in result2.stdout and 'wifi' not in result2.stdout.lower():
                self._fail_fast_capability("WiFi adapter", "Required for hotspot creation",
                                            "Ensure WiFi adapter is connected and recognized by system")
        else:
            print("    ├─ WiFi adapter: ✓")
        
        # 2. Check AP mode support
        result = subprocess.run(['iw', 'list'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            if 'AP' in result.stdout:
                print("    ├─ AP mode support: ✓")
            else:
                self._fail_fast_capability("AP mode support", "WiFi adapter must support AP mode",
                                            "Use compatible WiFi adapter")
        else:
            print("    ⚠️  Warning: Could not check AP mode support (iw list failed)")
        
        # 3. Check kernel modules
        result = subprocess.run(['lsmod'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for module in ['mac80211', 'cfg80211']:
                if module not in result.stdout:
                    self._fail_fast_capability(f"Kernel module {module}", "Required for WiFi operations",
                                                f"Load module: sudo modprobe {module}")
            print("    ├─ Kernel modules: ✓")
        else:
            print("    ⚠️  Warning: Could not check kernel modules")
        
        # 4. Check IP forwarding
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                if f.read().strip() != '1':
                    # This can be enabled at runtime, so just warn
                    self._warn_capability("IP forwarding", "disabled", "Will enable during startup")
                else:
                    print("    ├─ IP forwarding: ✓")
        except FileNotFoundError:
            print("    ⚠️  Warning: Could not check IP forwarding")
        
        # 5. Check network namespaces support
        result = subprocess.run(['ip', 'netns', 'list'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("    └─ Network namespaces: ✓")
        else:
            self._fail_fast_capability("Network namespaces", "Required for isolation",
                                        "Kernel networking support missing")
    
    def _validate_security_policies(self) -> None:
        """Validate security policies (SELinux, AppArmor)."""
        # 1. Check SELinux
        try:
            result = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                mode = result.stdout.strip()
                if mode == 'Enforcing':
                    # Check for required capabilities (simplified check)
                    # In production, would check for specific policies
                    print("    ├─ SELinux: Enforcing mode detected")
                    self._warn_security("SELinux", "enforcing", "Ensure required policies are installed")
                elif mode == 'Permissive':
                    self._warn_security("SELinux", "permissive", "Not enforcing")
                else:
                    print("    ├─ SELinux: Disabled")
        except FileNotFoundError:
            print("    ├─ SELinux: Not installed")
        
        # 2. Check AppArmor
        try:
            result = subprocess.run(['aa-status'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and 'profiles are loaded' in result.stdout:
                # Check if ax-traffic profile exists
                if 'ax-traffic' not in result.stdout:
                    print("    └─ AppArmor: Active (ax-traffic profile not found)")
                    self._warn_security("AppArmor", "active without profile", 
                                         "Install profile or disable AppArmor for testing")
                else:
                    print("    └─ AppArmor: Active with ax-traffic profile ✓")
            else:
                print("    └─ AppArmor: Not active")
        except FileNotFoundError:
            print("    └─ AppArmor: Not installed")
    
    def _validate_network_state(self) -> None:
        """Validate network state before startup."""
        # 1. Check for existing iptables rules
        result = subprocess.run(['iptables', '-L', 'AX_TRAFFIC_ANALYZER', '-n'],
                               capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            # Chain exists
            self._fail_fast_network("iptables conflict", 
                                    "AX_TRAFFIC_ANALYZER chain already exists",
                                    "Run cleanup: sudo iptables -F AX_TRAFFIC_ANALYZER && sudo iptables -X AX_TRAFFIC_ANALYZER")
        else:
            print("    ├─ iptables: No existing AX_TRAFFIC_ANALYZER chain ✓")
        
        # 2. Check port availability (API: 8443, mitmproxy: 8080, metrics: 9090)
        import socket
        ports_available = True
        required_ports = [8080, 8443, 9090]  # mitmproxy, API, metrics
        for port in required_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            if result == 0:
                port_name = "mitmproxy" if port == 8080 else ("API" if port == 8443 else "metrics")
                self._fail_fast_network(f"Port {port} ({port_name})", f"Port {port} already in use",
                                        f"Stop service using port {port}: sudo lsof -i :{port}")
                ports_available = False
        if ports_available:
            print("    ├─ Ports (API: 8443, mitmproxy: 8080, metrics: 9090): Available ✓")
        
        # 3. Check IP range conflicts
        result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            if '192.168.4.' in result.stdout:
                self._fail_fast_network("IP range conflict", 
                                        "192.168.4.0/24 already in use",
                                        "Change hotspot IP range in config.json (when config system is implemented)")
            else:
                print("    └─ IP range: No conflicts ✓")
        else:
            print("    └─ IP range: Could not check")
    
    def _fail_fast_tool(
        self,
        tool: str,
        version_req: str,
        check: DependencyCheck
    ) -> None:
        """Fail-fast for missing system tool."""
        platform_str = f"{self.platform_info.distribution} {self.platform_info.distribution_version}"
        
        # Get installation command based on distribution
        install_cmd = self._get_install_command(tool)
        
        error_msg = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
❌ CRITICAL ERROR: Required dependency missing
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

COMPONENT:    {tool}
VERSION REQ:  >= {version_req}
FOUND:        {check.error or "Not installed"}
PLATFORM:     Linux ({platform_str})
REQUIRED FOR: {self._get_tool_purpose(tool)}

SOLUTION:
  Run the following commands:

    {install_cmd}

  Then run AX-TrafficAnalyzer again.

DOCUMENTATION:
  https://docs.ax-traffic-analyzer.com/installation/dependencies

ALTERNATIVE:
  None - {tool} is a core dependency and cannot be substituted.

If you believe {tool} is installed but not detected:
  1. Check if it's in your PATH: which {tool}
  2. Set custom path via env: export {tool.upper()}_PATH=/path/to/{tool}
  3. Report this issue: https://github.com/ax/issues

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        raise DependencyValidationError(error_msg)
    
    def _fail_fast_package(
        self,
        package: str,
        version_bounds: Optional[Tuple[str, str]],
        check: DependencyCheck
    ) -> None:
        """Fail-fast for missing or incorrect Python package."""
        version_req = f">= {version_bounds[0]}, < {version_bounds[1]}" if version_bounds else "any recent version"
        
        if not check.found:
            install_cmd = f"pip install '{package}>={version_bounds[0]},<{version_bounds[1]}'" if version_bounds else f"pip install {package}"
        else:
            install_cmd = f"pip install --upgrade '{package}>={version_bounds[0]},<{version_bounds[1]}'"
        
        error_msg = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
❌ CRITICAL ERROR: Python package issue
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

COMPONENT:    {package}
VERSION REQ:  {version_req}
FOUND:        {check.error or (check.version or "Not installed")}
PLATFORM:     Python {self.platform_info.python_version}

SOLUTION:
  Run the following command:

    {install_cmd}

  Then run AX-TrafficAnalyzer again.

DOCUMENTATION:
  https://docs.ax-traffic-analyzer.com/installation/dependencies

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        raise DependencyValidationError(error_msg)
    
    def _fail_fast_capability(
        self,
        capability: str,
        reason: str,
        solution: str
    ) -> None:
        """Fail-fast for missing system capability."""
        error_msg = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
❌ CRITICAL ERROR: System capability missing
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CAPABILITY:   {capability}
REASON:      {reason}
PLATFORM:    {self.platform_info.distribution} {self.platform_info.distribution_version}

SOLUTION:
  {solution}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        raise DependencyValidationError(error_msg)
    
    def _fail_fast_resource(self, resource: str, required: str, found: str, solution: str) -> None:
        """Fail-fast for insufficient resources."""
        error_msg = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
❌ CRITICAL ERROR: Insufficient system resources
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RESOURCE:    {resource}
REQUIRED:    {required}
FOUND:       {found}
PLATFORM:    {self.platform_info.distribution} {self.platform_info.distribution_version}

SOLUTION:
  {solution}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        raise DependencyValidationError(error_msg)
    
    def _warn_resource(self, resource: str, found: str, recommendation: str) -> None:
        """Warning for resources (dev mode)."""
        print(f"    ⚠️  Warning: {resource} = {found} ({recommendation})")
    
    def _fail_fast_security(self, component: str, reason: str, solution: str) -> None:
        """Fail-fast for security policy issues."""
        error_msg = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
❌ CRITICAL ERROR: Security policy issue
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

COMPONENT:   {component}
REASON:      {reason}
PLATFORM:    {self.platform_info.distribution} {self.platform_info.distribution_version}

SOLUTION:
  {solution}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        raise DependencyValidationError(error_msg)
    
    def _warn_security(self, component: str, status: str, note: str) -> None:
        """Warning for security policies."""
        print(f"    ⚠️  Warning: {component} is {status} ({note})")
    
    def _fail_fast_network(self, issue: str, reason: str, solution: str) -> None:
        """Fail-fast for network state issues."""
        error_msg = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
❌ CRITICAL ERROR: Network state conflict
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ISSUE:       {issue}
REASON:      {reason}
PLATFORM:    {self.platform_info.distribution} {self.platform_info.distribution_version}

SOLUTION:
  {solution}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        raise DependencyValidationError(error_msg)
    
    def _warn_capability(self, capability: str, status: str, note: str) -> None:
        """Warning for capabilities that can be fixed at runtime."""
        print(f"    ⚠️  Warning: {capability} is {status} ({note})")
    
    def _get_install_command(self, tool: str) -> str:
        """Get installation command based on distribution."""
        dist = self.platform_info.distribution.lower()
        
        if dist in ["ubuntu", "debian"]:
            return f"sudo apt-get update\n    sudo apt-get install {tool}"
        elif dist in ["fedora", "rhel", "centos"]:
            return f"sudo dnf install {tool}"
        elif dist == "arch":
            return f"sudo pacman -S {tool}"
        else:
            return f"Install {tool} using your distribution's package manager"
    
    def _get_tool_purpose(self, tool: str) -> str:
        """Get purpose description for a tool."""
        purposes = {
            "hostapd": "WiFi hotspot creation",
            "dnsmasq": "DHCP and DNS server",
            "iptables": "IPv4 packet filtering",
            "ip6tables": "IPv6 packet filtering",
            "tcpdump": "Raw packet capture",
            "tshark": "Protocol dissection",
            "redis-server": "Message queue backend",
            "ntpd": "Network time synchronization",
            "chronyd": "Network time synchronization",
            "ip": "Network interface management",
            "systemctl": "Service management",
        }
        return purposes.get(tool, "System operation")

