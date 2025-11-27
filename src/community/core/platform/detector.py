"""
@fileoverview Platform Detection Module
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education
@version 1.0.0
@created 2025-11-18
@modified 2025-11-18

Detects platform (Linux/WSL2/Windows) and system capabilities.
This file is part of AX-TrafficAnalyzer Community Edition.
Licensed under MIT License. See LICENSE-COMMUNITY for details.

INNOVATION:
- World-class platform detection with WSL2 support
- Fail-fast validation with actionable error messages
- Comprehensive system capability detection
"""

import os
import platform
import sys
import subprocess
import re
from dataclasses import dataclass
from typing import Optional, Tuple
from pathlib import Path

from ..errors import PlatformDetectionError


@dataclass
class PlatformInfo:
    """Platform information dataclass."""
    os: str                      # "Linux" or "Windows"
    is_wsl2: bool               # True if WSL2
    is_native_linux: bool       # True if native Linux
    is_native_windows: bool     # True if native Windows (unsupported)
    wsl_distro: Optional[str]   # WSL distribution name
    kernel_version: str         # Kernel version
    architecture: str           # x86_64, arm64, etc.
    distribution: str           # Ubuntu, Debian, Fedora, etc.
    distribution_version: str   # 22.04, 11, etc.
    python_version: str         # Python version string
    python_version_tuple: Tuple[int, int, int]  # (3, 11, 0)


class PlatformDetector:
    """
    Platform detection with fail-fast validation.
    
    Detects:
    - Operating system (Linux/Windows)
    - WSL2 environment
    - Distribution information
    - Kernel version
    - Python version
    """
    
    MIN_PYTHON_VERSION = (3, 10, 0)
    MAX_PYTHON_VERSION = (3, 13, 0)  # Exclusive upper bound
    MIN_KERNEL_VERSION = (5, 4, 0)
    
    def __init__(self):
        self._platform_info: Optional[PlatformInfo] = None
    
    def detect(self) -> PlatformInfo:
        """
        Detect platform information.
        
        Returns:
            PlatformInfo: Platform information
            
        Raises:
            PlatformDetectionError: If platform is unsupported or detection fails
        """
        if self._platform_info is None:
            self._platform_info = self._detect_platform()
        return self._platform_info
    
    def _detect_platform(self) -> PlatformInfo:
        """Internal platform detection logic."""
        print("🔍 Detecting platform...")
        
        # Detect OS
        os_type = platform.system()
        print(f"  ├─ OS type: {os_type}")
        
        # Detect Python version
        python_version = sys.version_info
        python_version_str = f"{python_version.major}.{python_version.minor}.{python_version.micro}"
        print(f"  ├─ Python version: {python_version_str}")
        
        # Validate Python version
        if python_version < self.MIN_PYTHON_VERSION:
            self._fail_fast(
                component="Python",
                version_req=f">= {self.MIN_PYTHON_VERSION[0]}.{self.MIN_PYTHON_VERSION[1]}",
                found=f"{python_version.major}.{python_version.minor}.{python_version.micro}",
                reason="Python version too old",
                solution=f"Upgrade Python to {self.MIN_PYTHON_VERSION[0]}.{self.MIN_PYTHON_VERSION[1]}+"
            )
        
        if python_version >= self.MAX_PYTHON_VERSION:
            self._fail_fast(
                component="Python",
                version_req=f"< {self.MAX_PYTHON_VERSION[0]}.{self.MAX_PYTHON_VERSION[1]}",
                found=f"{python_version.major}.{python_version.minor}.{python_version.micro}",
                reason="Python version too new (not yet tested)",
                solution=f"Use Python {self.MIN_PYTHON_VERSION[0]}.{self.MIN_PYTHON_VERSION[1]} to {self.MAX_PYTHON_VERSION[0]}.{self.MAX_PYTHON_VERSION[1]-1}"
            )
        
        # Detect architecture
        architecture = platform.machine()
        print(f"  ├─ Architecture: {architecture}")
        
        if os_type == "Windows":
            # Check if WSL2
            is_wsl2, wsl_distro = self._detect_wsl2()
            print(f"  ├─ WSL2 detected: {is_wsl2}")
            
            if not is_wsl2:
                # Native Windows - NOT SUPPORTED
                self._fail_fast(
                    component="Platform",
                    version_req="Linux or WSL2",
                    found="Native Windows",
                    reason="Native Windows is not supported (lack of iptables, incompatible networking)",
                    solution="Install WSL2:\n  1. Open PowerShell as Administrator\n  2. Run: wsl --install\n  3. Restart your computer\n  4. Run AX-TrafficAnalyzer from WSL2",
                    documentation="https://docs.microsoft.com/en-us/windows/wsl/install"
                )
            
            # WSL2 - continue with Linux path
            kernel_version, distribution, distro_version = self._detect_linux_info()
            print(f"  ├─ Distribution: {distribution} {distro_version}")
            print(f"  └─ Kernel: {kernel_version}")
            return PlatformInfo(
                os="Linux",
                is_wsl2=True,
                is_native_linux=False,
                is_native_windows=False,
                wsl_distro=wsl_distro,
                kernel_version=kernel_version,
                architecture=architecture,
                distribution=distribution,
                distribution_version=distro_version,
                python_version=python_version_str,
                python_version_tuple=(python_version.major, python_version.minor, python_version.micro)
            )
        
        elif os_type == "Linux":
            # Native Linux
            kernel_version, distribution, distro_version = self._detect_linux_info()
            print(f"  ├─ Distribution: {distribution} {distro_version}")
            print(f"  ├─ Kernel: {kernel_version}")
            
            # Validate kernel version
            kernel_tuple = self._parse_version(kernel_version)
            if kernel_tuple < self.MIN_KERNEL_VERSION:
                self._fail_fast(
                    component="Kernel",
                    version_req=f">= {self.MIN_KERNEL_VERSION[0]}.{self.MIN_KERNEL_VERSION[1]}",
                    found=kernel_version,
                    reason="Kernel version too old (missing modern networking features)",
                    solution=f"Upgrade kernel to {self.MIN_KERNEL_VERSION[0]}.{self.MIN_KERNEL_VERSION[1]}+"
                )
            
            print(f"  └─ Platform detection complete ✓")
            return PlatformInfo(
                os="Linux",
                is_wsl2=False,
                is_native_linux=True,
                is_native_windows=False,
                wsl_distro=None,
                kernel_version=kernel_version,
                architecture=architecture,
                distribution=distribution,
                distribution_version=distro_version,
                python_version=python_version_str,
                python_version_tuple=(python_version.major, python_version.minor, python_version.micro)
            )
        
        else:
            # Unsupported OS
            self._fail_fast(
                component="Platform",
                version_req="Linux or WSL2",
                found=os_type,
                reason=f"{os_type} is not supported",
                solution="Use Linux (Ubuntu 20.04+, Debian 11+, Fedora 35+, Arch Linux) or WSL2"
            )
    
    def _detect_wsl2(self) -> Tuple[bool, Optional[str]]:
        """Detect if running in WSL2."""
        # Check /proc/version for WSL indicators
        try:
            with open("/proc/version", "r") as f:
                proc_version = f.read().lower()
                if "microsoft" in proc_version or "wsl" in proc_version:
                    # Get WSL distribution name
                    wsl_distro = os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSLENV")
                    return True, wsl_distro
        except FileNotFoundError:
            pass
        
        # Check for Windows filesystem mount
        if Path("/mnt/c/Windows").exists():
            wsl_distro = os.environ.get("WSL_DISTRO_NAME")
            return True, wsl_distro
        
        return False, None
    
    def _detect_linux_info(self) -> Tuple[str, str, str]:
        """Detect Linux kernel version and distribution."""
        # Get kernel version
        kernel_version = platform.release()
        
        # Get distribution info from /etc/os-release
        distribution = "Unknown"
        distro_version = "Unknown"
        
        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("ID="):
                        distribution = line.split("=", 1)[1].strip('"')
                    elif line.startswith("VERSION_ID="):
                        distro_version = line.split("=", 1)[1].strip('"')
        except FileNotFoundError:
            # Try alternative methods
            try:
                result = subprocess.run(
                    ["lsb_release", "-is"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    distribution = result.stdout.strip()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        
        return kernel_version, distribution, distro_version
    
    def _parse_version(self, version_str: str) -> Tuple[int, int, int]:
        """Parse version string to tuple."""
        # Extract version numbers (e.g., "5.15.0-157-generic" -> (5, 15, 0))
        match = re.match(r"(\d+)\.(\d+)\.(\d+)", version_str)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        return (0, 0, 0)
    
    def _fail_fast(
        self,
        component: str,
        version_req: str,
        found: str,
        reason: str,
        solution: str,
        documentation: Optional[str] = None
    ) -> None:
        """
        Fail-fast with detailed error message.
        
        Format matches DESIGN_PLAN.md specification.
        """
        platform_str = f"{platform.system()} ({platform.release()})"
        if self._platform_info and self._platform_info.distribution:
            platform_str = f"{platform.system()} ({self._platform_info.distribution} {self._platform_info.distribution_version})"
        
        error_msg = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
❌ CRITICAL ERROR: Platform validation failed
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

COMPONENT:    {component}
VERSION REQ:  {version_req}
FOUND:        {found}
PLATFORM:     {platform_str}
REQUIRED FOR: System operation

WHY THIS FAILS:
  {reason}

SOLUTION:
  {solution}

DOCUMENTATION:
  {documentation or "https://docs.ax-traffic-analyzer.com/installation/platform"}

ALTERNATIVE:
  None - {component} is a core requirement and cannot be substituted.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        raise PlatformDetectionError(error_msg)


# Singleton instance
_detector_instance: Optional[PlatformDetector] = None


def get_platform_info() -> PlatformInfo:
    """
    Get platform information (singleton pattern).
    
    Returns:
        PlatformInfo: Platform information
        
    Raises:
        PlatformDetectionError: If platform is unsupported
    """
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = PlatformDetector()
    return _detector_instance.detect()

