"""
@fileoverview Keyring Manager - Platform-aware secure key storage
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Platform-aware keyring integration for secure key storage.
Linux: libsecret, WSL2: Windows DPAPI
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import keyring
import subprocess
from typing import Optional
from pathlib import Path

from ..errors import SecurityError
from ..logging import get_logger
from ..platform.detector import PlatformInfo

log = get_logger(__name__)

# Keyring service name
KEYRING_SERVICE = "ax-traffic-analyzer"


class KeyringManager:
    """
    Platform-aware keyring manager for secure key storage.
    
    Linux: Uses libsecret (GNOME Keyring, KWallet)
    WSL2: Uses Windows DPAPI via keyring backend
    """
    
    def __init__(self, platform_info: PlatformInfo):
        """
        Initialize keyring manager.
        
        Args:
            platform_info: Platform information from detector
            
        Raises:
            SecurityError: If keyring unavailable or validation fails
        """
        self.platform_info = platform_info
        self._validate_keyring_available()
        log.debug("keyring_manager_initialized", platform=platform_info.os, is_wsl2=platform_info.is_wsl2)
    
    def _validate_keyring_available(self) -> None:
        """Validate keyring is available (fail-fast)."""
        try:
            # Test keyring backend
            backend = keyring.get_keyring()
            backend_name = backend.name
            log.debug("keyring_backend_detected", backend=backend_name)
            
            # Platform-specific validation
            if self.platform_info.is_native_linux:
                # Linux: Check for libsecret-tool (optional, but preferred)
                result = subprocess.run(
                    ["which", "libsecret-tool"],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode != 0:
                    log.warning("libsecret_tool_not_found", 
                               note="Keyring will use default backend")
            
            # Test write/read
            test_key = "ax-traffic-test-key"
            test_value = "test-value"
            try:
                keyring.set_password(KEYRING_SERVICE, test_key, test_value)
                retrieved = keyring.get_password(KEYRING_SERVICE, test_key)
                if retrieved != test_value:
                    raise SecurityError(
                        "Keyring test failed: retrieved value mismatch",
                        None
                    )
                keyring.delete_password(KEYRING_SERVICE, test_key)
                log.debug("keyring_test_passed")
            except Exception as e:
                raise SecurityError(
                    f"Keyring test failed: {e}. "
                    f"Ensure keyring service is available (Linux: libsecret, WSL2: Windows DPAPI).",
                    None
                )
                
        except ImportError:
            raise SecurityError(
                "keyring package not installed. "
                "Install with: pip install keyring>=24.0.0,<25.0.0",
                None
            )
        except Exception as e:
            raise SecurityError(
                f"Keyring unavailable: {e}. "
                f"Platform: {self.platform_info.os}, WSL2: {self.platform_info.is_wsl2}",
                None
            )
    
    def store_key(self, key_id: str, key_data: bytes) -> None:
        """
        Store encrypted key in system keyring.
        
        Args:
            key_id: Unique identifier for the key
            key_data: Key data as bytes
            
        Raises:
            SecurityError: If storage fails
        """
        try:
            # Convert bytes to base64 string for keyring storage
            import base64
            key_str = base64.b64encode(key_data).decode('utf-8')
            
            keyring.set_password(KEYRING_SERVICE, key_id, key_str)
            log.info("key_stored", key_id=key_id, service=KEYRING_SERVICE)
        except Exception as e:
            raise SecurityError(
                f"Failed to store key '{key_id}' in keyring: {e}",
                None
            )
    
    def retrieve_key(self, key_id: str) -> bytes:
        """
        Retrieve and decrypt key from system keyring.
        
        Args:
            key_id: Unique identifier for the key
            
        Returns:
            Key data as bytes
            
        Raises:
            SecurityError: If key not found or retrieval fails
        """
        try:
            key_str = keyring.get_password(KEYRING_SERVICE, key_id)
            if key_str is None:
                raise SecurityError(
                    f"Key '{key_id}' not found in keyring",
                    None
                )
            
            # Convert from base64 string back to bytes
            import base64
            key_data = base64.b64decode(key_str.encode('utf-8'))
            log.debug("key_retrieved", key_id=key_id)
            return key_data
        except SecurityError:
            raise
        except Exception as e:
            raise SecurityError(
                f"Failed to retrieve key '{key_id}' from keyring: {e}",
                None
            )
    
    def delete_key(self, key_id: str) -> None:
        """
        Delete key from system keyring.
        
        Args:
            key_id: Unique identifier for the key
        """
        try:
            keyring.delete_password(KEYRING_SERVICE, key_id)
            log.info("key_deleted", key_id=key_id)
        except keyring.errors.PasswordDeleteError:
            log.warning("key_delete_not_found", key_id=key_id)
        except Exception as e:
            log.error("key_delete_failed", key_id=key_id, error=str(e))

