"""
@fileoverview Certificate Security Manager - Encrypted certificate storage
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Certificate security with encrypted private key storage.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import os
from pathlib import Path
from typing import Optional

from ..errors import SecurityError, ConfigurationError
from ..logging import get_logger
from .keyring_manager import KeyringManager

log = get_logger(__name__)


class CertificateSecurityManager:
    """
    Certificate security manager with encrypted private key storage.
    
    Features:
    - Private keys encrypted at rest using system keyring
    - Certificate files stored with 0600 permissions
    - Directory creation with 0700 permissions
    """
    
    def __init__(self, keyring_manager: KeyringManager, cert_dir: str = "./certs"):
        """
        Initialize certificate security manager.
        
        Args:
            keyring_manager: KeyringManager instance
            cert_dir: Directory for certificate storage
            
        Raises:
            ConfigurationError: If directory cannot be created or is not writable
        """
        self.keyring_manager = keyring_manager
        self.cert_dir = Path(cert_dir)
        self._ensure_cert_directory()
        log.debug("cert_security_manager_initialized", cert_dir=str(self.cert_dir))
    
    def _ensure_cert_directory(self) -> None:
        """Ensure certificate directory exists with correct permissions."""
        try:
            if not self.cert_dir.exists():
                self.cert_dir.mkdir(parents=True, mode=0o700)
                log.info("cert_directory_created", path=str(self.cert_dir))
            
            # Verify writable
            if not os.access(self.cert_dir, os.W_OK):
                raise ConfigurationError(
                    f"Certificate directory not writable: {self.cert_dir}",
                    None
                )
            
            # Set permissions (0700)
            os.chmod(self.cert_dir, 0o700)
            log.debug("cert_directory_validated", path=str(self.cert_dir))
        except Exception as e:
            raise ConfigurationError(
                f"Failed to create certificate directory '{self.cert_dir}': {e}",
                None
            )
    
    def store_private_key(self, key_id: str, key_pem: bytes) -> str:
        """
        Store private key encrypted in keyring, return file path.
        
        The private key is stored in the system keyring (encrypted).
        A placeholder file is created with 0600 permissions for reference.
        
        Args:
            key_id: Unique identifier for the key (e.g., "root-ca-key")
            key_pem: Private key in PEM format
            
        Returns:
            Path to key file (placeholder, actual key in keyring)
            
        Raises:
            SecurityError: If storage fails
        """
        try:
            # Store encrypted key in keyring
            self.keyring_manager.store_key(key_id, key_pem)
            
            # Create placeholder file with 0600 permissions
            key_file = self.cert_dir / f"{key_id}.key"
            with open(key_file, 'wb') as f:
                # Write placeholder (actual key is in keyring)
                f.write(b"# Private key stored in system keyring\n")
                f.write(f"# Key ID: {key_id}\n".encode())
                f.write(b"# Use KeyringManager.retrieve_key() to access\n")
            
            # Set 0600 permissions
            os.chmod(key_file, 0o600)
            log.info("private_key_stored", key_id=key_id, file=str(key_file))
            return str(key_file)
        except Exception as e:
            raise SecurityError(
                f"Failed to store private key '{key_id}': {e}",
                None
            )
    
    def retrieve_private_key(self, key_id: str) -> bytes:
        """
        Retrieve private key from keyring.
        
        Args:
            key_id: Unique identifier for the key
            
        Returns:
            Private key in PEM format
            
        Raises:
            SecurityError: If key not found or retrieval fails
        """
        try:
            key_data = self.keyring_manager.retrieve_key(key_id)
            log.debug("private_key_retrieved", key_id=key_id)
            return key_data
        except Exception as e:
            raise SecurityError(
                f"Failed to retrieve private key '{key_id}': {e}",
                None
            )
    
    def store_certificate(self, cert_id: str, cert_pem: bytes) -> str:
        """
        Store certificate file with 0644 permissions.
        
        Args:
            cert_id: Unique identifier for the certificate (e.g., "root-ca")
            cert_pem: Certificate in PEM format
            
        Returns:
            Path to certificate file
            
        Raises:
            SecurityError: If storage fails
        """
        try:
            cert_file = self.cert_dir / f"{cert_id}.pem"
            with open(cert_file, 'wb') as f:
                f.write(cert_pem)
            
            # Set 0644 permissions (certificate is public)
            os.chmod(cert_file, 0o644)
            log.info("certificate_stored", cert_id=cert_id, file=str(cert_file))
            return str(cert_file)
        except Exception as e:
            raise SecurityError(
                f"Failed to store certificate '{cert_id}': {e}",
                None
            )
    
    def get_cert_path(self, cert_id: str) -> Path:
        """Get path to certificate file."""
        return self.cert_dir / f"{cert_id}.pem"
    
    def get_key_path(self, key_id: str) -> Path:
        """Get path to key placeholder file."""
        return self.cert_dir / f"{key_id}.key"

