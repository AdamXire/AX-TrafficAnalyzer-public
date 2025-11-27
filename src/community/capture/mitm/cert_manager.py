"""
@fileoverview Certificate Manager - Root CA generation and validation
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Certificate generation and validation for mitmproxy.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from ...core.errors import SecurityError, ConfigurationError
from ...core.logging import get_logger
from ...core.security import CertificateSecurityManager, KeyringManager
from ...core.platform import get_platform_info

log = get_logger(__name__)


class CertificateManager:
    """
    Manages root CA certificate generation and validation.
    
    Handles first-run certificate generation and ongoing validation.
    """
    
    def __init__(self, cert_dir: str = "./certs", keyring_manager: Optional[KeyringManager] = None):
        """
        Initialize certificate manager.
        
        Args:
            cert_dir: Directory for certificate storage
            keyring_manager: KeyringManager instance (creates if None)
        """
        self.cert_dir = Path(cert_dir)
        self.cert_security = CertificateSecurityManager(
            keyring_manager or KeyringManager(get_platform_info()),
            cert_dir=str(cert_dir)
        )
        self.ca_cert_path = self.cert_dir / "ax-traffic-ca.pem"
        self.ca_key_id = "ax-traffic-ca-key"
        log.debug("certificate_manager_initialized", cert_dir=str(cert_dir))
    
    def validate_or_generate(self) -> None:
        """
        Validate existing certificate OR generate on first run.
        
        Step 5 of startup orchestration:
        - If cert exists: validate (fail-fast if expired/invalid)
        - If cert missing AND first run: generate + validate
        - If cert missing AND NOT first run: fail-fast
        
        Raises:
            SecurityError: If certificate validation fails
            ConfigurationError: If certificate missing but not first run
        """
        if self.ca_cert_path.exists():
            log.info("certificate_exists", path=str(self.ca_cert_path))
            self._validate_certificate()
        else:
            log.info("certificate_not_found", path=str(self.ca_cert_path))
            if self._is_first_run():
                log.info("first_run_detected", generating_ca=True)
                self._generate_root_ca()
                self._validate_certificate()
            else:
                raise ConfigurationError(
                    f"CA certificate missing at {self.ca_cert_path} but not first run. "
                    f"Certificate may have been deleted. Regenerate manually or restore from backup.",
                    None
                )
    
    def _is_first_run(self) -> bool:
        """
        Check if this is first run (no certificate exists).
        
        Returns:
            True if first run, False otherwise
        """
        # Simple heuristic: no cert file = first run
        # Could be enhanced with flag file or database check
        return not self.ca_cert_path.exists()
    
    def _generate_root_ca(self) -> None:
        """
        Generate root CA certificate (atomic operation).
        
        Raises:
            SecurityError: If generation fails
        """
        log.info("generating_root_ca", cert_dir=str(self.cert_dir))
        
        try:
            # Generate private key (2048-bit RSA)
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Serialize private key
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Store encrypted private key using CertificateSecurityManager
            self.cert_security.store_private_key(self.ca_key_id, key_pem)
            log.debug("ca_private_key_stored", key_id=self.ca_key_id)
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AX-TrafficAnalyzer"),
                x509.NameAttribute(NameOID.COMMON_NAME, "AX-TrafficAnalyzer Root CA"),
            ])
            
            # Valid for 1 year
            valid_from = datetime.utcnow()
            valid_to = valid_from + timedelta(days=365)
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                valid_from
            ).not_valid_after(
                valid_to
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    key_encipherment=False,
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Serialize certificate
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            
            # Store certificate
            self.cert_security.store_certificate("ax-traffic-ca", cert_pem)
            log.info("root_ca_generated", cert_path=str(self.ca_cert_path), valid_until=valid_to.isoformat())
            
        except Exception as e:
            raise SecurityError(
                f"Failed to generate root CA certificate: {e}",
                None
            )
    
    def _validate_certificate(self) -> None:
        """
        Validate CA certificate (fail-fast if expired/invalid).
        
        Raises:
            SecurityError: If certificate is expired or invalid
        """
        log.debug("validating_certificate", path=str(self.ca_cert_path))
        
        try:
            # Load certificate
            with open(self.ca_cert_path, 'rb') as f:
                cert_pem = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            
            # Check expiration
            now = datetime.utcnow()
            if cert.not_valid_after < now:
                raise SecurityError(
                    f"CA certificate expired on {cert.not_valid_after.isoformat()}. "
                    f"Generate new certificate or restore from backup.",
                    None
                )
            
            # Check validity period (warn if expiring soon)
            days_until_expiry = (cert.not_valid_after - now).days
            if days_until_expiry < 30:
                log.warning("certificate_expiring_soon", days=days_until_expiry)
            
            # Verify basic constraints
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                )
                if not basic_constraints.value.ca:
                    raise SecurityError(
                        "Certificate is not a CA certificate (BasicConstraints CA=False)",
                        None
                    )
            except x509.ExtensionNotFound:
                raise SecurityError(
                    "Certificate missing BasicConstraints extension (required for CA)",
                    None
                )
            
            log.info("certificate_validated", 
                    valid_from=cert.not_valid_before.isoformat(),
                    valid_to=cert.not_valid_after.isoformat(),
                    days_until_expiry=days_until_expiry)
            
        except FileNotFoundError:
            raise SecurityError(
                f"Certificate file not found: {self.ca_cert_path}",
                None
            )
        except Exception as e:
            raise SecurityError(
                f"Certificate validation failed: {e}",
                None
            )
    
    def get_ca_cert_path(self) -> Path:
        """Get path to CA certificate file."""
        return self.ca_cert_path

