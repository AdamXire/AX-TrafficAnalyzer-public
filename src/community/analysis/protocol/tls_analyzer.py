"""
@fileoverview TLS/SSL Analyzer - Certificate and cipher suite analysis
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

TLS/SSL protocol analyzer for certificate chain and cipher suite validation.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import Dict, Any, List
from ...analysis.base import BaseAnalyzer, AnalysisResult, Finding, Severity
from datetime import datetime
from uuid import uuid4
from ...core.logging import get_logger

log = get_logger(__name__)


class TLSAnalyzer(BaseAnalyzer):
    """
    Analyzes TLS/SSL connections.
    
    Detects:
    - Weak cipher suites
    - Expired certificates
    - Self-signed certificates
    - Certificate chain issues
    - TLS version vulnerabilities
    """
    
    def __init__(self):
        super().__init__("tls_analyzer")
        self.weak_ciphers = [
            "RC4", "DES", "3DES", "MD5", "SHA1",
            "TLS_RSA_WITH_",  # RSA key exchange (weak)
            "TLS_DHE_RSA_WITH_",  # DHE (if weak parameters)
        ]
        self.weak_protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
        log.info("analyzer_initialized", name=self.name)
    
    async def analyze(self, flow: Dict[str, Any]) -> AnalysisResult:
        """
        Analyze TLS handshake.
        
        Note: Detailed TLS analysis requires mitmproxy TLS event hooks.
        This implementation analyzes available TLS metadata from flow.
        
        Args:
            flow: Flow data with TLS information
            
        Returns:
            AnalysisResult with findings
        """
        log.debug("tls_analysis_started", flow_id=flow.get("flow_id"))
        
        findings = []
        
        # Extract TLS information from flow
        tls_info = flow.get("tls_info", {})
        url = flow.get("url", "")
        is_https = url.startswith("https://")
        
        if not is_https:
            # Not an HTTPS connection - no TLS to analyze
            return AnalysisResult(
                analyzer_name=self.name,
                flow_id=flow.get("flow_id"),
                session_id=flow.get("session_id"),
                findings=[],
                metadata={"reason": "not_https"},
                timestamp=datetime.utcnow()
            )
        
        # Check TLS version
        tls_version = tls_info.get("version")
        if tls_version:
            findings.extend(self._check_tls_version(tls_version, url))
        
        # Check cipher suite
        cipher_suite = tls_info.get("cipher_suite")
        if cipher_suite:
            findings.extend(self._check_cipher_suite(cipher_suite, url))
        
        # Check certificate
        certificate = tls_info.get("certificate")
        if certificate:
            findings.extend(self._check_certificate(certificate, url))
        
        # Check certificate chain
        chain = tls_info.get("chain", [])
        if chain:
            findings.extend(self._check_certificate_chain(chain, url))
        
        log.debug("tls_analysis_complete", 
                 flow_id=flow.get("flow_id"), 
                 findings_count=len(findings))
        
        return AnalysisResult(
            analyzer_name=self.name,
            flow_id=flow.get("flow_id"),
            session_id=flow.get("session_id"),
            findings=findings,
            metadata={
                "tls_version": tls_version,
                "cipher_suite": cipher_suite,
                "has_certificate": certificate is not None,
                "chain_length": len(chain) if chain else 0
            },
            timestamp=datetime.utcnow()
        )
    
    def _check_tls_version(self, version: str, url: str) -> List[Finding]:
        """Check TLS version for vulnerabilities."""
        findings = []
        
        version_upper = version.upper()
        for weak_protocol in self.weak_protocols:
            if weak_protocol in version_upper:
                findings.append(Finding(
                    id=str(uuid4()),
                    severity=Severity.HIGH,
                    category="tls_vulnerability",
                    title=f"Weak TLS Protocol: {version}",
                    description=f"Connection uses {version}, which has known vulnerabilities",
                    recommendation=f"Upgrade to TLS 1.2 or TLS 1.3",
                    metadata={"version": version, "url": url[:200]},
                    timestamp=datetime.utcnow()
                ))
                break
        
        return findings
    
    def _check_cipher_suite(self, cipher: str, url: str) -> List[Finding]:
        """Check cipher suite for weaknesses."""
        findings = []
        
        cipher_upper = cipher.upper()
        for weak_cipher in self.weak_ciphers:
            if weak_cipher in cipher_upper:
                findings.append(Finding(
                    id=str(uuid4()),
                    severity=Severity.MEDIUM,
                    category="weak_cipher",
                    title=f"Weak Cipher Suite: {cipher}",
                    description=f"Connection uses {cipher}, which is considered weak or deprecated",
                    recommendation="Use modern cipher suites (AES-GCM, ChaCha20-Poly1305)",
                    metadata={"cipher": cipher, "url": url[:200]},
                    timestamp=datetime.utcnow()
                ))
                break
        
        return findings
    
    def _check_certificate(self, cert: Dict[str, Any], url: str) -> List[Finding]:
        """Check certificate for issues."""
        findings = []
        
        # Check expiration
        not_after = cert.get("not_after")
        if not_after:
            try:
                from datetime import datetime as dt
                expiry = dt.fromisoformat(not_after.replace('Z', '+00:00'))
                now = datetime.utcnow()
                days_until_expiry = (expiry - now).days
                
                if days_until_expiry < 0:
                    findings.append(Finding(
                        id=str(uuid4()),
                        severity=Severity.HIGH,
                        category="certificate_expired",
                        title="Expired Certificate",
                        description=f"Certificate expired {abs(days_until_expiry)} days ago",
                        recommendation="Renew certificate immediately",
                        metadata={"expiry_date": not_after, "url": url[:200]},
                        timestamp=datetime.utcnow()
                    ))
                elif days_until_expiry < 30:
                    findings.append(Finding(
                        id=str(uuid4()),
                        severity=Severity.MEDIUM,
                        category="certificate_expiring",
                        title="Certificate Expiring Soon",
                        description=f"Certificate expires in {days_until_expiry} days",
                        recommendation="Renew certificate before expiration",
                        metadata={"expiry_date": not_after, "days_remaining": days_until_expiry, "url": url[:200]},
                        timestamp=datetime.utcnow()
                    ))
            except Exception as e:
                log.debug("certificate_date_parse_failed", error=str(e))
        
        # Check if self-signed
        issuer = cert.get("issuer", {})
        subject = cert.get("subject", {})
        if issuer == subject:
            findings.append(Finding(
                id=str(uuid4()),
                severity=Severity.MEDIUM,
                category="self_signed_certificate",
                title="Self-Signed Certificate",
                description="Certificate is self-signed, not trusted by default",
                recommendation="Use certificate from trusted CA",
                metadata={"url": url[:200]},
                timestamp=datetime.utcnow()
            ))
        
        return findings
    
    def _check_certificate_chain(self, chain: List[Dict[str, Any]], url: str) -> List[Finding]:
        """Check certificate chain for issues."""
        findings = []
        
        # Check chain length
        if len(chain) < 2:
            findings.append(Finding(
                id=str(uuid4()),
                severity=Severity.LOW,
                category="incomplete_chain",
                title="Incomplete Certificate Chain",
                description=f"Certificate chain has only {len(chain)} certificate(s), may cause trust issues",
                recommendation="Include intermediate certificates in chain",
                metadata={"chain_length": len(chain), "url": url[:200]},
                timestamp=datetime.utcnow()
            ))
        
        return findings
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """Return detection rules."""
        return [
            {
                "id": "weak_tls_version",
                "check": "tls_version",
                "severity": Severity.HIGH,
                "category": "tls_vulnerability"
            },
            {
                "id": "weak_cipher",
                "check": "cipher_suite",
                "severity": Severity.MEDIUM,
                "category": "weak_cipher"
            },
            {
                "id": "certificate_expired",
                "check": "certificate",
                "severity": Severity.HIGH,
                "category": "certificate_expired"
            },
            {
                "id": "self_signed_cert",
                "check": "certificate",
                "severity": Severity.MEDIUM,
                "category": "self_signed_certificate"
            }
        ]

