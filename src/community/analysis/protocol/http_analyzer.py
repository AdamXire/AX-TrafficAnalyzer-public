"""
@fileoverview HTTP Protocol Analyzer - Security analysis for HTTP traffic
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

HTTP protocol analyzer for detecting security issues in HTTP requests/responses.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import Dict, List, Any
from ...analysis.base import BaseAnalyzer, AnalysisResult, Finding, Severity
from datetime import datetime
from uuid import uuid4
from ...core.logging import get_logger

log = get_logger(__name__)


class HTTPAnalyzer(BaseAnalyzer):
    """
    Analyzes HTTP traffic for security issues.
    
    Detects:
    - Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
    - Insecure cookies (missing Secure, HttpOnly, SameSite)
    - Sensitive data exposure (passwords, API keys in URLs)
    - Authentication over HTTP
    - Information disclosure (server versions, stack traces)
    """
    
    def __init__(self):
        super().__init__("http_analyzer")
        self.rules = self._load_rules()
        log.info("analyzer_initialized", name=self.name, rules_count=len(self.rules))
    
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load detection rules."""
        return [
            {
                "id": "missing_security_headers",
                "check": "security_headers",
                "severity": Severity.MEDIUM,
                "category": "http_security_headers"
            },
            {
                "id": "insecure_cookies",
                "check": "cookie_security",
                "severity": Severity.HIGH,
                "category": "insecure_cookies"
            },
            {
                "id": "sensitive_data_exposure",
                "check": "sensitive_data",
                "severity": Severity.CRITICAL,
                "category": "sensitive_data_exposure"
            },
            {
                "id": "authentication_over_http",
                "check": "auth_security",
                "severity": Severity.HIGH,
                "category": "authentication_security"
            },
        ]
    
    async def analyze(self, flow: Dict[str, Any]) -> AnalysisResult:
        """
        Analyze HTTP flow for security issues.
        
        Args:
            flow: Flow data with request/response headers
            
        Returns:
            AnalysisResult with findings
        """
        log.debug("http_analysis_started", flow_id=flow.get("flow_id"), url=flow.get("url", "")[:100])
        
        findings = []
        
        # Check security headers
        findings.extend(self._check_security_headers(flow))
        
        # Check cookie security
        findings.extend(self._check_cookies(flow))
        
        # Check for sensitive data
        findings.extend(self._check_sensitive_data(flow))
        
        # Check authentication security
        findings.extend(self._check_auth_security(flow))
        
        log.debug("http_analysis_complete", 
                 flow_id=flow.get("flow_id"), 
                 findings_count=len(findings),
                 severities={
                     "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                     "high": sum(1 for f in findings if f.severity == Severity.HIGH),
                     "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
                     "low": sum(1 for f in findings if f.severity == Severity.LOW)
                 })
        
        return AnalysisResult(
            analyzer_name=self.name,
            flow_id=flow.get("flow_id"),
            session_id=flow.get("session_id"),
            findings=findings,
            metadata={
                "total_findings": len(findings),
                "url": flow.get("url", "")[:200],
                "method": flow.get("method"),
                "status_code": flow.get("status_code")
            },
            timestamp=datetime.utcnow()
        )
    
    def _check_security_headers(self, flow: Dict[str, Any]) -> List[Finding]:
        """Check for missing security headers."""
        findings = []
        response_headers = flow.get("response_headers", {})
        url = flow.get("url", "")
        
        # Only check HTTPS-specific headers for HTTPS URLs
        is_https = url.startswith("https://")
        
        # Required security headers
        required_headers = {
            "X-Content-Type-Options": {
                "title": "Missing X-Content-Type-Options Header",
                "description": "Response lacks X-Content-Type-Options: nosniff header, allowing MIME type sniffing attacks",
                "recommendation": "Add 'X-Content-Type-Options: nosniff' header to all responses",
                "severity": Severity.MEDIUM
            },
            "X-Frame-Options": {
                "title": "Missing X-Frame-Options Header",
                "description": "Response lacks X-Frame-Options header, allowing potential clickjacking attacks",
                "recommendation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header",
                "severity": Severity.MEDIUM
            },
            "Content-Security-Policy": {
                "title": "Missing Content-Security-Policy Header",
                "description": "Response lacks Content-Security-Policy (CSP) header, reducing protection against XSS attacks",
                "recommendation": "Implement a Content-Security-Policy header with appropriate directives",
                "severity": Severity.MEDIUM
            }
        }
        
        # HTTPS-only headers
        if is_https:
            required_headers["Strict-Transport-Security"] = {
                "title": "Missing Strict-Transport-Security Header",
                "description": "HTTPS response lacks HSTS header, allowing potential downgrade attacks",
                "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header",
                "severity": Severity.HIGH
            }
        
        for header, details in required_headers.items():
            if header not in response_headers:
                findings.append(Finding(
                    id=str(uuid4()),
                    severity=details["severity"],
                    category="http_security_headers",
                    title=details["title"],
                    description=details["description"],
                    recommendation=details["recommendation"],
                    metadata={
                        "header": header,
                        "url": url[:200],
                        "flow_id": flow.get("flow_id")
                    },
                    timestamp=datetime.utcnow()
                ))
        
        return findings
    
    def _check_cookies(self, flow: Dict[str, Any]) -> List[Finding]:
        """Check cookie security attributes."""
        findings = []
        cookies = flow.get("cookies", {})
        url = flow.get("url", "")
        is_https = url.startswith("https://")
        
        if not cookies or not isinstance(cookies, dict):
            return findings
        
        raw_cookies = cookies.get("raw", "")
        if not raw_cookies:
            return findings
        
        # Check for Secure flag (critical for HTTPS)
        if is_https and "Secure" not in raw_cookies:
            findings.append(Finding(
                id=str(uuid4()),
                severity=Severity.HIGH,
                category="insecure_cookies",
                title="Cookie Missing Secure Flag",
                description="Cookie set over HTTPS without Secure flag, vulnerable to interception over HTTP",
                recommendation="Add 'Secure' attribute to all cookies set over HTTPS",
                metadata={
                    "cookie": raw_cookies[:100],
                    "url": url[:200],
                    "flow_id": flow.get("flow_id")
                },
                timestamp=datetime.utcnow()
            ))
        
        # Check for HttpOnly flag
        if "HttpOnly" not in raw_cookies:
            findings.append(Finding(
                id=str(uuid4()),
                severity=Severity.MEDIUM,
                category="insecure_cookies",
                title="Cookie Missing HttpOnly Flag",
                description="Cookie accessible to JavaScript, vulnerable to XSS-based theft",
                recommendation="Add 'HttpOnly' attribute to sensitive cookies",
                metadata={
                    "cookie": raw_cookies[:100],
                    "url": url[:200],
                    "flow_id": flow.get("flow_id")
                },
                timestamp=datetime.utcnow()
            ))
        
        # Check for SameSite attribute
        if "SameSite" not in raw_cookies:
            findings.append(Finding(
                id=str(uuid4()),
                severity=Severity.MEDIUM,
                category="insecure_cookies",
                title="Cookie Missing SameSite Attribute",
                description="Cookie lacks SameSite attribute, vulnerable to CSRF attacks",
                recommendation="Add 'SameSite=Strict' or 'SameSite=Lax' attribute to cookies",
                metadata={
                    "cookie": raw_cookies[:100],
                    "url": url[:200],
                    "flow_id": flow.get("flow_id")
                },
                timestamp=datetime.utcnow()
            ))
        
        return findings
    
    def _check_sensitive_data(self, flow: Dict[str, Any]) -> List[Finding]:
        """Check for sensitive data in URLs or headers."""
        findings = []
        url = flow.get("url", "")
        request_headers = flow.get("request_headers", {})
        
        # Common sensitive patterns
        sensitive_patterns = {
            "password": "password parameter",
            "passwd": "password parameter",
            "pwd": "password parameter",
            "apikey": "API key",
            "api_key": "API key",
            "api-key": "API key",
            "token": "authentication token",
            "secret": "secret value",
            "private_key": "private key",
            "access_token": "access token",
            "refresh_token": "refresh token",
            "session_id": "session ID",
            "ssn": "social security number",
            "credit_card": "credit card number",
            "ccnumber": "credit card number"
        }
        
        url_lower = url.lower()
        for pattern, data_type in sensitive_patterns.items():
            if pattern in url_lower:
                findings.append(Finding(
                    id=str(uuid4()),
                    severity=Severity.CRITICAL,
                    category="sensitive_data_exposure",
                    title="Sensitive Data in URL",
                    description=f"URL contains '{pattern}' which may expose {data_type}",
                    recommendation="Use POST body or Authorization header for sensitive data, never in URL",
                    metadata={
                        "pattern": pattern,
                        "data_type": data_type,
                        "url": url[:200],
                        "flow_id": flow.get("flow_id")
                    },
                    timestamp=datetime.utcnow()
                ))
        
        # Check for Authorization header in plaintext (should be over HTTPS)
        if "Authorization" in request_headers and not url.startswith("https://"):
            findings.append(Finding(
                id=str(uuid4()),
                severity=Severity.CRITICAL,
                category="sensitive_data_exposure",
                title="Authorization Header Over HTTP",
                description="Authorization credentials sent over unencrypted HTTP connection",
                recommendation="Use HTTPS for all authenticated requests",
                metadata={
                    "url": url[:200],
                    "flow_id": flow.get("flow_id")
                },
                timestamp=datetime.utcnow()
            ))
        
        return findings
    
    def _check_auth_security(self, flow: Dict[str, Any]) -> List[Finding]:
        """Check authentication security."""
        findings = []
        auth_detected = flow.get("auth_detected")
        url = flow.get("url", "")
        
        # Check if auth is over HTTP (not HTTPS)
        if auth_detected and url.startswith("http://"):
            findings.append(Finding(
                id=str(uuid4()),
                severity=Severity.CRITICAL,
                category="authentication_security",
                title="Authentication Over Unencrypted HTTP",
                description=f"{auth_detected} authentication sent over unencrypted HTTP connection",
                recommendation="Use HTTPS for all authenticated requests to protect credentials",
                metadata={
                    "auth_type": auth_detected,
                    "url": url[:200],
                    "flow_id": flow.get("flow_id")
                },
                timestamp=datetime.utcnow()
            ))
        
        # Warn about Basic authentication even over HTTPS (credentials in every request)
        if auth_detected == "Basic":
            findings.append(Finding(
                id=str(uuid4()),
                severity=Severity.MEDIUM,
                category="authentication_security",
                title="HTTP Basic Authentication Detected",
                description="Basic authentication sends credentials in every request (base64-encoded, not encrypted)",
                recommendation="Consider using token-based authentication (JWT, OAuth) instead",
                metadata={
                    "auth_type": auth_detected,
                    "url": url[:200],
                    "flow_id": flow.get("flow_id")
                },
                timestamp=datetime.utcnow()
            ))
        
        return findings
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """Return detection rules."""
        return self.rules

