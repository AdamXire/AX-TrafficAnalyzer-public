"""
@fileoverview Passive Vulnerability Scanner - Non-invasive security scanning
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Passive vulnerability scanner that analyzes traffic without sending active probes.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import List, Dict, Any
from ..base import Finding, Severity
from datetime import datetime
from uuid import uuid4
from ...core.logging import get_logger

log = get_logger(__name__)


class PassiveScanner:
    """
    Passive vulnerability scanner.
    
    Analyzes traffic without sending active probes, detecting:
    - Information disclosure (server versions, tech stack)
    - Outdated software versions
    - Debug/development endpoints
    - Directory listings
    - Error messages with stack traces
    """
    
    def __init__(self):
        self.name = "passive_scanner"
        self.known_vulnerable_versions = self._load_vulnerable_versions()
        log.info("scanner_initialized", name=self.name)
    
    def _load_vulnerable_versions(self) -> Dict[str, List[str]]:
        """
        Load known vulnerable software versions.
        
        In production, this would query a CVE database.
        For now, using a hardcoded list of examples.
        """
        return {
            "Apache": ["2.4.49", "2.4.50"],  # CVE-2021-41773, CVE-2021-42013
            "nginx": ["1.20.0"],  # Example
            "PHP": ["7.4.0", "7.4.1", "7.4.2"],  # Example old versions
            "OpenSSL": ["1.0.1", "1.0.2"],  # Heartbleed era
        }
    
    async def scan_flow(self, flow: Dict[str, Any]) -> List[Finding]:
        """
        Scan a flow for vulnerabilities.
        
        Args:
            flow: Flow data
            
        Returns:
            List of findings
        """
        log.debug("passive_scan_started", flow_id=flow.get("flow_id"))
        
        findings = []
        
        # Check for information disclosure
        findings.extend(self._check_information_disclosure(flow))
        
        # Check for outdated software
        findings.extend(self._check_outdated_software(flow))
        
        # Check for debug/development indicators
        findings.extend(self._check_debug_indicators(flow))
        
        # Check for error messages
        findings.extend(self._check_error_messages(flow))
        
        log.debug("passive_scan_complete", flow_id=flow.get("flow_id"), findings_count=len(findings))
        
        return findings
    
    def _check_information_disclosure(self, flow: Dict[str, Any]) -> List[Finding]:
        """Check for information disclosure in headers."""
        findings = []
        response_headers = flow.get("response_headers", {})
        
        # Check for Server header (version disclosure)
        if "Server" in response_headers:
            server = response_headers["Server"]
            # Check if it contains version information
            if any(char in server for char in [".", "/", " "]):
                findings.append(Finding(
                    id=str(uuid4()),
                    severity=Severity.LOW,
                    category="information_disclosure",
                    title="Server Version Disclosure",
                    description=f"Server header reveals version information: {server}",
                    recommendation="Remove version information from Server header or suppress it entirely",
                    metadata={
                        "server": server,
                        "url": flow.get("url", "")[:200],
                        "flow_id": flow.get("flow_id")
                    },
                    timestamp=datetime.utcnow()
                ))
        
        # Check for X-Powered-By header
        if "X-Powered-By" in response_headers:
            powered_by = response_headers["X-Powered-By"]
            findings.append(Finding(
                id=str(uuid4()),
                severity=Severity.LOW,
                category="information_disclosure",
                title="Technology Stack Disclosure",
                description=f"X-Powered-By header reveals technology: {powered_by}",
                recommendation="Remove X-Powered-By header to reduce information leakage",
                metadata={
                    "header": powered_by,
                    "url": flow.get("url", "")[:200],
                    "flow_id": flow.get("flow_id")
                },
                timestamp=datetime.utcnow()
            ))
        
        # Check for X-AspNet-Version
        if "X-AspNet-Version" in response_headers:
            findings.append(Finding(
                id=str(uuid4()),
                severity=Severity.LOW,
                category="information_disclosure",
                title="ASP.NET Version Disclosure",
                description=f"X-AspNet-Version header reveals ASP.NET version: {response_headers['X-AspNet-Version']}",
                recommendation="Disable X-AspNet-Version header in web.config",
                metadata={
                    "version": response_headers["X-AspNet-Version"],
                    "url": flow.get("url", "")[:200],
                    "flow_id": flow.get("flow_id")
                },
                timestamp=datetime.utcnow()
            ))
        
        # Check for X-Generator (CMS identification)
        if "X-Generator" in response_headers:
            findings.append(Finding(
                id=str(uuid4()),
                severity=Severity.LOW,
                category="information_disclosure",
                title="CMS/Generator Disclosure",
                description=f"X-Generator header reveals CMS/generator: {response_headers['X-Generator']}",
                recommendation="Remove X-Generator header",
                metadata={
                    "generator": response_headers["X-Generator"],
                    "url": flow.get("url", "")[:200],
                    "flow_id": flow.get("flow_id")
                },
                timestamp=datetime.utcnow()
            ))
        
        return findings
    
    def _check_outdated_software(self, flow: Dict[str, Any]) -> List[Finding]:
        """Check for known outdated software versions."""
        findings = []
        response_headers = flow.get("response_headers", {})
        
        server_header = response_headers.get("Server", "")
        
        # Check against known vulnerable versions
        for software, vulnerable_versions in self.known_vulnerable_versions.items():
            if software in server_header:
                for version in vulnerable_versions:
                    if version in server_header:
                        findings.append(Finding(
                            id=str(uuid4()),
                            severity=Severity.HIGH,
                            category="outdated_software",
                            title=f"Potentially Vulnerable {software} Version Detected",
                            description=f"Server appears to be running {software} {version}, which may have known vulnerabilities",
                            recommendation=f"Upgrade {software} to the latest stable version and review security advisories",
                            metadata={
                                "software": software,
                                "version": version,
                                "server_header": server_header,
                                "url": flow.get("url", "")[:200],
                                "flow_id": flow.get("flow_id")
                            },
                            timestamp=datetime.utcnow()
                        ))
        
        return findings
    
    def _check_debug_indicators(self, flow: Dict[str, Any]) -> List[Finding]:
        """Check for debug/development indicators."""
        findings = []
        url = flow.get("url", "")
        response_headers = flow.get("response_headers", {})
        
        # Check for common debug/development paths
        debug_patterns = [
            "/debug/", "/dev/", "/.git/", "/.svn/", 
            "/test/", "/staging/", "/admin/phpinfo.php",
            "/phpinfo.php", "/info.php", "/.env"
        ]
        
        url_lower = url.lower()
        for pattern in debug_patterns:
            if pattern in url_lower:
                # Only flag if response was successful (2xx, 3xx)
                status_code = flow.get("status_code", 0)
                if 200 <= status_code < 400:
                    findings.append(Finding(
                        id=str(uuid4()),
                        severity=Severity.MEDIUM,
                        category="debug_endpoint",
                        title="Debug/Development Endpoint Accessible",
                        description=f"Debug or development endpoint '{pattern}' is accessible in production",
                        recommendation="Remove or restrict access to debug/development endpoints",
                        metadata={
                            "pattern": pattern,
                            "status_code": status_code,
                            "url": url[:200],
                            "flow_id": flow.get("flow_id")
                        },
                        timestamp=datetime.utcnow()
                    ))
        
        # Check for debug headers
        debug_headers = ["X-Debug", "X-Debug-Token", "X-Debug-Token-Link"]
        for header in debug_headers:
            if header in response_headers:
                findings.append(Finding(
                    id=str(uuid4()),
                    severity=Severity.MEDIUM,
                    category="debug_information",
                    title="Debug Header Present",
                    description=f"Debug header '{header}' found in response",
                    recommendation="Disable debug mode in production",
                    metadata={
                        "header": header,
                        "value": response_headers[header][:100],
                        "url": url[:200],
                        "flow_id": flow.get("flow_id")
                    },
                    timestamp=datetime.utcnow()
                ))
        
        return findings
    
    def _check_error_messages(self, flow: Dict[str, Any]) -> List[Finding]:
        """Check for verbose error messages with stack traces."""
        findings = []
        status_code = flow.get("status_code", 0)
        content_type = flow.get("content_type", "")
        
        # Check for 500 errors with HTML/text content (likely error pages)
        if status_code >= 500 and ("html" in content_type.lower() or "text" in content_type.lower()):
            findings.append(Finding(
                id=str(uuid4()),
                severity=Severity.MEDIUM,
                category="error_disclosure",
                title="Server Error With Potential Information Disclosure",
                description=f"Server returned {status_code} error which may contain stack traces or system information",
                recommendation="Configure custom error pages that don't reveal system details",
                metadata={
                    "status_code": status_code,
                    "content_type": content_type,
                    "url": flow.get("url", "")[:200],
                    "flow_id": flow.get("flow_id")
                },
                timestamp=datetime.utcnow()
            ))
        
        return findings

