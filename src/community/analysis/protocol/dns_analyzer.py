"""
@fileoverview DNS Analyzer - DNS query analysis and leak detection
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

DNS analyzer for detecting leaks, suspicious domains, and DNS tunneling.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import Dict, Any, List
from ...analysis.base import BaseAnalyzer, AnalysisResult, Finding, Severity
from datetime import datetime
from uuid import uuid4
from ...core.logging import get_logger
import re

log = get_logger(__name__)


class DNSAnalyzer(BaseAnalyzer):
    """
    Analyzes DNS queries for leaks and suspicious domains.
    
    Detects:
    - DNS leaks (queries outside expected DNS servers)
    - Suspicious domains (DGA patterns, typosquatting)
    - DNS tunneling indicators
    - Unusual query patterns
    """
    
    def __init__(self):
        super().__init__("dns_analyzer")
        # Common suspicious TLDs
        self.suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]
        # DGA patterns (Domain Generation Algorithm indicators)
        self.dga_patterns = [
            r'[a-z]{10,}',  # Long random strings
            r'[0-9]{5,}',   # Many numbers
            r'[a-z0-9]{20,}',  # Very long alphanumeric
        ]
        log.info("analyzer_initialized", name=self.name)
    
    async def analyze(self, query: Dict[str, Any]) -> AnalysisResult:
        """
        Analyze DNS query.
        
        Args:
            query: DNS query data from tcpdump PCAP
                Expected format:
                {
                    "query": "example.com",
                    "query_type": "A",
                    "response": {"ips": ["1.2.3.4"]},
                    "session_id": "...",
                    "timestamp": "..."
                }
            
        Returns:
            AnalysisResult with findings
        """
        log.debug("dns_analysis_started", query=query.get("query"))
        
        findings = []
        
        domain = query.get("query", "")
        query_type = query.get("query_type", "A")
        
        if not domain:
            return AnalysisResult(
                analyzer_name=self.name,
                flow_id=None,
                session_id=query.get("session_id"),
                findings=[],
                metadata={"reason": "no_domain"},
                timestamp=datetime.utcnow()
            )
        
        # Check for suspicious TLDs
        findings.extend(self._check_suspicious_tld(domain))
        
        # Check for DGA patterns
        findings.extend(self._check_dga_patterns(domain))
        
        # Check for typosquatting (simplified)
        findings.extend(self._check_typosquatting(domain))
        
        # Check for DNS tunneling indicators
        findings.extend(self._check_dns_tunneling(query))
        
        log.debug("dns_analysis_complete", 
                 query=domain, 
                 findings_count=len(findings))
        
        return AnalysisResult(
            analyzer_name=self.name,
            flow_id=None,
            session_id=query.get("session_id"),
            findings=findings,
            metadata={
                "query": domain,
                "query_type": query_type,
                "has_response": query.get("response") is not None
            },
            timestamp=datetime.utcnow()
        )
    
    def _check_suspicious_tld(self, domain: str) -> List[Finding]:
        """Check for suspicious top-level domains."""
        findings = []
        
        domain_lower = domain.lower()
        for tld in self.suspicious_tlds:
            if domain_lower.endswith(tld):
                findings.append(Finding(
                    id=str(uuid4()),
                    severity=Severity.MEDIUM,
                    category="suspicious_domain",
                    title=f"Suspicious TLD: {tld}",
                    description=f"Domain uses suspicious TLD {tld}, commonly used for malicious purposes",
                    recommendation="Review domain legitimacy and consider blocking",
                    metadata={"domain": domain, "tld": tld},
                    timestamp=datetime.utcnow()
                ))
                break
        
        return findings
    
    def _check_dga_patterns(self, domain: str) -> List[Finding]:
        """Check for Domain Generation Algorithm patterns."""
        findings = []
        
        # Remove TLD for pattern matching
        domain_part = domain.split('.')[0] if '.' in domain else domain
        
        for pattern in self.dga_patterns:
            if re.match(pattern, domain_part, re.IGNORECASE):
                findings.append(Finding(
                    id=str(uuid4()),
                    severity=Severity.HIGH,
                    category="dga_domain",
                    title="Potential DGA Domain Detected",
                    description=f"Domain '{domain}' matches DGA pattern, may be generated by malware",
                    recommendation="Investigate domain and consider blocking",
                    metadata={"domain": domain, "pattern": pattern},
                    timestamp=datetime.utcnow()
                ))
                break
        
        return findings
    
    def _check_typosquatting(self, domain: str) -> List[Finding]:
        """Check for typosquatting (simplified detection)."""
        findings = []
        
        # Common typosquatting patterns (simplified)
        suspicious_patterns = [
            "paypa1", "paypai",  # PayPal typos
            "goog1e", "g00gle",  # Google typos
            "faceb00k", "fac3book",  # Facebook typos
        ]
        
        domain_lower = domain.lower()
        for pattern in suspicious_patterns:
            if pattern in domain_lower:
                findings.append(Finding(
                    id=str(uuid4()),
                    severity=Severity.MEDIUM,
                    category="typosquatting",
                    title="Potential Typosquatting Domain",
                    description=f"Domain '{domain}' may be a typosquatting attempt",
                    recommendation="Verify domain legitimacy before accessing",
                    metadata={"domain": domain, "pattern": pattern},
                    timestamp=datetime.utcnow()
                ))
                break
        
        return findings
    
    def _check_dns_tunneling(self, query: Dict[str, Any]) -> List[Finding]:
        """Check for DNS tunneling indicators."""
        findings = []
        
        domain = query.get("query", "")
        query_type = query.get("query_type", "A")
        
        # DNS tunneling often uses TXT queries with long subdomains
        if query_type == "TXT" and len(domain) > 100:
            findings.append(Finding(
                id=str(uuid4()),
                severity=Severity.HIGH,
                category="dns_tunneling",
                title="Potential DNS Tunneling Detected",
                description=f"Unusually long TXT query ({len(domain)} chars) may indicate DNS tunneling",
                recommendation="Investigate for data exfiltration",
                metadata={"domain": domain[:100], "query_type": query_type, "length": len(domain)},
                timestamp=datetime.utcnow()
            ))
        
        # Multiple subdomains can indicate tunneling
        subdomain_count = domain.count('.')
        if subdomain_count > 5:
            findings.append(Finding(
                id=str(uuid4()),
                severity=Severity.MEDIUM,
                category="dns_tunneling",
                title="Unusual DNS Query Pattern",
                description=f"Domain has {subdomain_count} subdomains, may indicate DNS tunneling",
                recommendation="Review query pattern for suspicious activity",
                metadata={"domain": domain, "subdomain_count": subdomain_count},
                timestamp=datetime.utcnow()
            ))
        
        return findings
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """Return detection rules."""
        return [
            {
                "id": "suspicious_tld",
                "check": "tld",
                "severity": Severity.MEDIUM,
                "category": "suspicious_domain"
            },
            {
                "id": "dga_domain",
                "check": "dga_pattern",
                "severity": Severity.HIGH,
                "category": "dga_domain"
            },
            {
                "id": "dns_tunneling",
                "check": "tunneling",
                "severity": Severity.HIGH,
                "category": "dns_tunneling"
            }
        ]

