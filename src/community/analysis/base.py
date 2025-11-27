"""
@fileoverview Base Analyzer - Abstract class for all analyzers
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Base classes and interfaces for all traffic analyzers.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class Severity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a vulnerability or anomaly finding."""
    id: str
    severity: Severity
    category: str
    title: str
    description: str
    recommendation: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    timestamp: Optional[datetime] = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


@dataclass
class AnalysisResult:
    """Result from an analyzer."""
    analyzer_name: str
    flow_id: Optional[str]
    session_id: str
    findings: List[Finding]
    metadata: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "analyzer_name": self.analyzer_name,
            "flow_id": self.flow_id,
            "session_id": self.session_id,
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat()
        }


class BaseAnalyzer(ABC):
    """Abstract base class for all analyzers."""
    
    def __init__(self, name: str):
        """
        Initialize analyzer.
        
        Args:
            name: Unique name for this analyzer
        """
        self.name = name
    
    @abstractmethod
    async def analyze(self, flow: Dict[str, Any]) -> AnalysisResult:
        """
        Analyze a flow and return findings.
        
        Args:
            flow: Flow data dictionary with request/response details
            
        Returns:
            AnalysisResult with findings
            
        Raises:
            NotImplementedError: If subclass doesn't implement this method
        """
        pass
    
    @abstractmethod
    def get_rules(self) -> List[Dict[str, Any]]:
        """
        Return list of detection rules used by this analyzer.
        
        Returns:
            List of rule definitions
        """
        pass

