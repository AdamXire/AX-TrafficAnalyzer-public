"""
@fileoverview Analysis Metrics - Performance monitoring for analyzers
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Metrics collection for analysis performance monitoring.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict
from ..core.logging import get_logger

log = get_logger(__name__)


class AnalysisMetrics:
    """
    Metrics collector for analysis operations.
    
    Tracks:
    - Analysis throughput (flows/second)
    - Finding generation rate
    - Error rates
    - Performance (avg analysis time)
    - Severity distribution
    """
    
    def __init__(self):
        """Initialize metrics collector."""
        self.counters = {
            "flows_analyzed": 0,
            "findings_generated": 0,
            "errors": 0,
            "database_errors": 0
        }
        
        self.timings = []  # List of (timestamp, duration_ms) tuples
        self.severity_counts = defaultdict(int)
        self.category_counts = defaultdict(int)
        self.analyzer_performance = defaultdict(list)  # analyzer_name -> [durations]
        
        self.start_time = datetime.utcnow()
        log.info("analysis_metrics_initialized")
    
    def record_analysis(
        self,
        analyzer_name: str,
        duration_ms: float,
        findings_count: int,
        findings_severities: Dict[str, int],
        findings_categories: Dict[str, int],
        error: bool = False
    ) -> None:
        """
        Record an analysis operation.
        
        Args:
            analyzer_name: Name of the analyzer
            duration_ms: Analysis duration in milliseconds
            findings_count: Number of findings generated
            findings_severities: Dict of severity -> count
            findings_categories: Dict of category -> count
            error: Whether an error occurred
        """
        self.counters["flows_analyzed"] += 1
        self.counters["findings_generated"] += findings_count
        
        if error:
            self.counters["errors"] += 1
        
        # Record timing (keep last 1000)
        self.timings.append((datetime.utcnow(), duration_ms))
        if len(self.timings) > 1000:
            self.timings.pop(0)
        
        # Record analyzer performance
        self.analyzer_performance[analyzer_name].append(duration_ms)
        if len(self.analyzer_performance[analyzer_name]) > 100:
            self.analyzer_performance[analyzer_name].pop(0)
        
        # Update severity/category counts
        for severity, count in findings_severities.items():
            self.severity_counts[severity] += count
        
        for category, count in findings_categories.items():
            self.category_counts[category] += count
    
    def get_stats(self, window_minutes: int = 60) -> Dict[str, Any]:
        """
        Get statistics for the last N minutes.
        
        Args:
            window_minutes: Time window in minutes
            
        Returns:
            Dictionary with statistics
        """
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=window_minutes)
        
        # Filter timings within window
        recent_timings = [
            duration for timestamp, duration in self.timings
            if timestamp >= window_start
        ]
        
        # Calculate throughput
        recent_flows = len(recent_timings)
        window_seconds = window_minutes * 60
        throughput = recent_flows / window_seconds if window_seconds > 0 else 0
        
        # Calculate average analysis time
        avg_time_ms = sum(recent_timings) / len(recent_timings) if recent_timings else 0.0
        
        # Calculate error rate
        total_operations = self.counters["flows_analyzed"]
        error_rate = (self.counters["errors"] / total_operations * 100) if total_operations > 0 else 0.0
        
        # Analyzer performance
        analyzer_stats = {}
        for analyzer_name, durations in self.analyzer_performance.items():
            if durations:
                analyzer_stats[analyzer_name] = {
                    "avg_time_ms": sum(durations) / len(durations),
                    "min_time_ms": min(durations),
                    "max_time_ms": max(durations),
                    "count": len(durations)
                }
        
        return {
            "total_flows_analyzed": self.counters["flows_analyzed"],
            "total_findings_generated": self.counters["findings_generated"],
            "total_errors": self.counters["errors"],
            "error_rate_percent": round(error_rate, 2),
            "throughput_flows_per_second": round(throughput, 2),
            "avg_analysis_time_ms": round(avg_time_ms, 2),
            "window_minutes": window_minutes,
            "recent_flows": recent_flows,
            "severity_distribution": dict(self.severity_counts),
            "category_distribution": dict(self.category_counts),
            "analyzer_performance": analyzer_stats,
            "uptime_seconds": (now - self.start_time).total_seconds()
        }
    
    def reset(self) -> None:
        """Reset all metrics (for testing)."""
        self.counters = {
            "flows_analyzed": 0,
            "findings_generated": 0,
            "errors": 0,
            "database_errors": 0
        }
        self.timings.clear()
        self.severity_counts.clear()
        self.category_counts.clear()
        self.analyzer_performance.clear()
        self.start_time = datetime.utcnow()
        log.info("analysis_metrics_reset")

