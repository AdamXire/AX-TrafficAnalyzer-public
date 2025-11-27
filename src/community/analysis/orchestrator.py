"""
@fileoverview Analysis Orchestrator - Coordinates all analyzers
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Orchestrates analysis pipeline, running analyzers and storing results.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import List, Dict, Any, Optional
from .protocol import HTTPAnalyzer
from .scanner import PassiveScanner
from .base import AnalysisResult, Finding
from .metrics import AnalysisMetrics
from .cache import AnalysisCache
from ..core.logging import get_logger
from ..storage.models import FindingDB, AnalysisResultDB
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import uuid4
from datetime import datetime
from collections import defaultdict

log = get_logger(__name__)


class AnalysisOrchestrator:
    """
    Orchestrates all analyzers.
    
    Coordinates the analysis pipeline:
    1. HTTP protocol analysis
    2. Passive vulnerability scanning
    3. Stores findings in database
    4. Broadcasts events via WebSocket (if available)
    """
    
    def __init__(self, db_manager=None, config: Optional[Dict[str, Any]] = None):
        """
        Initialize orchestrator.
        
        Args:
            db_manager: Database manager instance
            config: Analysis configuration
        """
        self.db_manager = db_manager
        self.config = config or {}
        self.analysis_config = self.config.get("analysis", {})
        
        # Production hardening: Metrics, caching, and performance monitoring
        self.metrics_collector = AnalysisMetrics()
        cache_config = self.analysis_config.get("cache", {})
        cache_enabled = cache_config.get("enabled", True)
        self.cache = AnalysisCache(
            max_size=cache_config.get("max_size", 1000),
            ttl_seconds=cache_config.get("ttl_seconds", 3600)
        ) if cache_enabled else None
        self._max_analysis_time_ms = self.analysis_config.get("max_analysis_time_ms", 100)  # Fail-fast threshold
        self._max_concurrent_analyses = self.analysis_config.get("max_concurrent_analyses", 10)  # Backpressure
        self._current_analyses = 0  # Track concurrent operations
        
        # Initialize analyzers based on config
        self.analyzers = []
        
        if self.analysis_config.get("http_analyzer", True):
            self.http_analyzer = HTTPAnalyzer()
            self.analyzers.append(self.http_analyzer)
            log.info("http_analyzer_enabled")
        else:
            self.http_analyzer = None
        
        if self.analysis_config.get("passive_scanner", True):
            self.passive_scanner = PassiveScanner()
            self.analyzers.append(self.passive_scanner)
            log.info("passive_scanner_enabled")
        else:
            self.passive_scanner = None
        
        # TLS Analyzer (requires TLS metadata from mitmproxy)
        if self.analysis_config.get("tls_analyzer", False):
            from .protocol import TLSAnalyzer
            self.tls_analyzer = TLSAnalyzer()
            self.analyzers.append(self.tls_analyzer)
            log.info("tls_analyzer_enabled")
        else:
            self.tls_analyzer = None
        
        # DNS Analyzer (requires DNS query data from tcpdump/tshark)
        if self.analysis_config.get("dns_analyzer", False):
            from .protocol import DNSAnalyzer
            self.dns_analyzer = DNSAnalyzer()
            self.analyzers.append(self.dns_analyzer)
            log.info("dns_analyzer_enabled")
        else:
            self.dns_analyzer = None
        
        log.info("analysis_orchestrator_initialized", 
                analyzers_count=len(self.analyzers),
                enabled_analyzers=[a.name for a in self.analyzers])
    
    async def analyze_flow(self, flow: Dict[str, Any], db_session: Optional[AsyncSession] = None) -> List[AnalysisResult]:
        """
        Run all enabled analyzers on a flow with performance monitoring.
        
        Args:
            flow: Flow data dictionary
            db_session: Optional database session (for batch operations)
            
        Returns:
            List of AnalysisResults
        """
        import time
        start_time = time.time()
        
        flow_id = flow.get("flow_id")
        session_id = flow.get("session_id")
        
        if not flow_id or not session_id:
            log.warning("flow_missing_ids", flow_id=flow_id, session_id=session_id)
            return []
        
        # Production hardening: Check concurrent analysis limit (backpressure)
        if self._current_analyses >= self._max_concurrent_analyses:
            log.warning("analysis_backpressure", 
                       current=self._current_analyses,
                       max=self._max_concurrent_analyses,
                       flow_id=flow_id)
            # Return empty results (fail-fast, don't queue)
            return []
        
        self._current_analyses += 1
        
        try:
            log.debug("analyzing_flow", flow_id=flow_id, analyzers_count=len(self.analyzers))
            
            results = []
            
            # Run HTTP analyzer (with caching if enabled)
            if self.http_analyzer:
                # Check cache first
                cached_result = None
                if self.cache:
                    cached_result = self.cache.get(flow_id, self.http_analyzer.name)
                
                if cached_result:
                    log.debug("analysis_cache_hit", flow_id=flow_id, analyzer=self.http_analyzer.name)
                    # For cache hits, still run analysis (findings should be fresh)
                    # Cache is mainly for metadata/performance tracking
                    http_result = await self.http_analyzer.analyze(flow)
                else:
                    http_result = await self.http_analyzer.analyze(flow)
                    # Cache result metadata (not findings, as they're stored in DB)
                    if self.cache:
                        self.cache.set(flow_id, self.http_analyzer.name, {
                            "analyzer_name": http_result.analyzer_name,
                            "findings_count": len(http_result.findings),
                            "metadata": http_result.metadata
                        })
                
                results.append(http_result)
                log.debug("http_analysis_complete", 
                         flow_id=flow_id, 
                         findings_count=len(http_result.findings))
            
            # Run passive scanner
            if self.passive_scanner:
                scanner_findings = await self.passive_scanner.scan_flow(flow)
                if scanner_findings:
                    # Wrap scanner findings in AnalysisResult
                    scanner_result = AnalysisResult(
                        analyzer_name=self.passive_scanner.name,
                        flow_id=flow_id,
                        session_id=session_id,
                        findings=scanner_findings,
                        metadata={"findings_count": len(scanner_findings)},
                        timestamp=datetime.utcnow()
                    )
                    results.append(scanner_result)
                    log.debug("passive_scan_complete", 
                             flow_id=flow_id, 
                             findings_count=len(scanner_findings))
            
            # Run TLS analyzer (if TLS info available and analyzer enabled)
            if self.tls_analyzer and flow.get("tls_info"):
                tls_result = await self.tls_analyzer.analyze(flow)
                if tls_result.findings:
                    results.append(tls_result)
                    log.debug("tls_analysis_complete", 
                             flow_id=flow_id, 
                             findings_count=len(tls_result.findings))
            
            # Store findings in database
            if results and self.db_manager:
                await self._store_findings(results, db_session)
            
            # Update metrics
            analysis_time_ms = (time.time() - start_time) * 1000
            
            # Collect severity and category distributions
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)
            for result in results:
                for finding in result.findings:
                    severity = finding.severity.value if hasattr(finding.severity, 'value') else finding.severity
                    severity_counts[severity] += 1
                    category_counts[finding.category] += 1
            
            # Record metrics for each analyzer
            for result in results:
                analyzer_findings = result.findings
                analyzer_severities = defaultdict(int)
                analyzer_categories = defaultdict(int)
                for finding in analyzer_findings:
                    severity = finding.severity.value if hasattr(finding.severity, 'value') else finding.severity
                    analyzer_severities[severity] += 1
                    analyzer_categories[finding.category] += 1
                
                self.metrics_collector.record_analysis(
                    analyzer_name=result.analyzer_name,
                    duration_ms=analysis_time_ms / len(results),  # Approximate per-analyzer time
                    findings_count=len(analyzer_findings),
                    findings_severities=dict(analyzer_severities),
                    findings_categories=dict(analyzer_categories),
                    error=False
                )
            
            # Fail-fast: Warn if analysis takes too long
            if analysis_time_ms > self._max_analysis_time_ms:
                log.warning("analysis_slow", 
                           flow_id=flow_id,
                           analysis_time_ms=analysis_time_ms,
                           threshold_ms=self._max_analysis_time_ms)
            
            log.debug("flow_analysis_complete", 
                     flow_id=flow_id, 
                     results_count=len(results),
                     total_findings=sum(len(r.findings) for r in results),
                     analysis_time_ms=round(analysis_time_ms, 2))
        
        except Exception as e:
            # Record error in metrics
            self.metrics_collector.record_analysis(
                analyzer_name="unknown",
                duration_ms=(time.time() - start_time) * 1000,
                findings_count=0,
                findings_severities={},
                findings_categories={},
                error=True
            )
            log.error("flow_analysis_failed", 
                     flow_id=flow_id, 
                     error=str(e), 
                     error_type=type(e).__name__)
        finally:
            # Always decrement concurrent counter
            self._current_analyses = max(0, self._current_analyses - 1)
        
        return results
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get analysis metrics for monitoring.
        
        Returns:
            Dictionary with metrics
        """
        stats = self.metrics_collector.get_stats()
        metrics = {
            **stats,
            "enabled_analyzers": self.get_enabled_analyzers(),
            "analyzers_count": len(self.analyzers),
            "max_analysis_time_ms": self._max_analysis_time_ms,
            "max_concurrent_analyses": self._max_concurrent_analyses,
            "current_analyses": self._current_analyses
        }
        
        # Add cache stats if enabled
        if self.cache:
            metrics["cache"] = self.cache.get_stats()
        
        return metrics
    
    async def _store_findings(self, results: List[AnalysisResult], db_session: Optional[AsyncSession] = None) -> None:
        """
        Store findings in database with batch processing optimization.
        
        Args:
            results: List of AnalysisResults
            db_session: Optional database session (for batch operations)
        """
        if not self.db_manager:
            log.debug("db_manager_not_available", message="Skipping findings storage")
            return
        
        # Create a session if not provided
        if db_session is None:
            async with self.db_manager.get_session() as session:
                await self._store_findings_impl(results, session)
            return
        
        await self._store_findings_impl(results, db_session)
    
    async def _store_findings_impl(self, results: List[AnalysisResult], db_session: AsyncSession) -> None:
        """Internal implementation of findings storage."""
        try:
            # Batch process all results for better performance
            analysis_results_to_add = []
            findings_to_add = []
            
            for result in results:
                # Prepare analysis result
                analysis_result_db = AnalysisResultDB(
                    id=str(uuid4()),
                    flow_id=result.flow_id,
                    analyzer_name=result.analyzer_name,
                    timestamp=result.timestamp,
                    meta_data=result.metadata  # Use meta_data (SQLAlchemy reserved name)
                )
                analysis_results_to_add.append(analysis_result_db)
                
                # Prepare findings
                for finding in result.findings:
                    finding_db = FindingDB(
                        id=finding.id,
                        session_id=result.session_id,
                        flow_id=result.flow_id,
                        timestamp=finding.timestamp,
                        severity=finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
                        category=finding.category,
                        title=finding.title,
                        description=finding.description,
                        recommendation=finding.recommendation,
                        meta_data=finding.metadata  # Use meta_data (SQLAlchemy reserved name)
                    )
                    findings_to_add.append(finding_db)
            
            # Batch add all objects
            if analysis_results_to_add:
                db_session.add_all(analysis_results_to_add)
            if findings_to_add:
                db_session.add_all(findings_to_add)
            
            # Single commit for all operations
            await db_session.commit()
            
            log.debug("findings_stored_batch", 
                     results_count=len(results),
                     analysis_results_count=len(analysis_results_to_add),
                     total_findings=len(findings_to_add))
        
        except Exception as e:
            await db_session.rollback()
            log.error("findings_storage_failed", 
                     error=str(e), 
                     error_type=type(e).__name__,
                     results_count=len(results))
            # Don't re-raise - analysis failures shouldn't break capture
    
    async def analyze_session(
        self, 
        session_id: str, 
        db_session: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Analyze all flows in a session and generate summary.
        
        Args:
            session_id: Session ID to analyze
            db_session: Optional database session
            
        Returns:
            Analysis summary
        """
        log.info("analyzing_session", session_id=session_id)
        
        if not self.db_manager:
            log.warning("db_manager_not_available_for_session_analysis")
            return {"error": "Database not available"}
        
        # Get session flows
        # TODO: Query flows from database
        
        # For now, return placeholder
        return {
            "session_id": session_id,
            "status": "complete",
            "message": "Session analysis feature under development"
        }
    
    def get_enabled_analyzers(self) -> List[str]:
        """Get list of enabled analyzer names."""
        return [analyzer.name for analyzer in self.analyzers]
    
    async def analyze_dns_query(
        self, 
        query: Dict[str, Any], 
        db_session: Optional[AsyncSession] = None
    ) -> List[AnalysisResult]:
        """
        Analyze DNS query.
        
        Args:
            query: DNS query data dictionary
            db_session: Optional database session
            
        Returns:
            List of AnalysisResults
        """
        if not self.dns_analyzer:
            return []
        
        session_id = query.get("session_id")
        if not session_id:
            log.warning("dns_query_missing_session_id")
            return []
        
        log.debug("analyzing_dns_query", query=query.get("query"), session_id=session_id)
        
        results = []
        
        try:
            # Run DNS analyzer
            dns_result = await self.dns_analyzer.analyze(query)
            if dns_result.findings:
                results.append(dns_result)
                log.debug("dns_analysis_complete", 
                         query=query.get("query"), 
                         findings_count=len(dns_result.findings))
            
            # Store findings in database
            if results and self.db_manager:
                await self._store_findings(results, db_session)
        
        except Exception as e:
            log.error("dns_analysis_failed", 
                     query=query.get("query"), 
                     error=str(e), 
                     error_type=type(e).__name__)
        
        return results

