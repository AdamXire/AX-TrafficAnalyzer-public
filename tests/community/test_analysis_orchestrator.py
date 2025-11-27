"""
Tests for Analysis Orchestrator (Phase 5).
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime


class TestAnalysisOrchestrator:
    """Tests for AnalysisOrchestrator class."""
    
    @pytest.fixture
    def mock_db_manager(self):
        """Create mock database manager."""
        db = Mock()
        db.get_session = MagicMock(return_value=AsyncMock())
        return db
    
    @pytest.fixture
    def config(self):
        """Create test config."""
        return {
            "analysis": {
                "enabled": True,
                "http_analyzer": True,
                "tls_analyzer": False,
                "dns_analyzer": False,
                "passive_scanner": True,
                "max_analysis_time_ms": 100,
                "max_concurrent_analyses": 10,
                "cache": {
                    "enabled": True,
                    "max_size": 100,
                    "ttl_seconds": 60
                }
            }
        }
    
    def test_orchestrator_initialization(self, mock_db_manager, config):
        """Test orchestrator initializes with correct analyzers."""
        from src.community.analysis import AnalysisOrchestrator
        
        orchestrator = AnalysisOrchestrator(db_manager=mock_db_manager, config=config)
        
        assert orchestrator is not None
        assert orchestrator.db_manager == mock_db_manager
        enabled = orchestrator.get_enabled_analyzers()
        assert "http_analyzer" in enabled
        assert "passive_scanner" in enabled
    
    def test_orchestrator_disabled_analyzers(self, mock_db_manager, config):
        """Test orchestrator respects disabled analyzers."""
        config["analysis"]["http_analyzer"] = False
        config["analysis"]["passive_scanner"] = False
        
        from src.community.analysis import AnalysisOrchestrator
        
        orchestrator = AnalysisOrchestrator(db_manager=mock_db_manager, config=config)
        enabled = orchestrator.get_enabled_analyzers()
        
        assert "http_analyzer" not in enabled
        assert "passive_scanner" not in enabled
    
    @pytest.mark.asyncio
    async def test_analyze_flow_basic(self, mock_db_manager, config):
        """Test basic flow analysis."""
        from src.community.analysis import AnalysisOrchestrator
        
        orchestrator = AnalysisOrchestrator(db_manager=mock_db_manager, config=config)
        
        flow_data = {
            "flow_id": "test-flow-123",
            "session_id": "test-session-456",
            "method": "GET",
            "url": "https://example.com/api/test",
            "status_code": 200,
            "request_headers": {"User-Agent": "Test"},
            "response_headers": {"Content-Type": "application/json"},
            "cookies": {},
            "auth_detected": None,
            "duration_ms": 50
        }
        
        # analyze_flow is sync but runs async internally
        orchestrator.analyze_flow(flow_data)
        # Should not raise
    
    def test_get_metrics(self, mock_db_manager, config):
        """Test metrics retrieval."""
        from src.community.analysis import AnalysisOrchestrator
        
        orchestrator = AnalysisOrchestrator(db_manager=mock_db_manager, config=config)
        metrics = orchestrator.get_metrics()
        
        assert "total_flows_analyzed" in metrics
        assert "total_findings_generated" in metrics
        assert "enabled_analyzers" in metrics


class TestHTTPAnalyzer:
    """Tests for HTTP Protocol Analyzer."""
    
    @pytest.fixture
    def analyzer(self):
        """Create HTTP analyzer instance."""
        from src.community.analysis.protocol.http_analyzer import HTTPAnalyzer
        return HTTPAnalyzer()
    
    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initializes correctly."""
        assert analyzer.name == "http_analyzer"
        rules = analyzer.get_rules()
        assert len(rules) > 0
    
    @pytest.mark.asyncio
    async def test_check_security_headers_missing(self, analyzer):
        """Test detection of missing security headers."""
        flow = {
            "flow_id": "test-123",
            "session_id": "session-456",
            "url": "https://example.com",
            "response_headers": {}  # Missing all security headers
        }
        
        result = await analyzer.analyze(flow)
        
        assert result is not None
        assert result.analyzer_name == "http_analyzer"
        # Should find missing security headers
        security_findings = [f for f in result.findings if "Security Header" in f.title]
        assert len(security_findings) > 0
    
    @pytest.mark.asyncio
    async def test_check_security_headers_present(self, analyzer):
        """Test no findings when security headers present."""
        flow = {
            "flow_id": "test-123",
            "session_id": "session-456",
            "url": "https://example.com",
            "response_headers": {
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'"
            }
        }
        
        result = await analyzer.analyze(flow)
        
        security_findings = [f for f in result.findings if "Security Header" in f.title]
        assert len(security_findings) == 0
    
    @pytest.mark.asyncio
    async def test_check_insecure_cookies(self, analyzer):
        """Test detection of insecure cookies."""
        flow = {
            "flow_id": "test-123",
            "session_id": "session-456",
            "url": "https://example.com",
            "response_headers": {},
            "cookies": {"raw": "session=abc123; Path=/"}  # Missing Secure, HttpOnly
        }
        
        result = await analyzer.analyze(flow)
        
        cookie_findings = [f for f in result.findings if "Cookie" in f.title]
        assert len(cookie_findings) >= 1
    
    @pytest.mark.asyncio
    async def test_check_sensitive_data_in_url(self, analyzer):
        """Test detection of sensitive data in URL."""
        flow = {
            "flow_id": "test-123",
            "session_id": "session-456",
            "url": "https://example.com/api?password=secret123&apikey=xyz",
            "response_headers": {}
        }
        
        result = await analyzer.analyze(flow)
        
        sensitive_findings = [f for f in result.findings if "Sensitive Data" in f.title]
        assert len(sensitive_findings) >= 1
    
    @pytest.mark.asyncio
    async def test_check_auth_over_http(self, analyzer):
        """Test detection of authentication over HTTP."""
        flow = {
            "flow_id": "test-123",
            "session_id": "session-456",
            "url": "http://example.com/api",  # HTTP not HTTPS
            "auth_detected": "Bearer",
            "response_headers": {}
        }
        
        result = await analyzer.analyze(flow)
        
        auth_findings = [f for f in result.findings if "Authentication" in f.title]
        assert len(auth_findings) >= 1


class TestPassiveScanner:
    """Tests for Passive Vulnerability Scanner."""
    
    @pytest.fixture
    def scanner(self):
        """Create passive scanner instance."""
        from src.community.analysis.scanner.passive import PassiveScanner
        return PassiveScanner()
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly."""
        assert scanner.name == "passive_scanner"
    
    @pytest.mark.asyncio
    async def test_check_server_version_disclosure(self, scanner):
        """Test detection of server version disclosure."""
        flow = {
            "flow_id": "test-123",
            "response_headers": {
                "Server": "Apache/2.4.41 (Ubuntu)"
            }
        }
        
        findings = await scanner.scan_flow(flow)
        
        server_findings = [f for f in findings if "Server" in f.title]
        assert len(server_findings) >= 1
    
    @pytest.mark.asyncio
    async def test_check_x_powered_by_disclosure(self, scanner):
        """Test detection of X-Powered-By disclosure."""
        flow = {
            "flow_id": "test-123",
            "response_headers": {
                "X-Powered-By": "PHP/7.4.3"
            }
        }
        
        findings = await scanner.scan_flow(flow)
        
        tech_findings = [f for f in findings if "Technology" in f.title or "X-Powered-By" in str(f)]
        assert len(tech_findings) >= 1
    
    @pytest.mark.asyncio
    async def test_no_findings_clean_headers(self, scanner):
        """Test no findings when headers are clean."""
        flow = {
            "flow_id": "test-123",
            "response_headers": {
                "Content-Type": "application/json"
            }
        }
        
        findings = await scanner.scan_flow(flow)
        
        # Should have minimal or no findings
        assert len(findings) <= 1


class TestAnalysisCache:
    """Tests for Analysis Cache."""
    
    @pytest.fixture
    def cache(self):
        """Create cache instance."""
        from src.community.analysis.cache import AnalysisCache
        return AnalysisCache(max_size=10, ttl_seconds=60)
    
    def test_cache_initialization(self, cache):
        """Test cache initializes correctly."""
        assert cache.max_size == 10
        # ttl is stored as timedelta
        assert cache.ttl.total_seconds() == 60
    
    def test_cache_set_get(self, cache):
        """Test cache set and get."""
        cache.set("flow1", "http_analyzer", {"result": "value1"})
        result = cache.get("flow1", "http_analyzer")
        
        assert result is not None
        assert result["result"] == "value1"
    
    def test_cache_miss(self, cache):
        """Test cache miss returns None."""
        result = cache.get("nonexistent", "http_analyzer")
        assert result is None
    
    def test_cache_eviction(self, cache):
        """Test cache evicts oldest entries when full."""
        # Fill cache beyond max_size
        for i in range(15):
            cache.set(f"flow{i}", "http_analyzer", {"value": i})
        
        # First entries should be evicted
        assert cache.get("flow0", "http_analyzer") is None
        # Recent entries should exist
        assert cache.get("flow14", "http_analyzer") is not None
    
    def test_cache_stats(self, cache):
        """Test cache statistics."""
        cache.set("flow1", "http_analyzer", {"value": 1})
        cache.get("flow1", "http_analyzer")  # Hit
        cache.get("flow2", "http_analyzer")  # Miss
        
        stats = cache.get_stats()
        assert "size" in stats
        assert "max_size" in stats
        assert "ttl_seconds" in stats


class TestAnalysisMetrics:
    """Tests for Analysis Metrics."""
    
    @pytest.fixture
    def metrics(self):
        """Create metrics instance."""
        from src.community.analysis.metrics import AnalysisMetrics
        return AnalysisMetrics()
    
    def test_metrics_initialization(self, metrics):
        """Test metrics initializes correctly."""
        assert metrics.counters["flows_analyzed"] == 0
        assert metrics.counters["findings_generated"] == 0
        assert metrics.counters["errors"] == 0
    
    def test_record_analysis(self, metrics):
        """Test recording analysis."""
        metrics.record_analysis(
            analyzer_name="http_analyzer",
            duration_ms=50,
            findings_count=3,
            findings_severities={"high": 1, "medium": 2},
            findings_categories={"security_headers": 2, "cookies": 1}
        )
        
        assert metrics.counters["flows_analyzed"] == 1
        assert metrics.counters["findings_generated"] == 3
    
    def test_record_error(self, metrics):
        """Test recording error."""
        metrics.record_analysis(
            analyzer_name="http_analyzer",
            duration_ms=10,
            findings_count=0,
            findings_severities={},
            findings_categories={},
            error=True
        )
        
        assert metrics.counters["errors"] == 1
    
    def test_get_stats(self, metrics):
        """Test getting metrics stats."""
        metrics.record_analysis(
            analyzer_name="http_analyzer",
            duration_ms=30,
            findings_count=2,
            findings_severities={"high": 2},
            findings_categories={"security": 2}
        )
        metrics.record_analysis(
            analyzer_name="passive_scanner",
            duration_ms=20,
            findings_count=1,
            findings_severities={"low": 1},
            findings_categories={"info": 1}
        )
        
        stats = metrics.get_stats()
        
        assert stats["total_flows_analyzed"] == 2
        assert stats["total_findings_generated"] == 3
        assert "analyzer_performance" in stats

