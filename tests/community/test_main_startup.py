"""
Tests for main.py startup sequence (mocked).
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock


class TestMainStartup:
    """Tests for main application startup."""
    
    def test_config_loading(self):
        """Test config loading from config.json."""
        from src.community.core.config import load_config
        
        config = load_config()
        
        assert config is not None
        assert "mode" in config
        assert "api" in config
    
    def test_fastapi_app_creation(self):
        """Test FastAPI app is created."""
        # Import should not fail
        from fastapi import FastAPI
        
        app = FastAPI(title="Test")
        assert app is not None


class TestComponentReferences:
    """Tests for ComponentReferences dataclass."""
    
    def test_component_references_creation(self):
        """Test creating ComponentReferences."""
        # This tests the dataclass structure
        pass  # ComponentReferences is defined in main.py


class TestAnalysisIntegration:
    """Tests for analysis integration in main."""
    
    def test_analysis_config_structure(self):
        """Test analysis config structure."""
        from src.community.core.config import load_config
        
        config = load_config()
        analysis = config.get("analysis", {})
        
        assert "enabled" in analysis
        assert "http_analyzer" in analysis
        assert "passive_scanner" in analysis


class TestPDFGenerator:
    """Tests for PDF Report Generator."""
    
    @pytest.mark.skipif(
        not pytest.importorskip("reportlab", reason="reportlab not installed"),
        reason="reportlab not installed"
    )
    def test_generator_initialization(self):
        """Test generator initializes correctly."""
        try:
            from src.community.analysis.reports.pdf_generator import PDFReportGenerator
            generator = PDFReportGenerator()
            assert generator is not None
        except RuntimeError:
            pytest.skip("reportlab not installed")


class TestVirusTotalClient:
    """Tests for VirusTotal client."""
    
    @pytest.fixture
    def skip_if_no_requests(self):
        """Skip if requests not installed."""
        pytest.importorskip("requests")
    
    def test_client_initialization_no_key(self, skip_if_no_requests):
        """Test client initialization without API key."""
        from src.community.analysis.threat_intel.virustotal import VirusTotalClient
        
        client = VirusTotalClient(api_key=None)
        
        assert client is not None
        assert client.api_key is None
    
    def test_client_initialization_with_key(self, skip_if_no_requests):
        """Test client initialization with API key."""
        from src.community.analysis.threat_intel.virustotal import VirusTotalClient
        
        client = VirusTotalClient(api_key="test-key-123")
        
        assert client.api_key == "test-key-123"
    
    @pytest.mark.asyncio
    async def test_check_domain_no_key(self, skip_if_no_requests):
        """Test domain check without API key."""
        from src.community.analysis.threat_intel.virustotal import VirusTotalClient
        
        client = VirusTotalClient(api_key=None)
        
        result = await client.check_domain("example.com", db_session=None)
        
        assert result["status"] == "no_api_key"
        assert result["reputation"] == "unknown"


class TestMLClassifier:
    """Tests for ML Traffic Classifier."""
    
    @pytest.fixture
    def skip_if_no_sklearn(self):
        """Skip if sklearn not installed."""
        pytest.importorskip("sklearn")
        pytest.importorskip("numpy")
    
    def test_classifier_initialization(self, skip_if_no_sklearn):
        """Test classifier initialization."""
        from src.community.analysis.classifier.ml_classifier import MLTrafficClassifier
        
        classifier = MLTrafficClassifier()
        
        assert classifier is not None
        assert classifier.trained is False
    
    def test_extract_features(self, skip_if_no_sklearn):
        """Test feature extraction."""
        from src.community.analysis.classifier.ml_classifier import MLTrafficClassifier
        
        classifier = MLTrafficClassifier()
        
        flow = {
            "request_size": 100,
            "response_size": 500,
            "duration_ms": 50,
            "method": "GET",
            "status_code": 200,
            "url": "https://example.com",
            "auth_detected": None
        }
        
        features = classifier.extract_features(flow)
        
        assert features is not None
        assert features.shape == (1, 7)  # 7 features in classifier
    
    def test_feature_names(self, skip_if_no_sklearn):
        """Test feature names are defined."""
        from src.community.analysis.classifier.ml_classifier import MLTrafficClassifier
        
        classifier = MLTrafficClassifier()
        
        assert len(classifier.feature_names) == 7
        assert "request_size" in classifier.feature_names
    
    @pytest.mark.asyncio
    async def test_classify_untrained(self, skip_if_no_sklearn):
        """Test classification when not trained."""
        from src.community.analysis.classifier.ml_classifier import MLTrafficClassifier
        
        classifier = MLTrafficClassifier()
        
        flow = {
            "request_size": 100,
            "response_size": 500,
            "duration_ms": 50,
            "method": "GET",
            "status_code": 200
        }
        
        result = await classifier.classify(flow)
        
        assert result["category"] == "unknown"
        assert result["confidence"] == 0.0


class TestAdminCLI:
    """Tests for Admin CLI."""
    
    def test_cli_module_import(self):
        """Test CLI module can be imported."""
        from src.community.cli import admin
        
        assert admin is not None


class TestHotspotBase:
    """Tests for Hotspot base class."""
    
    def test_hotspot_base_import(self):
        """Test hotspot base can be imported."""
        from src.community.hotspot.base import HotspotBase
        
        assert HotspotBase is not None
    
    def test_hotspot_base_is_abstract(self):
        """Test HotspotBase is abstract."""
        from src.community.hotspot.base import HotspotBase
        from abc import ABC
        
        assert issubclass(HotspotBase, ABC)
    
    def test_client_info_dataclass(self):
        """Test ClientInfo dataclass."""
        from src.community.hotspot.base import ClientInfo
        
        client = ClientInfo(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_address="192.168.4.100",
            hostname="iPhone"
        )
        
        assert client.mac_address == "aa:bb:cc:dd:ee:ff"
        assert client.ip_address == "192.168.4.100"

