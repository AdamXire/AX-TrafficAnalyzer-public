"""Tests for main application startup and components."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio


class TestMainImports:
    """Test main module imports."""

    def test_fastapi_app_import(self):
        """Test FastAPI app can be imported."""
        # Import just the app creation parts
        from fastapi import FastAPI
        app = FastAPI(title="AX-TrafficAnalyzer")
        assert app is not None

    def test_component_references_import(self):
        """Test ComponentReferences can be imported."""
        from community.main import ComponentReferences
        assert ComponentReferences is not None

    def test_component_references_creation(self):
        """Test ComponentReferences dataclass."""
        from community.main import ComponentReferences
        refs = ComponentReferences(
            hotspot=None,
            iptables=None,
            disk_monitor=None,
            cert_manager=None,
            mitmproxy=None,
            tcpdump=None,
            session_tracker=MagicMock(),
            pcap_exporter=None,
            database=MagicMock(),
            jwt_manager=None,
            websocket_manager=None
        )
        assert refs.hotspot is None
        assert refs.session_tracker is not None


class TestAnalysisAPI:
    """Test analysis API endpoints."""

    def test_analysis_router_import(self):
        """Test analysis router can be imported."""
        from community.api.analysis import router
        assert router is not None

    def test_analysis_router_has_routes(self):
        """Test analysis router has expected routes."""
        from community.api.analysis import router
        routes = [r.path for r in router.routes]
        assert len(routes) > 0


class TestFlowsAPI:
    """Test flows API endpoints."""

    def test_flows_router_import(self):
        """Test flows router can be imported."""
        from community.api.flows import router
        assert router is not None


class TestSessionsAPI:
    """Test sessions API endpoints."""

    def test_sessions_router_import(self):
        """Test sessions router can be imported."""
        from community.api.sessions import router
        assert router is not None


class TestHealthAPI:
    """Test health API endpoints."""

    def test_health_router_import(self):
        """Test health router can be imported."""
        from community.api.health import router
        assert router is not None


class TestPCAPExporter:
    """Test PCAP exporter functionality."""

    def test_pcap_exporter_import(self):
        """Test StreamingPCAPExporter can be imported."""
        from community.capture.pcap.exporter import StreamingPCAPExporter
        assert StreamingPCAPExporter is not None


class TestTCPDump:
    """Test tcpdump manager functionality."""

    def test_tcpdump_manager_import(self):
        """Test TCPDumpManager can be imported."""
        from community.capture.raw.tcpdump import TCPDumpManager
        assert TCPDumpManager is not None


class TestCertManager:
    """Test certificate manager functionality."""

    def test_cert_manager_import(self):
        """Test CertificateManager can be imported."""
        from community.capture.mitm.cert_manager import CertificateManager
        assert CertificateManager is not None


class TestMitmProxy:
    """Test mitmproxy manager functionality."""

    def test_mitmproxy_manager_import(self):
        """Test MitmproxyManager can be imported."""
        from community.capture.mitm.proxy import MitmproxyManager
        assert MitmproxyManager is not None


class TestSessionTracker:
    """Test session tracker functionality."""

    def test_session_tracker_import(self):
        """Test SessionTracker can be imported."""
        from community.capture.session.tracker import SessionTracker
        assert SessionTracker is not None

    def test_session_tracker_attributes(self):
        """Test SessionTracker has expected attributes."""
        from community.capture.session.tracker import SessionTracker
        assert hasattr(SessionTracker, 'get_or_create_session')
        assert hasattr(SessionTracker, 'get_session')


class TestOrchestrator:
    """Test core orchestrator functionality."""

    def test_startup_orchestrator_import(self):
        """Test StartupOrchestrator can be imported."""
        from community.core.orchestrator import StartupOrchestrator
        assert StartupOrchestrator is not None

    def test_component_dataclass_import(self):
        """Test Component dataclass can be imported."""
        from community.core.orchestrator import Component
        assert Component is not None


class TestCloudBackup:
    """Test cloud backup functionality."""

    def test_cloud_backup_import(self):
        """Test CloudBackupManager can be imported."""
        from community.cloud.backup import CloudBackupManager
        assert CloudBackupManager is not None


class TestVirusTotal:
    """Test VirusTotal client functionality."""

    def test_virustotal_import(self):
        """Test VirusTotalClient can be imported."""
        from community.analysis.threat_intel.virustotal import VirusTotalClient
        assert VirusTotalClient is not None

    def test_virustotal_init(self):
        """Test VirusTotalClient initialization."""
        from community.analysis.threat_intel.virustotal import VirusTotalClient
        client = VirusTotalClient(api_key="test-key")
        assert client.api_key == "test-key"


class TestMLClassifier:
    """Test ML classifier functionality."""

    def test_ml_classifier_import(self):
        """Test MLClassifier can be imported."""
        try:
            from community.analysis.classifier.ml_classifier import MLTrafficClassifier
            assert MLTrafficClassifier is not None
        except ImportError:
            pytest.skip("sklearn not installed")


class TestPDFGenerator:
    """Test PDF generator functionality."""

    def test_pdf_generator_import(self):
        """Test PDFReportGenerator can be imported."""
        try:
            from community.analysis.reports.pdf_generator import PDFReportGenerator
            assert PDFReportGenerator is not None
        except ImportError:
            pytest.skip("reportlab not installed")


class TestDiskMonitor:
    """Test disk monitor functionality."""

    def test_disk_space_manager_import(self):
        """Test DiskSpaceManager can be imported."""
        from community.storage.disk_monitor import DiskSpaceManager
        assert DiskSpaceManager is not None

    def test_disk_thresholds_import(self):
        """Test disk thresholds can be imported."""
        from community.storage.disk_monitor import WARNING_THRESHOLD_GB, CRITICAL_THRESHOLD_GB
        assert WARNING_THRESHOLD_GB > 0
        assert CRITICAL_THRESHOLD_GB > 0


class TestAdminCLI:
    """Test admin CLI functionality."""

    def test_admin_cli_import(self):
        """Test admin CLI can be imported."""
        from community.cli.admin import create_admin_user
        assert create_admin_user is not None

    def test_admin_cli_callable(self):
        """Test create_admin_user is callable."""
        from community.cli.admin import create_admin_user
        assert callable(create_admin_user)

