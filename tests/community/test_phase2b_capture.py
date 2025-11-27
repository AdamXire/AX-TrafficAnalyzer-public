"""
@fileoverview Phase 2b Traffic Capture Tests
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Integration tests for Phase 2b traffic capture components.
"""

import pytest
import sys
import os
import tempfile
import asyncio
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from community.capture.mitm import MitmproxyManager, CertificateManager
from community.capture.raw import TCPDumpManager
from community.capture.session import SessionTracker
from community.capture.pcap import StreamingPCAPExporter
from community.core.security import KeyringManager
from community.core.platform import get_platform_info
from community.core.memory import RingBuffer, BackpressureController


class TestCertificateManager:
    """Test CertificateManager."""
    
    @pytest.mark.skipif(
        not os.path.exists("/usr/bin/libsecret-tool"),
        reason="libsecret-tool not available"
    )
    def test_cert_manager_initialization(self):
        """Test certificate manager initialization."""
        platform = get_platform_info()
        keyring_mgr = KeyringManager(platform)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_mgr = CertificateManager(cert_dir=tmpdir, keyring_manager=keyring_mgr)
            assert cert_mgr is not None
            print("✓ CertificateManager initialized")
    
    @pytest.mark.skipif(
        not os.path.exists("/usr/bin/libsecret-tool"),
        reason="libsecret-tool not available"
    )
    def test_validate_or_generate_first_run(self):
        """Test certificate generation on first run."""
        platform = get_platform_info()
        keyring_mgr = KeyringManager(platform)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_mgr = CertificateManager(cert_dir=tmpdir, keyring_manager=keyring_mgr)
            # First run should generate certificate
            cert_mgr.validate_or_generate()
            assert cert_mgr.ca_cert_path.exists()
            print("✓ Certificate generated on first run")


class TestMitmproxyManager:
    """Test MitmproxyManager."""
    
    def test_mitmproxy_initialization(self):
        """Test mitmproxy manager initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = MitmproxyManager(port=8080, cert_dir=tmpdir)
            assert manager.port == 8080
            assert manager.cert_dir == Path(tmpdir)
            print("✓ MitmproxyManager initialized")
    
    def test_mitmproxy_status(self):
        """Test mitmproxy status."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = MitmproxyManager(port=8080, cert_dir=tmpdir)
            status = manager.get_status()
            assert "running" in status
            assert "port" in status
            print("✓ MitmproxyManager status check working")


class TestTCPDumpManager:
    """Test TCPDumpManager."""
    
    def test_tcpdump_initialization(self):
        """Test tcpdump manager initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = TCPDumpManager(interface="lo", output_dir=tmpdir, filter_expr="udp")
            assert manager.interface == "lo"
            assert manager.filter_expr == "udp"
            print("✓ TCPDumpManager initialized")
    
    def test_tcpdump_status(self):
        """Test tcpdump status."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = TCPDumpManager(interface="lo", output_dir=tmpdir)
            status = manager.get_status()
            assert "running" in status
            assert "interface" in status
            print("✓ TCPDumpManager status check working")


class TestSessionTracker:
    """Test SessionTracker."""
    
    @pytest.mark.asyncio
    async def test_session_tracker_initialization(self):
        """Test session tracker initialization."""
        tracker = SessionTracker(timeout_seconds=3600)
        assert tracker.timeout_seconds == 3600
        print("✓ SessionTracker initialized")
    
    @pytest.mark.asyncio
    async def test_get_or_create_session(self):
        """Test session creation."""
        tracker = SessionTracker()
        session_id = await tracker.get_or_create_session(
            client_ip="192.168.4.10",
            user_agent="TestAgent"
        )
        assert session_id is not None
        print(f"✓ Session created: {session_id[:8]}...")
    
    @pytest.mark.asyncio
    async def test_session_reuse(self):
        """Test session reuse for same IP."""
        tracker = SessionTracker()
        session_id1 = await tracker.get_or_create_session(client_ip="192.168.4.10")
        session_id2 = await tracker.get_or_create_session(client_ip="192.168.4.10")
        assert session_id1 == session_id2
        print("✓ Session reused for same IP")


class TestPCAPExporter:
    """Test StreamingPCAPExporter."""
    
    def test_pcap_exporter_initialization(self):
        """Test PCAP exporter initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            exporter = StreamingPCAPExporter(output_dir=tmpdir, buffer_size_mb=10)
            assert exporter.buffer.max_size_mb() == 10.0
            assert exporter.backpressure is not None
            print("✓ StreamingPCAPExporter initialized")
    
    def test_backpressure_integration(self):
        """Test backpressure integration."""
        exporter = StreamingPCAPExporter(buffer_size_mb=1)
        # Fill buffer to trigger backpressure
        threshold_bytes = int(exporter.buffer.backpressure_threshold)
        exporter.buffer.push(b"x" * threshold_bytes)
        assert exporter.backpressure.should_pause()
        print("✓ Backpressure integration working")


class TestBackpressureHandling:
    """Test backpressure handling."""
    
    def test_ring_buffer_backpressure(self):
        """Test ring buffer backpressure threshold."""
        buffer = RingBuffer(max_size_mb=1)
        controller = BackpressureController(buffer)
        
        # Fill to threshold
        threshold_bytes = int(buffer.backpressure_threshold)
        buffer.push(b"x" * (threshold_bytes - 100))
        assert not controller.should_pause()
        
        # Exceed threshold
        buffer.push(b"x" * 200)
        assert controller.should_pause()
        print("✓ Backpressure threshold working")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("Phase 2b Traffic Capture Tests")
    print("="*60 + "\n")
    
    # Run tests
    pytest.main([__file__, "-v", "-s"])

