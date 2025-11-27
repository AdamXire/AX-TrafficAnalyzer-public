"""
@fileoverview Phase 1 Integration Tests
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Integration tests for Phase 1 components.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from community.core.orchestrator import StartupOrchestrator
from community.storage.disk_monitor import DiskSpaceManager


def test_orchestrator_component_registration():
    """Test component registration with orchestrator."""
    orchestrator = StartupOrchestrator()
    
    start_mock = Mock()
    stop_mock = Mock()
    
    orchestrator.register_component(
        name="test_component",
        start_func=start_mock,
        stop_func=stop_mock
    )
    
    assert len(orchestrator.components) == 1
    assert orchestrator.components[0].name == "test_component"


def test_orchestrator_startup_rollback():
    """Test orchestrator rollback on component failure."""
    orchestrator = StartupOrchestrator()
    
    # First component succeeds
    start1 = Mock()
    stop1 = Mock()
    orchestrator.register_component("component1", start1, stop1)
    
    # Second component fails
    start2 = Mock(side_effect=Exception("Test failure"))
    stop2 = Mock()
    orchestrator.register_component("component2", start2, stop2)
    
    # Start should fail and rollback
    with pytest.raises(Exception, match="Test failure"):
        orchestrator.start()
    
    # First component should be stopped during rollback
    stop1.assert_called_once()
    # Second component should not be stopped (never started)
    stop2.assert_not_called()
    
    # Started components list should be cleared
    assert len(orchestrator.started_components) == 0


def test_orchestrator_graceful_shutdown():
    """Test orchestrator graceful shutdown."""
    orchestrator = StartupOrchestrator()
    
    start_mock = Mock()
    stop_mock = Mock()
    
    orchestrator.register_component("test", start_mock, stop_mock)
    orchestrator.start()
    
    # Stop should call stop on all started components
    orchestrator.stop()
    stop_mock.assert_called_once()
    
    # Started components should be cleared
    assert len(orchestrator.started_components) == 0


def test_disk_monitor_initialization():
    """Test disk monitor initialization."""
    monitor = DiskSpaceManager(monitor_path="/tmp", check_interval=30)
    
    assert monitor.monitor_path == Path("/tmp")
    assert monitor.check_interval == 30
    assert monitor.monitoring == False
    assert len(monitor.cleanup_callbacks) == 0


def test_disk_monitor_check_disk_space():
    """Test disk space check."""
    monitor = DiskSpaceManager()
    
    # Should return status dict
    status = monitor.check_disk_space()
    
    assert "free_gb" in status
    assert "status" in status
    assert isinstance(status["free_gb"], float)
    assert status["free_gb"] >= 0


@patch('community.storage.disk_monitor.os.statvfs')
def test_disk_monitor_critical_threshold(mock_statvfs):
    """Test disk monitor fails fast on critical threshold."""
    # Mock very low disk space
    mock_stat = Mock()
    mock_stat.f_bavail = 100 * 1024  # ~100MB
    mock_stat.f_frsize = 4096
    mock_statvfs.return_value = mock_stat
    
    monitor = DiskSpaceManager()
    
    # Should raise ResourceError on critical threshold
    with pytest.raises(Exception):  # ResourceError
        monitor.check_disk_space()


def test_component_references():
    """Test ComponentReferences dataclass."""
    from community.api.health import ComponentReferences
    
    refs = ComponentReferences(
        hotspot=Mock(),
        iptables=Mock(),
        disk_monitor=Mock()
    )
    
    assert refs.hotspot is not None
    assert refs.iptables is not None
    assert refs.disk_monitor is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

