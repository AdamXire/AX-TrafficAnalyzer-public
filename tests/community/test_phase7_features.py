"""
AX-TrafficAnalyzer - Phase 7 Feature Tests
Copyright © 2025 MMeTech (Macau) Ltd.

Tests for Desktop GUI, 802.11 Monitor, GPS, and Mobile App components.
"""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch, AsyncMock
from pathlib import Path


class TestAirmonManager:
    """Tests for AirmonManager (802.11 monitor mode)."""
    
    def test_airmon_import(self):
        """Test AirmonManager can be imported."""
        from src.community.capture.wireless.airmon import AirmonManager, AirmonManagerError
        assert AirmonManager is not None
        assert AirmonManagerError is not None
    
    @patch('shutil.which')
    def test_airmon_fail_fast_no_airmon(self, mock_which):
        """Test fail-fast when airmon-ng not found."""
        mock_which.return_value = None
        
        from src.community.capture.wireless.airmon import AirmonManager, AirmonManagerError
        
        with pytest.raises(AirmonManagerError) as exc_info:
            AirmonManager("wlan0")
        
        assert "airmon-ng not found" in str(exc_info.value)
        assert "apt install aircrack-ng" in str(exc_info.value)
    
    @patch('shutil.which')
    @patch('subprocess.run')
    def test_airmon_fail_fast_no_interface(self, mock_run, mock_which):
        """Test fail-fast when interface not found."""
        mock_which.return_value = "/usr/bin/airmon-ng"
        mock_run.return_value = MagicMock(returncode=1)
        
        from src.community.capture.wireless.airmon import AirmonManager, AirmonManagerError
        
        with pytest.raises(AirmonManagerError) as exc_info:
            AirmonManager("wlan99")
        
        assert "not found" in str(exc_info.value)


class TestWirelessFrameCapture:
    """Tests for WirelessFrameCapture."""
    
    def test_frame_capture_import(self):
        """Test frame capture can be imported."""
        from src.community.capture.wireless.frame_capture import WirelessFrameCapture, WiFiFrame
        assert WirelessFrameCapture is not None
        assert WiFiFrame is not None
    
    def test_wifi_frame_dataclass(self):
        """Test WiFiFrame dataclass."""
        from src.community.capture.wireless.frame_capture import WiFiFrame
        
        frame = WiFiFrame(
            id="test-123",
            timestamp=datetime.now(),
            frame_type="beacon",
            source_mac="aa:bb:cc:dd:ee:ff",
            dest_mac="ff:ff:ff:ff:ff:ff",
            bssid="aa:bb:cc:dd:ee:ff",
            ssid="TestNetwork",
            signal_strength=-50,
            channel=6,
            raw_data=b""
        )
        
        assert frame.frame_type == "beacon"
        assert frame.ssid == "TestNetwork"
        assert frame.channel == 6


class TestWirelessFrameAnalyzer:
    """Tests for WirelessFrameAnalyzer."""
    
    def test_analyzer_import(self):
        """Test analyzer can be imported."""
        from src.community.capture.wireless.frame_analyzer import (
            WirelessFrameAnalyzer,
            AccessPoint,
            WirelessClient,
            SecurityFinding
        )
        assert WirelessFrameAnalyzer is not None
    
    def test_analyzer_init(self):
        """Test analyzer initialization."""
        from src.community.capture.wireless.frame_analyzer import WirelessFrameAnalyzer
        
        analyzer = WirelessFrameAnalyzer()
        assert len(analyzer.access_points) == 0
        assert len(analyzer.clients) == 0
        assert len(analyzer.findings) == 0
    
    @pytest.mark.asyncio
    async def test_analyze_beacon_frame(self):
        """Test beacon frame analysis."""
        from src.community.capture.wireless.frame_analyzer import WirelessFrameAnalyzer
        from src.community.capture.wireless.frame_capture import WiFiFrame
        
        analyzer = WirelessFrameAnalyzer()
        
        frame = WiFiFrame(
            id="test-1",
            timestamp=datetime.now(),
            frame_type="beacon",
            source_mac="aa:bb:cc:dd:ee:ff",
            dest_mac="ff:ff:ff:ff:ff:ff",
            bssid="aa:bb:cc:dd:ee:ff",
            ssid="TestAP",
            signal_strength=-60,
            channel=11,
            raw_data=b""
        )
        
        await analyzer.analyze_frame(frame)
        
        assert "aa:bb:cc:dd:ee:ff" in analyzer.access_points
        ap = analyzer.access_points["aa:bb:cc:dd:ee:ff"]
        assert ap.ssid == "TestAP"
        assert ap.channel == 11
    
    def test_get_summary(self):
        """Test summary generation."""
        from src.community.capture.wireless.frame_analyzer import WirelessFrameAnalyzer
        
        analyzer = WirelessFrameAnalyzer()
        summary = analyzer.get_summary()
        
        assert "access_points" in summary
        assert "clients" in summary
        assert "findings" in summary
        assert "findings_by_severity" in summary


class TestGPSTracker:
    """Tests for GPSTracker."""
    
    def test_gps_types_import(self):
        """Test GPS types can be imported."""
        from src.community.gps.types import Location
        assert Location is not None
    
    def test_location_dataclass(self):
        """Test Location dataclass."""
        from src.community.gps.types import Location
        
        loc = Location(
            latitude=22.1987,
            longitude=113.5439,
            altitude=50.0,
            speed=0.0,
            accuracy=5.0
        )
        
        assert loc.latitude == 22.1987
        assert loc.longitude == 113.5439
        assert "22.1987" in str(loc)
    
    def test_location_to_dict(self):
        """Test Location.to_dict()."""
        from src.community.gps.types import Location
        
        loc = Location(latitude=22.0, longitude=113.0)
        data = loc.to_dict()
        
        assert data["latitude"] == 22.0
        assert data["longitude"] == 113.0
        assert "timestamp" in data
    
    @patch('shutil.which')
    def test_gps_tracker_fail_fast_no_gpsd(self, mock_which):
        """Test fail-fast when gpsd not found."""
        mock_which.return_value = None
        
        from src.community.gps.tracker import GPSTracker, GPSTrackerError
        
        with pytest.raises(GPSTrackerError) as exc_info:
            GPSTracker()
        
        assert "gpsd not found" in str(exc_info.value)
        assert "apt install gpsd" in str(exc_info.value)


class TestWiFiFrameDB:
    """Tests for WiFiFrameDB model."""
    
    def test_model_import(self):
        """Test WiFiFrameDB can be imported."""
        from src.community.storage.models import WiFiFrameDB
        assert WiFiFrameDB is not None
    
    def test_model_tablename(self):
        """Test table name."""
        from src.community.storage.models import WiFiFrameDB
        assert WiFiFrameDB.__tablename__ == "wifi_frames"
    
    def test_model_columns(self):
        """Test model has required columns."""
        from src.community.storage.models import WiFiFrameDB
        
        columns = [c.name for c in WiFiFrameDB.__table__.columns]
        
        assert "id" in columns
        assert "session_id" in columns
        assert "timestamp" in columns
        assert "frame_type" in columns
        assert "source_mac" in columns
        assert "dest_mac" in columns
        assert "bssid" in columns
        assert "ssid" in columns
        assert "signal_strength" in columns
        assert "channel" in columns
        assert "raw_data" in columns


class TestPhase7Migrations:
    """Tests for Phase 7 database migrations."""
    
    def test_wifi_frames_migration_exists(self):
        """Test wifi_frames migration file exists."""
        migration_path = Path("alembic/versions/b8c9d0e1f234_add_wifi_frames_table.py")
        assert migration_path.exists()
    
    def test_gps_columns_migration_exists(self):
        """Test GPS columns migration file exists."""
        migration_path = Path("alembic/versions/c9d0e1f23456_add_gps_columns.py")
        assert migration_path.exists()


class TestDesktopApp:
    """Tests for Desktop Electron app files."""
    
    def test_package_json_exists(self):
        """Test desktop package.json exists."""
        package_path = Path("desktop/package.json")
        assert package_path.exists()
    
    def test_main_ts_exists(self):
        """Test main.ts exists."""
        main_path = Path("desktop/electron/main.ts")
        assert main_path.exists()
    
    def test_preload_ts_exists(self):
        """Test preload.ts exists."""
        preload_path = Path("desktop/electron/preload.ts")
        assert preload_path.exists()
    
    def test_bundle_script_exists(self):
        """Test bundle-backend.py exists."""
        script_path = Path("desktop/scripts/bundle-backend.py")
        assert script_path.exists()


class TestMobileApp:
    """Tests for Mobile React Native app files."""
    
    def test_package_json_exists(self):
        """Test mobile package.json exists."""
        package_path = Path("mobile/package.json")
        assert package_path.exists()
    
    def test_app_json_exists(self):
        """Test app.json exists."""
        app_path = Path("mobile/app.json")
        assert app_path.exists()
    
    def test_app_tsx_exists(self):
        """Test App.tsx exists."""
        app_path = Path("mobile/App.tsx")
        assert app_path.exists()
    
    def test_api_client_exists(self):
        """Test API client exists."""
        client_path = Path("mobile/src/api/client.ts")
        assert client_path.exists()

