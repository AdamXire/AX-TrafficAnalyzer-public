"""
AX-TrafficAnalyzer - GPS Tracker
Copyright © 2025 MMeTech (Macau) Ltd.

GPS location tracking using gpsd daemon.
FAIL-FAST: Raises error if gpsd not available when enabled.
"""

import shutil
import threading
import time
from typing import Optional, Callable
from datetime import datetime
import structlog

from .types import Location

log = structlog.get_logger(__name__)


class GPSTrackerError(Exception):
    """GPS tracker error with actionable message."""
    pass


class GPSTracker:
    """
    GPS location tracker using gpsd.
    
    FAIL-FAST: Constructor raises if gpsd not available.
    """
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 2947,
        poll_interval: float = 1.0,
        timeout: float = 5.0,
        on_location: Optional[Callable[[Location], None]] = None
    ):
        """
        Initialize GPS tracker.
        
        Args:
            host: gpsd host
            port: gpsd port
            poll_interval: Seconds between location polls
            timeout: Connection timeout
            on_location: Callback for new locations
            
        Raises:
            GPSTrackerError: If gpsd not found
        """
        log.info("[GPS] Initializing GPS tracker", host=host, port=port)
        
        # FAIL-FAST: Check gpsd exists
        if not shutil.which("gpsd"):
            raise GPSTrackerError(
                "gpsd not found in PATH.\n"
                "Install with: sudo apt install gpsd gpsd-clients\n"
                "Or disable GPS tracking in config.json"
            )
        
        # Try to import gpsd library
        try:
            import gpsd as gpsd_lib
            self._gpsd = gpsd_lib
        except ImportError:
            raise GPSTrackerError(
                "gpsd-py3 library not installed.\n"
                "Install with: pip install gpsd-py3\n"
                "Or disable GPS tracking in config.json"
            )
        
        self.host = host
        self.port = port
        self.poll_interval = poll_interval
        self.timeout = timeout
        self.on_location = on_location
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._current_location: Optional[Location] = None
        self._lock = threading.Lock()
        self._connected = False
        
        log.info("[GPS] GPS tracker initialized")
    
    def start(self) -> None:
        """Start GPS tracking thread."""
        if self._running:
            log.warning("[GPS] Already running")
            return
        
        log.info("[GPS] Starting GPS tracker")
        self._running = True
        self._thread = threading.Thread(target=self._tracking_loop, daemon=True)
        self._thread.start()
    
    def stop(self) -> None:
        """Stop GPS tracking."""
        if not self._running:
            return
        
        log.info("[GPS] Stopping GPS tracker")
        self._running = False
        
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        
        log.info("[GPS] GPS tracker stopped")
    
    def _tracking_loop(self) -> None:
        """Main tracking loop - runs in background thread."""
        log.debug("[GPS] Tracking loop started")
        
        # Connect to gpsd
        try:
            self._gpsd.connect(host=self.host, port=self.port)
            self._connected = True
            log.info("[GPS] Connected to gpsd", host=self.host, port=self.port)
        except Exception as e:
            log.error("[GPS] Failed to connect to gpsd", error=str(e))
            self._running = False
            return
        
        while self._running:
            try:
                packet = self._gpsd.get_current()
                
                if packet.mode >= 2:  # 2D or 3D fix
                    location = Location(
                        latitude=packet.lat,
                        longitude=packet.lon,
                        altitude=packet.alt if packet.mode >= 3 else None,
                        speed=packet.speed() if hasattr(packet, 'speed') else None,
                        heading=packet.track if hasattr(packet, 'track') else None,
                        accuracy=packet.error.get('x', None) if hasattr(packet, 'error') else None,
                        timestamp=datetime.now()
                    )
                    
                    with self._lock:
                        self._current_location = location
                    
                    log.debug("[GPS] Location updated", location=str(location))
                    
                    if self.on_location:
                        try:
                            self.on_location(location)
                        except Exception as e:
                            log.warning("[GPS] Callback error", error=str(e))
                else:
                    log.debug("[GPS] No GPS fix", mode=packet.mode)
                
            except Exception as e:
                log.warning("[GPS] Poll error", error=str(e))
            
            time.sleep(self.poll_interval)
        
        log.debug("[GPS] Tracking loop ended")
    
    @property
    def current_location(self) -> Optional[Location]:
        """Get current location (thread-safe)."""
        with self._lock:
            return self._current_location
    
    @property
    def is_connected(self) -> bool:
        """Check if connected to gpsd."""
        return self._connected and self._running
    
    def get_location_tuple(self) -> Optional[tuple[float, float]]:
        """Get current location as (lat, lon) tuple."""
        loc = self.current_location
        if loc:
            return (loc.latitude, loc.longitude)
        return None
    
    async def async_start(self) -> None:
        """Async start for orchestrator compatibility."""
        self.start()
    
    async def async_stop(self) -> None:
        """Async stop for orchestrator compatibility."""
        self.stop()

