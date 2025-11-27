"""
AX-TrafficAnalyzer - GPS Tracking Module
Copyright © 2025 MMeTech (Macau) Ltd.

GPS location tracking using gpsd.
"""

from .tracker import GPSTracker
from .types import Location

__all__ = ["GPSTracker", "Location"]

