"""
AX-TrafficAnalyzer - GPS Types
Copyright © 2025 MMeTech (Macau) Ltd.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Location:
    """GPS location data."""
    latitude: float
    longitude: float
    altitude: Optional[float] = None  # meters
    speed: Optional[float] = None  # m/s
    heading: Optional[float] = None  # degrees
    accuracy: Optional[float] = None  # meters
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> dict:
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "altitude": self.altitude,
            "speed": self.speed,
            "heading": self.heading,
            "accuracy": self.accuracy,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }
    
    def __str__(self) -> str:
        return f"({self.latitude:.6f}, {self.longitude:.6f})"

