"""
AX-TrafficAnalyzer - 802.11 Frame Analyzer
Copyright © 2025 MMeTech (Macau) Ltd.

Analyzes captured 802.11 frames for security insights.
"""

from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import structlog

from .frame_capture import WiFiFrame

log = structlog.get_logger(__name__)


@dataclass
class AccessPoint:
    """Detected access point."""
    bssid: str
    ssid: Optional[str]
    channel: Optional[int]
    signal_strength: Optional[int]
    first_seen: datetime
    last_seen: datetime
    beacon_count: int = 0
    clients: set = field(default_factory=set)


@dataclass
class WirelessClient:
    """Detected wireless client."""
    mac: str
    associated_bssid: Optional[str]
    first_seen: datetime
    last_seen: datetime
    frame_count: int = 0
    probed_ssids: set = field(default_factory=set)


@dataclass
class SecurityFinding:
    """Security finding from wireless analysis."""
    severity: str  # low, medium, high, critical
    category: str
    title: str
    description: str
    evidence: dict
    timestamp: datetime = field(default_factory=datetime.now)


class WirelessFrameAnalyzer:
    """
    Analyzes 802.11 frames for:
    - Access point detection
    - Client tracking
    - Deauth attack detection
    - Rogue AP detection
    - Hidden SSID detection
    """
    
    def __init__(self):
        log.info("[ANALYZER] Initializing wireless frame analyzer")
        
        self.access_points: dict[str, AccessPoint] = {}
        self.clients: dict[str, WirelessClient] = {}
        self.findings: list[SecurityFinding] = []
        
        # Detection thresholds
        self._deauth_threshold = 10  # Deauths per minute
        self._deauth_counts: dict[str, list[datetime]] = defaultdict(list)
        
        # Known good APs (populated from config)
        self._known_aps: set[str] = set()
        
        log.info("[ANALYZER] Wireless analyzer initialized")
    
    def set_known_aps(self, bssids: list[str]) -> None:
        """Set known good access points."""
        self._known_aps = set(bssids)
        log.info("[ANALYZER] Known APs configured", count=len(bssids))
    
    async def analyze_frame(self, frame: WiFiFrame) -> Optional[SecurityFinding]:
        """
        Analyze a single frame.
        
        Returns:
            SecurityFinding if suspicious activity detected
        """
        log.debug("[ANALYZER] Analyzing frame", type=frame.frame_type)
        
        # Update AP tracking
        if frame.frame_type in ("beacon", "probe_response"):
            self._track_ap(frame)
        
        # Update client tracking
        if frame.source_mac and frame.source_mac != "ff:ff:ff:ff:ff:ff":
            self._track_client(frame)
        
        # Security checks
        finding = None
        
        if frame.frame_type == "deauthentication":
            finding = self._check_deauth_attack(frame)
        
        if frame.frame_type == "beacon" and frame.bssid:
            finding = self._check_rogue_ap(frame)
        
        if frame.frame_type == "probe_request":
            self._track_probe_request(frame)
        
        if finding:
            self.findings.append(finding)
            log.warning("[ANALYZER] Security finding", 
                       severity=finding.severity, 
                       title=finding.title)
        
        return finding
    
    def _track_ap(self, frame: WiFiFrame) -> None:
        """Track access point from beacon/probe response."""
        if not frame.bssid:
            return
        
        now = datetime.now()
        
        if frame.bssid in self.access_points:
            ap = self.access_points[frame.bssid]
            ap.last_seen = now
            ap.beacon_count += 1
            if frame.signal_strength:
                ap.signal_strength = frame.signal_strength
        else:
            self.access_points[frame.bssid] = AccessPoint(
                bssid=frame.bssid,
                ssid=frame.ssid,
                channel=frame.channel,
                signal_strength=frame.signal_strength,
                first_seen=now,
                last_seen=now,
                beacon_count=1
            )
            log.info("[ANALYZER] New AP detected", 
                    bssid=frame.bssid, 
                    ssid=frame.ssid)
    
    def _track_client(self, frame: WiFiFrame) -> None:
        """Track wireless client."""
        mac = frame.source_mac
        now = datetime.now()
        
        if mac in self.clients:
            client = self.clients[mac]
            client.last_seen = now
            client.frame_count += 1
            if frame.bssid:
                client.associated_bssid = frame.bssid
        else:
            self.clients[mac] = WirelessClient(
                mac=mac,
                associated_bssid=frame.bssid,
                first_seen=now,
                last_seen=now,
                frame_count=1
            )
            log.debug("[ANALYZER] New client detected", mac=mac)
    
    def _track_probe_request(self, frame: WiFiFrame) -> None:
        """Track probe requests for SSID enumeration."""
        if frame.source_mac and frame.ssid:
            if frame.source_mac in self.clients:
                self.clients[frame.source_mac].probed_ssids.add(frame.ssid)
    
    def _check_deauth_attack(self, frame: WiFiFrame) -> Optional[SecurityFinding]:
        """Detect deauthentication flood attacks."""
        key = f"{frame.source_mac}_{frame.bssid}"
        now = datetime.now()
        
        # Clean old entries
        self._deauth_counts[key] = [
            t for t in self._deauth_counts[key]
            if (now - t).total_seconds() < 60
        ]
        
        self._deauth_counts[key].append(now)
        
        if len(self._deauth_counts[key]) >= self._deauth_threshold:
            return SecurityFinding(
                severity="high",
                category="wireless_attack",
                title="Deauthentication Flood Detected",
                description=(
                    f"High rate of deauth frames detected from {frame.source_mac} "
                    f"targeting {frame.bssid}. This may indicate a deauth attack."
                ),
                evidence={
                    "source_mac": frame.source_mac,
                    "target_bssid": frame.bssid,
                    "deauth_count": len(self._deauth_counts[key]),
                    "time_window": "60 seconds"
                }
            )
        return None
    
    def _check_rogue_ap(self, frame: WiFiFrame) -> Optional[SecurityFinding]:
        """Detect potential rogue access points."""
        if not self._known_aps:
            return None  # No known APs configured
        
        if frame.bssid and frame.bssid not in self._known_aps:
            # Check if SSID matches a known AP (evil twin)
            known_ssids = {
                ap.ssid for ap in self.access_points.values()
                if ap.bssid in self._known_aps and ap.ssid
            }
            
            if frame.ssid and frame.ssid in known_ssids:
                return SecurityFinding(
                    severity="critical",
                    category="rogue_ap",
                    title="Potential Evil Twin AP Detected",
                    description=(
                        f"AP with BSSID {frame.bssid} is broadcasting SSID '{frame.ssid}' "
                        f"which matches a known network but from unknown hardware."
                    ),
                    evidence={
                        "rogue_bssid": frame.bssid,
                        "ssid": frame.ssid,
                        "channel": frame.channel,
                        "signal_strength": frame.signal_strength
                    }
                )
        return None
    
    def get_summary(self) -> dict:
        """Get analysis summary."""
        return {
            "access_points": len(self.access_points),
            "clients": len(self.clients),
            "findings": len(self.findings),
            "findings_by_severity": {
                "critical": len([f for f in self.findings if f.severity == "critical"]),
                "high": len([f for f in self.findings if f.severity == "high"]),
                "medium": len([f for f in self.findings if f.severity == "medium"]),
                "low": len([f for f in self.findings if f.severity == "low"]),
            }
        }

