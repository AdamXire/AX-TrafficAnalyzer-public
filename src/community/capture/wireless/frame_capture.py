"""
AX-TrafficAnalyzer - 802.11 Frame Capture
Copyright © 2025 MMeTech (Macau) Ltd.

Captures 802.11 frames using tcpdump on monitor interface.
"""

import subprocess
import asyncio
import shutil
from pathlib import Path
from typing import Optional, Callable, Awaitable
from dataclasses import dataclass
from datetime import datetime
import structlog

log = structlog.get_logger(__name__)


@dataclass
class WiFiFrame:
    """Captured 802.11 frame."""
    id: str
    timestamp: datetime
    frame_type: str  # beacon, probe_request, probe_response, data, etc.
    source_mac: str
    dest_mac: str
    bssid: Optional[str]
    ssid: Optional[str]
    signal_strength: Optional[int]  # dBm
    channel: Optional[int]
    raw_data: bytes


class WirelessFrameCapture:
    """
    Captures 802.11 frames from monitor mode interface.
    
    Uses tcpdump for raw capture, tshark for parsing.
    """
    
    def __init__(
        self,
        interface: str,
        output_dir: Path,
        on_frame: Optional[Callable[[WiFiFrame], Awaitable[None]]] = None
    ):
        """
        Initialize frame capture.
        
        Args:
            interface: Monitor mode interface (e.g., wlan0mon)
            output_dir: Directory to save PCAP files
            on_frame: Async callback for each captured frame
        """
        log.info("[WIRELESS] Initializing frame capture", interface=interface)
        
        # FAIL-FAST: Check tcpdump
        if not shutil.which("tcpdump"):
            raise RuntimeError(
                "tcpdump not found. Install with: sudo apt install tcpdump"
            )
        
        # FAIL-FAST: Check tshark for parsing
        if not shutil.which("tshark"):
            raise RuntimeError(
                "tshark not found. Install with: sudo apt install tshark"
            )
        
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.on_frame = on_frame
        
        self._process: Optional[subprocess.Popen] = None
        self._running = False
        self._current_pcap: Optional[Path] = None
        
        log.info("[WIRELESS] Frame capture initialized")
    
    async def start(self) -> None:
        """Start capturing frames."""
        if self._running:
            log.warning("[WIRELESS] Already capturing")
            return
        
        log.info("[WIRELESS] Starting frame capture", interface=self.interface)
        
        # Generate PCAP filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._current_pcap = self.output_dir / f"wireless_{timestamp}.pcap"
        
        # Start tcpdump with 802.11 frame capture
        cmd = [
            "sudo", "tcpdump",
            "-i", self.interface,
            "-w", str(self._current_pcap),
            "-U",  # Unbuffered output
            "-s", "0",  # Full packet capture
            "-e",  # Print link-level header
        ]
        
        log.debug("[WIRELESS] Running command", cmd=cmd)
        
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self._running = True
            log.info("[WIRELESS] Capture started", pcap=str(self._current_pcap))
            
            # Start async frame processing
            asyncio.create_task(self._process_frames())
            
        except Exception as e:
            log.error("[WIRELESS] Failed to start capture", error=str(e))
            raise
    
    async def stop(self) -> Optional[Path]:
        """
        Stop capturing frames.
        
        Returns:
            Path to captured PCAP file
        """
        if not self._running:
            return None
        
        log.info("[WIRELESS] Stopping frame capture")
        self._running = False
        
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
        
        pcap_path = self._current_pcap
        self._current_pcap = None
        
        log.info("[WIRELESS] Capture stopped", pcap=str(pcap_path))
        return pcap_path
    
    async def _process_frames(self) -> None:
        """Process captured frames in real-time using tshark."""
        if not self._current_pcap:
            return
        
        # Wait for PCAP file to be created
        await asyncio.sleep(1)
        
        log.debug("[WIRELESS] Starting frame processing")
        
        # Use tshark to parse frames in real-time
        cmd = [
            "tshark",
            "-i", self.interface,
            "-T", "fields",
            "-e", "frame.time",
            "-e", "wlan.fc.type_subtype",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "wlan.bssid",
            "-e", "wlan.ssid",
            "-e", "radiotap.dbm_antsignal",
            "-e", "radiotap.channel.freq",
            "-E", "separator=|",
        ]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            frame_count = 0
            while self._running and process.stdout:
                line = await process.stdout.readline()
                if not line:
                    break
                
                try:
                    frame = self._parse_frame_line(line.decode().strip())
                    if frame and self.on_frame:
                        await self.on_frame(frame)
                    frame_count += 1
                    
                    if frame_count % 100 == 0:
                        log.debug("[WIRELESS] Frames processed", count=frame_count)
                        
                except Exception as e:
                    log.warning("[WIRELESS] Frame parse error", error=str(e))
            
            process.terminate()
            log.info("[WIRELESS] Frame processing stopped", total_frames=frame_count)
            
        except Exception as e:
            log.error("[WIRELESS] Frame processing failed", error=str(e))
    
    def _parse_frame_line(self, line: str) -> Optional[WiFiFrame]:
        """Parse tshark output line into WiFiFrame."""
        if not line:
            return None
        
        parts = line.split("|")
        if len(parts) < 4:
            return None
        
        import uuid
        
        # Parse frame type
        frame_type_code = parts[1] if len(parts) > 1 else ""
        frame_type = self._decode_frame_type(frame_type_code)
        
        # Parse signal strength
        signal = None
        if len(parts) > 6 and parts[6]:
            try:
                signal = int(parts[6])
            except ValueError:
                pass
        
        # Parse channel from frequency
        channel = None
        if len(parts) > 7 and parts[7]:
            try:
                freq = int(parts[7])
                channel = self._freq_to_channel(freq)
            except ValueError:
                pass
        
        return WiFiFrame(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),  # Simplified, should parse from parts[0]
            frame_type=frame_type,
            source_mac=parts[2] if len(parts) > 2 else "",
            dest_mac=parts[3] if len(parts) > 3 else "",
            bssid=parts[4] if len(parts) > 4 and parts[4] else None,
            ssid=parts[5] if len(parts) > 5 and parts[5] else None,
            signal_strength=signal,
            channel=channel,
            raw_data=b""  # Raw data from PCAP
        )
    
    def _decode_frame_type(self, code: str) -> str:
        """Decode 802.11 frame type/subtype code."""
        frame_types = {
            "0x00": "association_request",
            "0x01": "association_response",
            "0x04": "probe_request",
            "0x05": "probe_response",
            "0x08": "beacon",
            "0x0b": "authentication",
            "0x0c": "deauthentication",
            "0x20": "data",
            "0x28": "qos_data",
        }
        return frame_types.get(code, f"unknown_{code}")
    
    def _freq_to_channel(self, freq: int) -> int:
        """Convert frequency (MHz) to channel number."""
        if 2412 <= freq <= 2484:
            if freq == 2484:
                return 14
            return (freq - 2412) // 5 + 1
        elif 5180 <= freq <= 5825:
            return (freq - 5180) // 5 + 36
        return 0

