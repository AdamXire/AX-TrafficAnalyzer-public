"""
@fileoverview Streaming PCAP Exporter - Fast PCAP writing with backpressure
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Streaming PCAP export using python-libpcap with backpressure integration.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import subprocess
from pathlib import Path
from typing import Optional
from ...core.errors import NetworkError
from ...core.logging import get_logger
from ...core.memory import RingBuffer, BackpressureController, CircuitBreaker

log = get_logger(__name__)


class StreamingPCAPExporter:
    """
    Streaming PCAP exporter with backpressure control.
    
    Uses python-libpcap for fast writing (10x faster than scapy).
    """
    
    def __init__(self, output_dir: str = "./captures/pcap", buffer_size_mb: int = 10):
        """
        Initialize PCAP exporter.
        
        Args:
            output_dir: Directory for PCAP output files
            buffer_size_mb: Ring buffer size in MB (default: 10MB)
        """
        self.output_dir = Path(output_dir)
        self.buffer = RingBuffer(max_size_mb=buffer_size_mb)
        self.backpressure = BackpressureController(self.buffer)
        self.circuit_breaker = CircuitBreaker(failure_threshold=3)
        self.writer = None
        log.debug("pcap_exporter_initialized", output_dir=str(output_dir), buffer_size_mb=buffer_size_mb)
    
    def _ensure_output_dir(self) -> None:
        """Ensure output directory exists."""
        if not self.output_dir.exists():
            self.output_dir.mkdir(parents=True, mode=0o700)
            log.debug("pcap_output_directory_created", path=str(self.output_dir))
    
    def start(self, filename: str) -> None:
        """
        Start PCAP export to file.
        
        Args:
            filename: Output filename (e.g., "capture_20250101.pcap")
            
        Raises:
            NetworkError: If python-libpcap unavailable or file creation fails
        """
        self._ensure_output_dir()
        output_file = self.output_dir / filename
        
        try:
            # Import python-libpcap (fail-fast if missing)
            try:
                import libpcap
            except ImportError:
                raise NetworkError(
                    "python-libpcap not installed. Install with: pip install python-libpcap>=1.0.0,<2.0.0",
                    None
                )
            
            # Create PCAP writer
            self.writer = libpcap.Writer(open(output_file, 'wb'))
            log.info("pcap_export_started", output_file=str(output_file))
        except Exception as e:
            self.circuit_breaker.record_failure()
            raise NetworkError(
                f"Failed to start PCAP export: {e}",
                None
            )
    
    def export_packet(self, packet_data: bytes) -> bool:
        """
        Export packet data to PCAP.
        
        Args:
            packet_data: Raw packet bytes
            
        Returns:
            True if exported successfully, False if backpressure active
        """
        if self.circuit_breaker.should_open():
            log.warning("circuit_breaker_open_pcap_export_paused")
            return False
        
        if self.backpressure.should_pause():
            log.warning("backpressure_active_packet_dropped")
            return False
        
        if self.writer is None:
            log.error("pcap_writer_not_initialized")
            return False
        
        try:
            # Add to ring buffer first
            if not self.buffer.push(packet_data):
                log.warning("ring_buffer_full_packet_dropped")
                return False
            
            # Write from buffer to file
            packet = self.buffer.pop()
            if packet:
                self.writer.write_packet(packet)
                self.circuit_breaker.record_success()
                log.debug("packet_exported", size=len(packet))
                return True
        except Exception as e:
            self.circuit_breaker.record_failure()
            log.error("packet_export_failed", error=str(e))
            return False
    
    def stop(self, pcap_monitor=None) -> None:
        """
        Stop PCAP export and flush buffer.
        
        Args:
            pcap_monitor: Optional PCAPFileMonitor to trigger DNS processing
        """
        if self.writer:
            try:
                # Get current output file path before closing
                current_file = None
                if hasattr(self.writer, 'file') and hasattr(self.writer.file, 'name'):
                    current_file = Path(self.writer.file.name)
                elif hasattr(self.writer, 'filename'):
                    current_file = Path(self.writer.filename)
                
                # Flush remaining buffer
                while not self.buffer.is_empty():
                    packet = self.buffer.pop()
                    if packet:
                        self.writer.write_packet(packet)
                
                self.writer.close()
                
                # Trigger DNS processing if monitor is available
                if pcap_monitor and current_file and current_file.exists():
                    import asyncio
                    import threading
                    
                    def trigger_dns_processing():
                        """Trigger DNS processing in background thread."""
                        try:
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                            try:
                                loop.run_until_complete(
                                    pcap_monitor.process_file_immediately(current_file)
                                )
                            finally:
                                loop.close()
                        except Exception as e:
                            log.warning("pcap_dns_processing_trigger_failed", 
                                       file=str(current_file),
                                       error=str(e))
                    
                    # Run in background thread (non-blocking)
                    thread = threading.Thread(target=trigger_dns_processing, daemon=True)
                    thread.start()
                    log.debug("dns_processing_triggered", file=str(current_file))
                
                log.info("pcap_export_stopped", flushed_packets=self.buffer.size_mb())
            except Exception as e:
                log.error("pcap_export_stop_failed", error=str(e))
            finally:
                self.writer = None
    
    def validate_pcap(self, file_path: Path) -> bool:
        """
        Validate PCAP file using tshark.
        
        Args:
            file_path: Path to PCAP file
            
        Returns:
            True if valid, False otherwise
        """
        try:
            result = subprocess.run(
                ["tshark", "-r", str(file_path), "-c", "1"],
                capture_output=True,
                timeout=10
            )
            is_valid = result.returncode == 0
            log.debug("pcap_validation", file=str(file_path), valid=is_valid)
            return is_valid
        except Exception as e:
            log.error("pcap_validation_failed", file=str(file_path), error=str(e))
            return False

