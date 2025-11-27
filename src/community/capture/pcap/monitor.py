"""
@fileoverview PCAP File Monitor - Monitor PCAP directories and trigger DNS processing
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Monitors PCAP directories for new files and triggers DNS query processing.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import asyncio
from pathlib import Path
from typing import List, Set, Optional
from datetime import datetime
from ...core.logging import get_logger

log = get_logger(__name__)


class PCAPFileMonitor:
    """
    Monitors PCAP directories for new files and triggers DNS processing.
    
    Watches for new PCAP files and automatically processes them for DNS queries.
    """
    
    def __init__(
        self,
        pcap_directories: List[str],
        dns_handler,
        poll_interval_seconds: int = 30
    ):
        """
        Initialize PCAP file monitor.
        
        Args:
            pcap_directories: List of directories to monitor
            dns_handler: DNSHandler instance for processing
            poll_interval_seconds: How often to check for new files (default: 30s)
        """
        self.pcap_directories = [Path(d) for d in pcap_directories]
        self.dns_handler = dns_handler
        self.poll_interval = poll_interval_seconds
        self.processed_files: Set[Path] = set()
        self.running = False
        self.monitor_task: Optional[asyncio.Task] = None
        log.info("pcap_monitor_initialized", 
                directories=[str(d) for d in self.pcap_directories],
                poll_interval=poll_interval_seconds)
    
    async def start(self) -> None:
        """Start monitoring PCAP directories."""
        if self.running:
            log.warning("pcap_monitor_already_running")
            return
        
        self.running = True
        
        # Process existing files on startup
        await self._process_existing_files()
        
        # Start monitoring task
        self.monitor_task = asyncio.create_task(self._monitor_loop())
        log.info("pcap_monitor_started")
    
    async def stop(self) -> None:
        """Stop monitoring."""
        if not self.running:
            return
        
        self.running = False
        
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
        
        log.info("pcap_monitor_stopped")
    
    async def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self.running:
            try:
                await self._check_for_new_files()
                await asyncio.sleep(self.poll_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("pcap_monitor_loop_error", 
                         error=str(e),
                         error_type=type(e).__name__)
                await asyncio.sleep(self.poll_interval)
    
    async def _process_existing_files(self) -> None:
        """Process existing PCAP files in monitored directories."""
        log.info("processing_existing_pcap_files")
        
        for pcap_dir in self.pcap_directories:
            if not pcap_dir.exists():
                log.debug("pcap_directory_not_found", path=str(pcap_dir))
                continue
            
            pcap_files = list(pcap_dir.glob("*.pcap"))
            log.debug("found_existing_pcap_files", 
                     directory=str(pcap_dir),
                     count=len(pcap_files))
            
            for pcap_file in pcap_files:
                if pcap_file not in self.processed_files:
                    await self.process_file(pcap_file)
    
    async def _check_for_new_files(self) -> None:
        """Check for new PCAP files in monitored directories."""
        for pcap_dir in self.pcap_directories:
            if not pcap_dir.exists():
                continue
            
            pcap_files = list(pcap_dir.glob("*.pcap"))
            
            for pcap_file in pcap_files:
                if pcap_file not in self.processed_files:
                    # New file detected
                    log.info("new_pcap_file_detected", file=str(pcap_file))
                    await self.process_file(pcap_file)
    
    async def process_file(self, pcap_file: Path, session_id: Optional[str] = None) -> int:
        """
        Process a PCAP file for DNS queries.
        
        Args:
            pcap_file: Path to PCAP file
            session_id: Optional session ID (extracted from filename if not provided)
            
        Returns:
            Number of DNS queries processed
        """
        if pcap_file in self.processed_files:
            log.debug("pcap_file_already_processed", file=str(pcap_file))
            return 0
        
        if not pcap_file.exists():
            log.warning("pcap_file_not_found", file=str(pcap_file))
            return 0
        
        # Extract session_id from filename if not provided
        if not session_id:
            # Try patterns: session_<id>.pcap, capture_<timestamp>.pcap
            stem = pcap_file.stem
            if stem.startswith("session_"):
                session_id = stem.replace("session_", "")
            elif stem.startswith("capture_"):
                # Use timestamp as session ID
                session_id = stem.replace("capture_", "")
            else:
                # Use filename as session ID
                session_id = stem
        
        try:
            log.info("processing_pcap_file_for_dns", 
                    file=str(pcap_file),
                    session_id=session_id)
            
            # Process file via DNS handler
            count = await self.dns_handler.process_pcap_file(pcap_file, session_id)
            
            # Mark as processed
            self.processed_files.add(pcap_file)
            
            log.info("pcap_file_processed", 
                    file=str(pcap_file),
                    session_id=session_id,
                    dns_queries=count)
            
            return count
        
        except Exception as e:
            log.error("pcap_file_processing_failed",
                     file=str(pcap_file),
                     error=str(e),
                     error_type=type(e).__name__)
            return 0
    
    async def process_file_immediately(self, pcap_file: Path) -> int:
        """
        Process a PCAP file immediately (called from PCAP exporter on stop).
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Number of DNS queries processed
        """
        return await self.process_file(pcap_file)
    
    async def process_directory(self, pcap_dir: Path, session_id: Optional[str] = None) -> int:
        """
        Process all PCAP files in a directory.
        
        Args:
            pcap_dir: Directory containing PCAP files
            session_id: Optional session ID for all files
            
        Returns:
            Total number of DNS queries processed
        """
        if not pcap_dir.exists():
            log.warning("pcap_directory_not_found", path=str(pcap_dir))
            return 0
        
        total_queries = 0
        pcap_files = list(pcap_dir.glob("*.pcap"))
        
        log.info("processing_pcap_directory", 
                directory=str(pcap_dir),
                file_count=len(pcap_files))
        
        for pcap_file in pcap_files:
            count = await self.process_file(pcap_file, session_id)
            total_queries += count
        
        log.info("pcap_directory_processed",
                directory=str(pcap_dir),
                total_queries=total_queries)
        
        return total_queries
    
    def get_status(self) -> dict:
        """
        Get monitor status.
        
        Returns:
            Dictionary with status information
        """
        return {
            "running": self.running,
            "monitored_directories": [str(d) for d in self.pcap_directories],
            "processed_files_count": len(self.processed_files),
            "poll_interval_seconds": self.poll_interval
        }
