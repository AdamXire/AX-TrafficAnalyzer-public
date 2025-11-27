"""
@fileoverview DNS Handler - Integrate DNS processing with capture pipeline
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Handles DNS query processing integration with the capture pipeline.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from pathlib import Path
from typing import Optional
from .processor import DNSQueryProcessor
from ...core.logging import get_logger

log = get_logger(__name__)


class DNSHandler:
    """
    Handles DNS query processing for captured PCAP files.
    
    Integrates with tcpdump PCAP file rotation and processes DNS queries.
    """
    
    def __init__(
        self,
        analysis_orchestrator=None,
        db_manager=None,
        enabled: bool = True
    ):
        """
        Initialize DNS handler.
        
        Args:
            analysis_orchestrator: AnalysisOrchestrator instance
            db_manager: Database manager instance
            enabled: Whether DNS processing is enabled
        """
        self.enabled = enabled
        self.processor = DNSQueryProcessor(
            analysis_orchestrator=analysis_orchestrator,
            db_manager=db_manager
        ) if enabled else None
        log.info("dns_handler_initialized", enabled=enabled)
    
    async def process_pcap_file(self, pcap_path: Path, session_id: str) -> int:
        """
        Process PCAP file for DNS queries.
        
        Args:
            pcap_path: Path to PCAP file
            session_id: Session ID for DNS queries
            
        Returns:
            Number of DNS queries processed
        """
        if not self.enabled or not self.processor:
            log.debug("dns_processing_disabled")
            return 0
        
        if not pcap_path.exists():
            log.warning("pcap_file_not_found", path=str(pcap_path))
            return 0
        
        try:
            queries = await self.processor.process_pcap_file(pcap_path, session_id)
            count = len(queries)
            log.info("dns_queries_processed", 
                    pcap_path=str(pcap_path),
                    session_id=session_id,
                    count=count)
            return count
        except Exception as e:
            log.error("dns_pcap_processing_failed",
                     pcap_path=str(pcap_path),
                     error=str(e),
                     error_type=type(e).__name__)
            return 0
    
    async def process_pcap_directory(
        self,
        pcap_dir: Path,
        session_id: Optional[str] = None
    ) -> int:
        """
        Process all PCAP files in a directory.
        
        Args:
            pcap_dir: Directory containing PCAP files
            session_id: Optional session ID (if None, extracts from filename)
            
        Returns:
            Total number of DNS queries processed
        """
        if not self.enabled or not self.processor:
            return 0
        
        if not pcap_dir.exists():
            log.warning("pcap_directory_not_found", path=str(pcap_dir))
            return 0
        
        total_queries = 0
        pcap_files = list(pcap_dir.glob("*.pcap"))
        
        log.info("processing_pcap_directory", 
                directory=str(pcap_dir),
                file_count=len(pcap_files))
        
        for pcap_file in pcap_files:
            # Extract session_id from filename if not provided
            file_session_id = session_id
            if not file_session_id:
                # Try to extract from filename pattern: session_<id>.pcap
                if "_" in pcap_file.stem:
                    parts = pcap_file.stem.split("_")
                    if len(parts) > 1:
                        file_session_id = parts[-1]  # Last part as session ID
                else:
                    file_session_id = pcap_file.stem  # Use filename as session ID
            
            count = await self.process_pcap_file(pcap_file, file_session_id or "unknown")
            total_queries += count
        
        log.info("pcap_directory_processing_complete",
                directory=str(pcap_dir),
                total_queries=total_queries)
        
        return total_queries

