"""
@fileoverview DNS Query Processor - Parse DNS queries from PCAP and trigger analysis
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Processes DNS queries from tcpdump/tshark PCAP files and triggers DNS analysis.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import subprocess
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from uuid import uuid4
from ...core.logging import get_logger
from ...storage.models import DNSQueryDB
from sqlalchemy.ext.asyncio import AsyncSession

log = get_logger(__name__)


class DNSQueryProcessor:
    """
    Processes DNS queries from PCAP files using tshark.
    
    Extracts DNS queries and triggers DNS analyzer.
    """
    
    def __init__(self, analysis_orchestrator=None, db_manager=None):
        """
        Initialize DNS query processor.
        
        Args:
            analysis_orchestrator: AnalysisOrchestrator instance
            db_manager: Database manager instance
        """
        self.analysis_orchestrator = analysis_orchestrator
        self.db_manager = db_manager
        log.info("dns_processor_initialized", has_orchestrator=analysis_orchestrator is not None)
    
    async def process_pcap_file(self, pcap_path: Path, session_id: str) -> List[Dict[str, Any]]:
        """
        Process PCAP file and extract DNS queries.
        
        Args:
            pcap_path: Path to PCAP file
            session_id: Session ID for DNS queries
            
        Returns:
            List of DNS query dictionaries
        """
        if not pcap_path.exists():
            log.warning("pcap_file_not_found", path=str(pcap_path))
            return []
        
        log.debug("processing_pcap_for_dns", path=str(pcap_path), session_id=session_id)
        
        try:
            # Use tshark to extract DNS queries
            # tshark -r file.pcap -T json -e dns.qry.name -e dns.qry.type -e dns.resp.name -e ip.src -e ip.dst
            cmd = [
                "tshark",
                "-r", str(pcap_path),
                "-T", "json",
                "-Y", "dns",  # Filter for DNS packets only
                "-e", "dns.qry.name",
                "-e", "dns.qry.type",
                "-e", "dns.resp.name",
                "-e", "dns.a",
                "-e", "dns.aaaa",
                "-e", "frame.time",
                "-e", "ip.src",
                "-e", "ip.dst"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                log.warning("tshark_extraction_failed", 
                           returncode=result.returncode,
                           stderr=result.stderr[:200])
                return []
            
            # Parse JSON output
            try:
                tshark_data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                log.warning("tshark_json_parse_failed", error=str(e))
                return []
            
            # Extract DNS queries
            dns_queries = []
            for packet in tshark_data:
                layers = packet.get("_source", {}).get("layers", {})
                dns_layer = layers.get("dns", {})
                
                query_name = dns_layer.get("dns.qry.name", [None])[0] if isinstance(dns_layer.get("dns.qry.name"), list) else dns_layer.get("dns.qry.name")
                query_type = dns_layer.get("dns.qry.type", [None])[0] if isinstance(dns_layer.get("dns.qry.type"), list) else dns_layer.get("dns.qry.type")
                
                if not query_name:
                    continue
                
                # Map query type number to name
                query_type_map = {
                    "1": "A",
                    "2": "NS",
                    "5": "CNAME",
                    "15": "MX",
                    "16": "TXT",
                    "28": "AAAA"
                }
                query_type_name = query_type_map.get(str(query_type), f"TYPE{query_type}")
                
                # Extract response data
                response_data = {}
                if dns_layer.get("dns.a"):
                    response_data["a"] = dns_layer.get("dns.a", [])
                if dns_layer.get("dns.aaaa"):
                    response_data["aaaa"] = dns_layer.get("dns.aaaa", [])
                if dns_layer.get("dns.resp.name"):
                    response_data["cname"] = dns_layer.get("dns.resp.name", [])
                
                # Extract timestamp
                frame_time = layers.get("frame", {}).get("frame.time", [None])[0] if isinstance(layers.get("frame", {}).get("frame.time"), list) else layers.get("frame", {}).get("frame.time")
                
                dns_query = {
                    "id": str(uuid4()),
                    "session_id": session_id,
                    "query": query_name,
                    "query_type": query_type_name,
                    "response": response_data if response_data else None,
                    "timestamp": frame_time or datetime.utcnow().isoformat()
                }
                
                dns_queries.append(dns_query)
            
            log.info("dns_queries_extracted", 
                    pcap_path=str(pcap_path),
                    count=len(dns_queries),
                    session_id=session_id)
            
            # Store DNS queries in database
            if dns_queries and self.db_manager:
                await self._store_dns_queries(dns_queries)
            
            # Trigger DNS analysis for each query
            if dns_queries and self.analysis_orchestrator:
                for query in dns_queries:
                    try:
                        await self.analysis_orchestrator.analyze_dns_query(query)
                    except Exception as e:
                        log.warning("dns_analysis_trigger_failed", 
                                   query=query.get("query"),
                                   error=str(e))
            
            return dns_queries
        
        except subprocess.TimeoutExpired:
            log.error("tshark_timeout", path=str(pcap_path))
            return []
        except Exception as e:
            log.error("pcap_processing_failed", 
                     path=str(pcap_path),
                     error=str(e),
                     error_type=type(e).__name__)
            return []
    
    async def _store_dns_queries(self, queries: List[Dict[str, Any]]) -> None:
        """
        Store DNS queries in database.
        
        Args:
            queries: List of DNS query dictionaries
        """
        if not self.db_manager:
            return
        
        try:
            async with self.db_manager.get_session() as session:
                for query in queries:
                    # Parse timestamp
                    timestamp_str = query.get("timestamp")
                    if isinstance(timestamp_str, str):
                        try:
                            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        except Exception:
                            timestamp = datetime.utcnow()
                    else:
                        timestamp = datetime.utcnow()
                    
                    dns_query_db = DNSQueryDB(
                        id=query["id"],
                        session_id=query["session_id"],
                        timestamp=timestamp,
                        query=query["query"],
                        query_type=query["query_type"],
                        response=query.get("response")
                    )
                    session.add(dns_query_db)
                
                await session.commit()
                log.debug("dns_queries_stored", count=len(queries))
        
        except Exception as e:
            log.error("dns_queries_storage_failed", 
                     error=str(e),
                     error_type=type(e).__name__)

