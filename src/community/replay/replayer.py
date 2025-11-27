"""
@fileoverview Request Replayer - Replay captured HTTP requests
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Request replayer for re-sending captured HTTP requests with modifications.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import asyncio
import httpx
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4
from ..core.logging import get_logger
from ..storage.models import FlowDB

log = get_logger(__name__)


@dataclass
class ReplayRequest:
    """Request to be replayed."""
    replay_id: str
    original_flow_id: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[bytes] = None
    modifications: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ReplayResult:
    """Result of a replay operation."""
    replay_id: str
    original_flow_id: str
    success: bool
    status_code: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body: Optional[bytes] = None
    error: Optional[str] = None
    duration_ms: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "replay_id": self.replay_id,
            "original_flow_id": self.original_flow_id,
            "success": self.success,
            "status_code": self.status_code,
            "response_headers": self.response_headers,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat()
        }


class RequestReplayer:
    """
    Request replayer for re-sending captured HTTP requests.
    
    Supports:
    - Single request replay
    - Batch replay
    - Request modifications (headers, params, body)
    - Async execution
    """
    
    def __init__(
        self,
        db_manager=None,
        redis_queue=None,
        timeout_seconds: int = 30,
        max_concurrent: int = 10
    ):
        """
        Initialize request replayer.
        
        Args:
            db_manager: Database manager for retrieving flows
            redis_queue: Redis queue for async replay (optional)
            timeout_seconds: Request timeout
            max_concurrent: Maximum concurrent replays
        """
        self.db_manager = db_manager
        self.redis_queue = redis_queue
        self.timeout = timeout_seconds
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        
        log.info(
            "request_replayer_initialized",
            timeout=timeout_seconds,
            max_concurrent=max_concurrent
        )
    
    async def replay_flow(
        self,
        flow_id: str,
        modifications: Optional[Dict[str, Any]] = None
    ) -> ReplayResult:
        """
        Replay a captured flow.
        
        Args:
            flow_id: ID of flow to replay
            modifications: Optional modifications to apply
            
        Returns:
            ReplayResult with response data
        """
        replay_id = str(uuid4())
        log.debug("replay_starting", replay_id=replay_id, flow_id=flow_id)
        
        # Get original flow from database
        flow = await self._get_flow(flow_id)
        if not flow:
            return ReplayResult(
                replay_id=replay_id,
                original_flow_id=flow_id,
                success=False,
                error=f"Flow not found: {flow_id}"
            )
        
        # Build request
        request = self._build_request(flow, modifications or {})
        
        # Execute replay
        return await self._execute_replay(request)
    
    async def replay_batch(
        self,
        flow_ids: List[str],
        modifications: Optional[Dict[str, Any]] = None
    ) -> List[ReplayResult]:
        """
        Replay multiple flows.
        
        Args:
            flow_ids: List of flow IDs to replay
            modifications: Optional modifications to apply to all
            
        Returns:
            List of ReplayResults
        """
        tasks = [
            self.replay_flow(flow_id, modifications)
            for flow_id in flow_ids
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to error results
        processed = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed.append(ReplayResult(
                    replay_id=str(uuid4()),
                    original_flow_id=flow_ids[i],
                    success=False,
                    error=str(result)
                ))
            else:
                processed.append(result)
        
        return processed
    
    async def _get_flow(self, flow_id: str) -> Optional[Dict[str, Any]]:
        """Get flow from database."""
        if not self.db_manager:
            log.warning("replay_no_db_manager")
            return None
        
        try:
            async with self.db_manager.get_session() as session:
                from sqlalchemy import select
                result = await session.execute(
                    select(FlowDB).where(FlowDB.flow_id == flow_id)
                )
                flow = result.scalar_one_or_none()
                
                if flow:
                    return flow.to_dict()
                return None
        except Exception as e:
            log.error("replay_get_flow_failed", flow_id=flow_id, error=str(e))
            return None
    
    def _build_request(
        self,
        flow: Dict[str, Any],
        modifications: Dict[str, Any]
    ) -> ReplayRequest:
        """
        Build replay request from flow with modifications.
        
        Args:
            flow: Original flow data
            modifications: Modifications to apply
            
        Returns:
            ReplayRequest ready to execute
        """
        # Start with original values
        method = flow.get("method", "GET")
        url = flow.get("url", "")
        headers = flow.get("request_headers", {}) or {}
        body = flow.get("request_body")
        
        # Apply modifications
        if "method" in modifications:
            method = modifications["method"]
        
        if "url" in modifications:
            url = modifications["url"]
        
        if "headers" in modifications:
            # Merge headers
            headers.update(modifications["headers"])
        
        if "remove_headers" in modifications:
            for header in modifications["remove_headers"]:
                headers.pop(header, None)
        
        if "body" in modifications:
            body = modifications["body"]
            if isinstance(body, str):
                body = body.encode("utf-8")
        
        # Remove hop-by-hop headers
        hop_by_hop = [
            "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers", "transfer-encoding",
            "upgrade", "host"
        ]
        headers = {
            k: v for k, v in headers.items()
            if k.lower() not in hop_by_hop
        }
        
        return ReplayRequest(
            replay_id=str(uuid4()),
            original_flow_id=flow.get("flow_id", ""),
            method=method,
            url=url,
            headers=headers,
            body=body if isinstance(body, bytes) else None,
            modifications=modifications
        )
    
    async def _execute_replay(self, request: ReplayRequest) -> ReplayResult:
        """
        Execute replay request.
        
        Args:
            request: ReplayRequest to execute
            
        Returns:
            ReplayResult with response
        """
        async with self._semaphore:
            start_time = datetime.utcnow()
            
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    verify=False,  # nosec B501 - Intentional: replay requires connecting to arbitrary targets
                    follow_redirects=True
                ) as client:
                    response = await client.request(
                        method=request.method,
                        url=request.url,
                        headers=request.headers,
                        content=request.body
                    )
                    
                    duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                    
                    log.debug(
                        "replay_completed",
                        replay_id=request.replay_id,
                        status_code=response.status_code,
                        duration_ms=duration_ms
                    )
                    
                    return ReplayResult(
                        replay_id=request.replay_id,
                        original_flow_id=request.original_flow_id,
                        success=True,
                        status_code=response.status_code,
                        response_headers=dict(response.headers),
                        response_body=response.content,
                        duration_ms=duration_ms
                    )
                    
            except httpx.TimeoutException:
                return ReplayResult(
                    replay_id=request.replay_id,
                    original_flow_id=request.original_flow_id,
                    success=False,
                    error=f"Request timed out after {self.timeout}s"
                )
            except Exception as e:
                log.error(
                    "replay_failed",
                    replay_id=request.replay_id,
                    error=str(e)
                )
                return ReplayResult(
                    replay_id=request.replay_id,
                    original_flow_id=request.original_flow_id,
                    success=False,
                    error=str(e)
                )

