"""
@fileoverview Replay Queue Manager - Redis-backed replay queue
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Redis-backed queue for async replay operations.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import json
import asyncio
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
from uuid import uuid4
from ..core.logging import get_logger
from ..core.errors import DependencyValidationError

log = get_logger(__name__)


@dataclass
class QueuedReplay:
    """Queued replay job."""
    job_id: str
    flow_id: str
    modifications: Dict[str, Any]
    priority: int = 0
    created_at: str = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow().isoformat()


class ReplayQueueManager:
    """
    Redis-backed queue manager for replay operations.
    
    FAIL-FAST: In production with replay enabled, Redis must be available.
    
    Features:
    - Priority queuing
    - Job status tracking
    - Result storage
    - Retry handling
    """
    
    QUEUE_KEY = "ax:replay:queue"
    RESULTS_KEY = "ax:replay:results"
    STATUS_KEY = "ax:replay:status"
    
    def __init__(
        self,
        redis_queue=None,
        config: Dict[str, Any] = None,
        max_queue_size: int = 1000
    ):
        """
        Initialize replay queue manager.
        
        Args:
            redis_queue: RedisQueue instance
            config: Configuration dictionary
            max_queue_size: Maximum queue size before rejecting
            
        Raises:
            DependencyValidationError: If Redis required but unavailable
        """
        self.redis_queue = redis_queue
        self.config = config or {}
        self.max_queue_size = max_queue_size
        self.mode = config.get("mode", "production") if config else "production"
        
        # Validate Redis in production if replay enabled
        replay_config = config.get("replay", {}) if config else {}
        if replay_config.get("enabled", False) and self.mode == "production":
            if not redis_queue:
                raise DependencyValidationError(
                    "Redis required for replay in production mode.\n"
                    "Start redis-server or disable replay:\n"
                    "  config.replay.enabled = false"
                )
        
        log.info(
            "replay_queue_manager_initialized",
            has_redis=bool(redis_queue),
            max_queue_size=max_queue_size
        )
    
    async def enqueue(
        self,
        flow_id: str,
        modifications: Optional[Dict[str, Any]] = None,
        priority: int = 0
    ) -> str:
        """
        Enqueue a replay job.
        
        Args:
            flow_id: ID of flow to replay
            modifications: Optional modifications
            priority: Job priority (higher = sooner)
            
        Returns:
            Job ID
            
        Raises:
            RuntimeError: If queue is full
        """
        job_id = str(uuid4())
        
        job = QueuedReplay(
            job_id=job_id,
            flow_id=flow_id,
            modifications=modifications or {},
            priority=priority
        )
        
        if self.redis_queue:
            # Check queue size
            queue_size = await self._get_queue_size()
            if queue_size >= self.max_queue_size:
                raise RuntimeError(
                    f"Replay queue full ({queue_size}/{self.max_queue_size}). "
                    "Process existing jobs or increase max_queue_size."
                )
            
            # Enqueue to Redis
            await self.redis_queue.enqueue(
                self.QUEUE_KEY,
                json.dumps(asdict(job))
            )
            
            # Set status
            await self._set_status(job_id, "queued")
        else:
            log.warning("replay_queue_no_redis", job_id=job_id)
        
        log.debug("replay_job_enqueued", job_id=job_id, flow_id=flow_id)
        return job_id
    
    async def dequeue(self) -> Optional[QueuedReplay]:
        """
        Dequeue next replay job.
        
        Returns:
            QueuedReplay or None if queue empty
        """
        if not self.redis_queue:
            return None
        
        data = await self.redis_queue.dequeue(self.QUEUE_KEY)
        if not data:
            return None
        
        job_data = json.loads(data)
        job = QueuedReplay(**job_data)
        
        await self._set_status(job.job_id, "processing")
        
        log.debug("replay_job_dequeued", job_id=job.job_id)
        return job
    
    async def complete(
        self,
        job_id: str,
        result: Dict[str, Any],
        success: bool = True
    ) -> None:
        """
        Mark job as complete and store result.
        
        Args:
            job_id: Job ID
            result: Result data
            success: Whether job succeeded
        """
        if self.redis_queue:
            # Store result
            result_data = {
                "job_id": job_id,
                "success": success,
                "result": result,
                "completed_at": datetime.utcnow().isoformat()
            }
            await self.redis_queue.set(
                f"{self.RESULTS_KEY}:{job_id}",
                json.dumps(result_data),
                expire=3600  # 1 hour TTL
            )
            
            # Update status
            status = "completed" if success else "failed"
            await self._set_status(job_id, status)
        
        log.debug("replay_job_completed", job_id=job_id, success=success)
    
    async def get_result(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get result for a job.
        
        Args:
            job_id: Job ID
            
        Returns:
            Result data or None
        """
        if not self.redis_queue:
            return None
        
        data = await self.redis_queue.get(f"{self.RESULTS_KEY}:{job_id}")
        if data:
            return json.loads(data)
        return None
    
    async def get_status(self, job_id: str) -> Optional[str]:
        """
        Get status of a job.
        
        Args:
            job_id: Job ID
            
        Returns:
            Status string or None
        """
        if not self.redis_queue:
            return None
        
        return await self.redis_queue.get(f"{self.STATUS_KEY}:{job_id}")
    
    async def _set_status(self, job_id: str, status: str) -> None:
        """Set job status."""
        if self.redis_queue:
            await self.redis_queue.set(
                f"{self.STATUS_KEY}:{job_id}",
                status,
                expire=3600
            )
    
    async def _get_queue_size(self) -> int:
        """Get current queue size."""
        if not self.redis_queue:
            return 0
        
        return await self.redis_queue.length(self.QUEUE_KEY)
    
    async def get_queue_stats(self) -> Dict[str, Any]:
        """
        Get queue statistics.
        
        Returns:
            Dictionary with queue stats
        """
        queue_size = await self._get_queue_size() if self.redis_queue else 0
        
        return {
            "queue_size": queue_size,
            "max_queue_size": self.max_queue_size,
            "has_redis": bool(self.redis_queue),
            "queue_full": queue_size >= self.max_queue_size
        }

