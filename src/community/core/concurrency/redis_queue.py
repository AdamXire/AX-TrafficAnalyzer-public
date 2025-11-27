"""
@fileoverview Redis Queue - Event queue for traffic processing
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Redis-based message queue for event processing.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import json
from typing import Optional, Dict, Any
import aioredis
from ..errors import NetworkError
from ..logging import get_logger

log = get_logger(__name__)


class RedisQueue:
    """
    Redis-based message queue for event processing.
    
    Provides async queue operations for traffic events.
    Fail-fast if Redis unavailable.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379", queue_name: str = "ax-traffic-events"):
        """
        Initialize Redis queue.
        
        Args:
            redis_url: Redis connection URL (default: redis://localhost:6379)
            queue_name: Queue name for events (default: ax-traffic-events)
            
        Raises:
            NetworkError: If Redis connection fails
        """
        self.redis_url = redis_url
        self.queue_name = queue_name
        self.redis: Optional[aioredis.Redis] = None
        log.debug("redis_queue_initialized", redis_url=redis_url, queue_name=queue_name)
    
    async def connect(self) -> None:
        """
        Connect to Redis (fail-fast if unavailable).
        
        Raises:
            NetworkError: If connection fails
        """
        try:
            self.redis = await aioredis.from_url(self.redis_url, decode_responses=True)
            # Test connection
            await self.redis.ping()
            log.info("redis_connected", redis_url=self.redis_url)
        except Exception as e:
            raise NetworkError(
                f"Failed to connect to Redis at {self.redis_url}: {e}. "
                f"Ensure redis-server is running: sudo systemctl start redis",
                None
            )
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self.redis:
            await self.redis.close()
            log.info("redis_disconnected")
    
    async def enqueue(self, event: Dict[str, Any]) -> None:
        """
        Add event to queue.
        
        Args:
            event: Event dictionary to enqueue
            
        Raises:
            NetworkError: If Redis unavailable or enqueue fails
        """
        if not self.redis:
            await self.connect()
        
        try:
            event_json = json.dumps(event)
            await self.redis.lpush(self.queue_name, event_json)
            log.debug("event_enqueued", queue=self.queue_name, event_type=event.get("type"))
        except Exception as e:
            raise NetworkError(
                f"Failed to enqueue event: {e}",
                None
            )
    
    async def dequeue(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """
        Get next event from queue (blocking).
        
        Args:
            timeout: Timeout in seconds (None = blocking forever)
            
        Returns:
            Event dictionary or None if timeout
        """
        if not self.redis:
            await self.connect()
        
        try:
            if timeout is None:
                result = await self.redis.brpop(self.queue_name, timeout=0)
            else:
                result = await self.redis.brpop(self.queue_name, timeout=int(timeout))
            
            if result:
                _, event_json = result
                event = json.loads(event_json)
                log.debug("event_dequeued", queue=self.queue_name, event_type=event.get("type"))
                return event
            return None
        except Exception as e:
            log.error("event_dequeue_failed", error=str(e))
            raise NetworkError(
                f"Failed to dequeue event: {e}",
                None
            )
    
    async def queue_length(self) -> int:
        """
        Get current queue length.
        
        Returns:
            Number of events in queue
        """
        if not self.redis:
            await self.connect()
        
        try:
            length = await self.redis.llen(self.queue_name)
            return length
        except Exception as e:
            log.error("queue_length_failed", error=str(e))
            return 0

