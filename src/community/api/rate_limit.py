"""
@fileoverview Rate Limiting - Redis-based rate limiting
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Redis-based rate limiting for API endpoints.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import Optional
from fastapi import HTTPException, Request, status
from datetime import datetime, timedelta
from ..core.logging import get_logger

log = get_logger(__name__)


class RedisRateLimiter:
    """
    Redis-based rate limiter.
    
    Falls back to in-memory if Redis unavailable (fail-fast on config).
    """
    
    def __init__(self, redis_url: Optional[str] = None, enabled: bool = True):
        """
        Initialize rate limiter.
        
        Args:
            redis_url: Redis connection URL (None = in-memory fallback)
            enabled: Whether rate limiting is enabled
        """
        self.enabled = enabled
        self.redis_url = redis_url
        self.redis = None
        self._memory_store: dict = {}  # Fallback in-memory store
        
        if enabled and redis_url:
            try:
                import redis.asyncio as redis
                self.redis = redis.from_url(redis_url)
                log.debug("rate_limiter_redis_initialized", url=redis_url)
            except Exception as e:
                log.warning("rate_limiter_redis_failed", error=str(e), falling_back_to_memory=True)
                self.redis = None
    
    async def check_rate_limit(
        self,
        key: str,
        max_requests: int = 5,
        window_seconds: int = 300  # 5 minutes
    ) -> bool:
        """
        Check if rate limit exceeded.
        
        Args:
            key: Rate limit key (e.g., "login:192.168.1.1")
            max_requests: Maximum requests per window
            window_seconds: Time window in seconds
            
        Returns:
            True if allowed, False if rate limit exceeded
        """
        if not self.enabled:
            return True
        
        if self.redis:
            try:
                current = await self.redis.get(key)
                
                if current is None:
                    await self.redis.setex(key, window_seconds, 1)
                    log.debug("rate_limit_check", key=key, count=1, allowed=True)
                    return True
                
                count = int(current)
                if count >= max_requests:
                    log.warning("rate_limit_exceeded", key=key, count=count, max=max_requests)
                    return False
                
                await self.redis.incr(key)
                log.debug("rate_limit_check", key=key, count=count+1, allowed=True)
                return True
            except Exception as e:
                log.warning("rate_limit_redis_error", key=key, error=str(e), falling_back_to_memory=True)
                # Fall through to memory store
        else:
            # In-memory fallback
            now = datetime.utcnow()
            if key not in self._memory_store:
                self._memory_store[key] = {"count": 1, "reset_at": now + timedelta(seconds=window_seconds)}
                return True
            
            entry = self._memory_store[key]
            if now > entry["reset_at"]:
                # Reset window
                entry["count"] = 1
                entry["reset_at"] = now + timedelta(seconds=window_seconds)
                return True
            
            if entry["count"] >= max_requests:
                log.warning("rate_limit_exceeded", key=key, count=entry["count"], max=max_requests)
                return False
            
            entry["count"] += 1
            log.debug("rate_limit_check", key=key, count=entry["count"], allowed=True)
            return True


# Global rate limiter instance (will be initialized from config)
_rate_limiter: Optional[RedisRateLimiter] = None


def init_rate_limiter(config: dict) -> None:
    """
    Initialize global rate limiter from config.
    
    Args:
        config: Configuration dict
    """
    global _rate_limiter
    
    rate_config = config.get("rate_limiting", {})
    enabled = rate_config.get("enabled", True)
    redis_url = rate_config.get("redis_url", "redis://localhost:6379")
    
    _rate_limiter = RedisRateLimiter(redis_url=redis_url, enabled=enabled)
    log.info("rate_limiter_initialized", enabled=enabled, redis_url=redis_url if enabled else None)


async def rate_limit_dependency(
    request: Request,
    max_requests: int = 5,
    window_seconds: int = 300
) -> None:
    """
    FastAPI dependency for rate limiting.
    
    Args:
        request: FastAPI Request object
        max_requests: Maximum requests per window
        window_seconds: Time window in seconds
        
    Raises:
        HTTPException: If rate limit exceeded
    """
    global _rate_limiter
    
    if not _rate_limiter:
        # Not initialized - allow request (fail-open for now)
        log.debug("rate_limiter_not_initialized")
        return
    
    client_ip = request.client.host if request.client else "unknown"
    key = f"rate_limit:login:{client_ip}"
    
    allowed = await _rate_limiter.check_rate_limit(
        key=key,
        max_requests=max_requests,
        window_seconds=window_seconds
    )
    
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later."
        )

