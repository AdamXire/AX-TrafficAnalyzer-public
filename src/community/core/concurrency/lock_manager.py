"""
@fileoverview Async Lock Manager - Resource locking for concurrent operations
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

AsyncLockManager for protecting shared resources from race conditions.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import asyncio
from typing import Dict
from contextlib import asynccontextmanager
from ..logging import get_logger

log = get_logger(__name__)


class AsyncLockManager:
    """
    Async lock manager for protecting shared resources.
    
    Provides per-resource locks to prevent race conditions in concurrent operations.
    """
    
    def __init__(self):
        """Initialize async lock manager."""
        self._locks: Dict[str, asyncio.Lock] = {}
        log.debug("async_lock_manager_initialized")
    
    def _get_lock(self, resource_name: str) -> asyncio.Lock:
        """
        Get or create lock for resource.
        
        Args:
            resource_name: Name of the resource to lock
            
        Returns:
            asyncio.Lock instance for the resource
        """
        if resource_name not in self._locks:
            self._locks[resource_name] = asyncio.Lock()
            log.debug("lock_created", resource=resource_name)
        return self._locks[resource_name]
    
    @asynccontextmanager
    async def acquire(self, resource_name: str):
        """
        Acquire lock for resource (async context manager).
        
        Usage:
            async with lock_manager.acquire("session_123"):
                # Protected code
                pass
        
        Args:
            resource_name: Name of the resource to lock
            
        Yields:
            Lock instance (for context manager)
        """
        lock = self._get_lock(resource_name)
        log.debug("lock_acquiring", resource=resource_name)
        async with lock:
            log.debug("lock_acquired", resource=resource_name)
            try:
                yield lock
            finally:
                log.debug("lock_released", resource=resource_name)
    
    def has_lock(self, resource_name: str) -> bool:
        """Check if lock exists for resource."""
        return resource_name in self._locks
    
    def get_lock_count(self) -> int:
        """Get number of active locks."""
        return len(self._locks)

