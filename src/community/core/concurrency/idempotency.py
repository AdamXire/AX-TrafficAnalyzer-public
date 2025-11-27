"""
@fileoverview Idempotency Manager - Unique request IDs for idempotent operations
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Idempotency manager for ensuring operations are idempotent.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import uuid
import time
from typing import Set, Optional
from ..logging import get_logger

log = get_logger(__name__)


class IdempotencyManager:
    """
    Idempotency manager for unique request IDs.
    
    Tracks processed request IDs to prevent duplicate processing.
    """
    
    def __init__(self, max_tracked: int = 10000):
        """
        Initialize idempotency manager.
        
        Args:
            max_tracked: Maximum number of request IDs to track (default: 10000)
        """
        self.max_tracked = max_tracked
        self.processed_ids: Set[str] = set()
        log.debug("idempotency_manager_initialized", max_tracked=max_tracked)
    
    def generate_id(self) -> str:
        """
        Generate unique request ID.
        
        Returns:
            UUID4 string
        """
        request_id = str(uuid.uuid4())
        log.debug("request_id_generated", request_id=request_id)
        return request_id
    
    def is_processed(self, request_id: str) -> bool:
        """
        Check if request ID has been processed.
        
        Args:
            request_id: Request ID to check
            
        Returns:
            True if already processed
        """
        return request_id in self.processed_ids
    
    def mark_processed(self, request_id: str) -> None:
        """
        Mark request ID as processed.
        
        Args:
            request_id: Request ID to mark
        """
        # Cleanup if too many tracked
        if len(self.processed_ids) >= self.max_tracked:
            # Remove oldest 10% (simple cleanup)
            to_remove = list(self.processed_ids)[:self.max_tracked // 10]
            for rid in to_remove:
                self.processed_ids.remove(rid)
            log.debug("idempotency_cleanup", removed=len(to_remove))
        
        self.processed_ids.add(request_id)
        log.debug("request_id_marked_processed", request_id=request_id)
    
    def clear(self) -> None:
        """Clear all tracked request IDs."""
        count = len(self.processed_ids)
        self.processed_ids.clear()
        log.info("idempotency_cleared", cleared_count=count)
    
    def get_tracked_count(self) -> int:
        """Get number of tracked request IDs."""
        return len(self.processed_ids)

