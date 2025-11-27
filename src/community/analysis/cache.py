"""
@fileoverview Analysis Result Cache - Caching for performance
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Caching layer for analysis results to improve performance.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import OrderedDict
from ..core.logging import get_logger

log = get_logger(__name__)


class AnalysisCache:
    """
    LRU cache for analysis results.
    
    Caches protocol analysis results to avoid re-analyzing identical flows.
    Cache key: (flow_id, analyzer_name)
    """
    
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        """
        Initialize analysis cache.
        
        Args:
            max_size: Maximum number of cached entries
            ttl_seconds: Time-to-live for cache entries (default: 1 hour)
        """
        self.max_size = max_size
        self.ttl = timedelta(seconds=ttl_seconds)
        self.cache: OrderedDict[str, tuple] = OrderedDict()  # key -> (result, timestamp)
        log.info("analysis_cache_initialized", max_size=max_size, ttl_seconds=ttl_seconds)
    
    def get(self, flow_id: str, analyzer_name: str) -> Optional[Dict[str, Any]]:
        """
        Get cached analysis result.
        
        Args:
            flow_id: Flow ID
            analyzer_name: Analyzer name
            
        Returns:
            Cached result or None if not found/expired
        """
        key = f"{flow_id}:{analyzer_name}"
        
        if key not in self.cache:
            return None
        
        result, timestamp = self.cache[key]
        
        # Check if expired
        if datetime.utcnow() - timestamp > self.ttl:
            del self.cache[key]
            log.debug("analysis_cache_expired", key=key)
            return None
        
        # Move to end (LRU)
        self.cache.move_to_end(key)
        log.debug("analysis_cache_hit", key=key)
        return result
    
    def set(self, flow_id: str, analyzer_name: str, result: Dict[str, Any]) -> None:
        """
        Cache analysis result.
        
        Args:
            flow_id: Flow ID
            analyzer_name: Analyzer name
            result: Analysis result dictionary
        """
        key = f"{flow_id}:{analyzer_name}"
        
        # Remove oldest if at capacity
        if len(self.cache) >= self.max_size and key not in self.cache:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            log.debug("analysis_cache_evicted", key=oldest_key)
        
        self.cache[key] = (result, datetime.utcnow())
        self.cache.move_to_end(key)
        log.debug("analysis_cache_set", key=key)
    
    def clear(self) -> None:
        """Clear all cached entries."""
        self.cache.clear()
        log.info("analysis_cache_cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache stats
        """
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "ttl_seconds": self.ttl.total_seconds(),
            "usage_percent": (len(self.cache) / self.max_size * 100) if self.max_size > 0 else 0
        }

