"""
@fileoverview VirusTotal Integration - Domain reputation checks
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

VirusTotal API client for domain reputation checks.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import requests
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from ...core.logging import get_logger
from ...storage.models import ThreatIntelCacheDB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

log = get_logger(__name__)


class VirusTotalClient:
    """VirusTotal API client for domain reputation checks."""
    
    def __init__(self, api_key: Optional[str] = None, cache_ttl_hours: int = 24):
        """
        Initialize VirusTotal client.
        
        Args:
            api_key: VirusTotal API key (optional)
            cache_ttl_hours: Cache TTL in hours (default: 24)
        """
        self.api_key = api_key
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.base_url = "https://www.virustotal.com/api/v3"
        log.info("virustotal_client_initialized", has_api_key=bool(api_key))
    
    async def check_domain(
        self, 
        domain: str, 
        db_session: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Check domain reputation.
        
        Args:
            domain: Domain to check
            db_session: Optional database session for caching
            
        Returns:
            Reputation data
        """
        if not self.api_key:
            log.warning("virustotal_api_key_missing")
            return {
                "status": "no_api_key",
                "reputation": "unknown",
                "message": "VirusTotal API key not configured"
            }
        
        # Check cache first
        if db_session:
            cached = await self._get_from_cache(domain, db_session)
            if cached:
                log.debug("virustotal_cache_hit", domain=domain)
                return cached
        
        # If cache miss, query API
        try:
            headers = {"x-apikey": self.api_key}
            response = requests.get(
                f"{self.base_url}/domains/{domain}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                reputation = self._parse_reputation(data)
                
                # Cache result
                if db_session:
                    await self._save_to_cache(domain, reputation, db_session)
                
                log.debug("virustotal_check_success", domain=domain, reputation=reputation.get("reputation"))
                return reputation
            elif response.status_code == 404:
                log.debug("virustotal_domain_not_found", domain=domain)
                return {
                    "status": "not_found",
                    "reputation": "unknown",
                    "message": "Domain not found in VirusTotal database"
                }
            elif response.status_code == 429:
                log.warning("virustotal_rate_limit", domain=domain)
                return {
                    "status": "rate_limited",
                    "reputation": "unknown",
                    "message": "VirusTotal rate limit exceeded"
                }
            else:
                log.warning("virustotal_api_error", status_code=response.status_code, domain=domain)
                return {
                    "status": "error",
                    "reputation": "unknown",
                    "message": f"API error: {response.status_code}"
                }
        
        except requests.exceptions.Timeout:
            log.warning("virustotal_timeout", domain=domain)
            return {
                "status": "timeout",
                "reputation": "unknown",
                "message": "VirusTotal API timeout"
            }
        except Exception as e:
            log.error("virustotal_request_failed", error=str(e), domain=domain)
            return {
                "status": "error",
                "reputation": "unknown",
                "message": f"Request failed: {str(e)}"
            }
    
    def _parse_reputation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal response."""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        
        # Determine reputation
        if malicious > 0:
            reputation = "malicious"
        elif suspicious > 0:
            reputation = "suspicious"
        elif harmless > 0:
            reputation = "clean"
        else:
            reputation = "unknown"
        
        return {
            "status": "success",
            "reputation": reputation,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "undetected_count": undetected,
            "total_scans": malicious + suspicious + harmless + undetected,
            "metadata": {
                "last_analysis_date": attributes.get("last_analysis_date"),
                "categories": attributes.get("categories", {}),
                "popularity_ranks": attributes.get("popularity_ranks", {})
            }
        }
    
    async def _get_from_cache(
        self, 
        domain: str, 
        db_session: AsyncSession
    ) -> Optional[Dict[str, Any]]:
        """Get cached reputation from database."""
        try:
            result = await db_session.execute(
                select(ThreatIntelCacheDB).where(
                    ThreatIntelCacheDB.domain == domain,
                    ThreatIntelCacheDB.source == "virustotal"
                )
            )
            cached = result.scalar_one_or_none()
            
            if cached:
                # Check if cache is still valid
                age = datetime.utcnow() - cached.timestamp
                if age < self.cache_ttl:
                    return {
                        "status": "cached",
                        "reputation": cached.reputation,
                        "metadata": cached.meta_data,
                        "cached_at": cached.timestamp.isoformat()
                    }
            
            return None
        except Exception as e:
            log.warning("virustotal_cache_read_failed", error=str(e))
            return None
    
    async def _save_to_cache(
        self,
        domain: str,
        reputation_data: Dict[str, Any],
        db_session: AsyncSession
    ) -> None:
        """Save reputation to cache."""
        try:
            from datetime import datetime
            
            # Check if exists
            result = await db_session.execute(
                select(ThreatIntelCacheDB).where(
                    ThreatIntelCacheDB.domain == domain,
                    ThreatIntelCacheDB.source == "virustotal"
                )
            )
            existing = result.scalar_one_or_none()
            
            if existing:
                # Update existing
                existing.reputation = reputation_data.get("reputation", "unknown")
                existing.meta_data = reputation_data.get("metadata", {})
                existing.timestamp = datetime.utcnow()
            else:
                # Create new
                cached = ThreatIntelCacheDB(
                    domain=domain,
                    source="virustotal",
                    reputation=reputation_data.get("reputation", "unknown"),
                    meta_data=reputation_data.get("metadata", {}),
                    timestamp=datetime.utcnow()
                )
                db_session.add(cached)
            
            await db_session.commit()
            log.debug("virustotal_cache_saved", domain=domain)
        except Exception as e:
            await db_session.rollback()
            log.warning("virustotal_cache_save_failed", error=str(e))

