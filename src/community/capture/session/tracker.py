"""
@fileoverview Session Tracker - In-memory session management
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

In-memory session tracking with device identification.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import uuid
import time
import asyncio
from typing import Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ...core.logging import get_logger
from ...core.concurrency import AsyncLockManager

log = get_logger(__name__)


@dataclass
class Session:
    """Session data structure."""
    session_id: str
    client_ip: str
    mac_address: Optional[str] = None
    user_agent: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime = field(default_factory=datetime.utcnow)
    request_count: int = 0


class SessionTracker:
    """
    In-memory session tracker with device identification.
    
    Thread-safe using AsyncLockManager from Phase 2a.
    """
    
    def __init__(self, timeout_seconds: int = 3600, database: Optional[Any] = None):
        """
        Initialize session tracker.
        
        Args:
            timeout_seconds: Session timeout in seconds (default: 3600 = 1 hour)
            database: Optional DatabaseManager for persistence (Phase 3)
        """
        self.timeout_seconds = timeout_seconds
        self.database = database  # Optional database for persistence
        self.sessions: Dict[str, Session] = {}
        self.ip_to_session: Dict[str, str] = {}  # IP -> session_id mapping
        self.lock_manager = AsyncLockManager()
        log.debug("session_tracker_initialized", timeout_seconds=timeout_seconds, has_database=database is not None)
    
    async def get_or_create_session(self, client_ip: str, mac_address: Optional[str] = None,
                                   user_agent: str = "") -> str:
        """
        Get existing session or create new one.
        
        Args:
            client_ip: Client IP address
            mac_address: MAC address (optional)
            user_agent: User agent string
            
        Returns:
            Session ID
        """
        async with self.lock_manager.acquire(f"session_{client_ip}"):
            # Check if session exists for this IP
            if client_ip in self.ip_to_session:
                session_id = self.ip_to_session[client_ip]
                if session_id in self.sessions:
                    session = self.sessions[session_id]
                    # Update last activity
                    session.last_activity = datetime.utcnow()
                    session.request_count += 1
                    log.debug("session_updated", session_id=session_id, client_ip=client_ip)
                    return session_id
            
            # Create new session
            session_id = str(uuid.uuid4())
            session = Session(
                session_id=session_id,
                client_ip=client_ip,
                mac_address=mac_address,
                user_agent=user_agent
            )
            self.sessions[session_id] = session
            self.ip_to_session[client_ip] = session_id
            log.info("session_created", session_id=session_id, client_ip=client_ip, mac_address=mac_address)
            
            # Persist to database if available (Phase 3)
            if self.database:
                try:
                    asyncio.create_task(self._persist_session(session))
                except Exception as e:
                    log.warning("session_persistence_failed", session_id=session_id, error=str(e))
                    # Don't fail - persistence is optional
            
            return session_id
    
    async def get_session_id(self, client_ip: str) -> Optional[str]:
        """
        Get session ID for client IP.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            Session ID or None if not found
        """
        async with self.lock_manager.acquire(f"session_{client_ip}"):
            return self.ip_to_session.get(client_ip)
    
    async def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions.
        
        Returns:
            Number of sessions removed
        """
        now = datetime.utcnow()
        expired = []
        
        for session_id, session in self.sessions.items():
            if (now - session.last_activity).total_seconds() > self.timeout_seconds:
                expired.append(session_id)
        
        removed_count = 0
        for session_id in expired:
            async with self.lock_manager.acquire(f"session_{session_id}"):
                if session_id in self.sessions:
                    session = self.sessions[session_id]
                    # Remove from IP mapping
                    if session.client_ip in self.ip_to_session:
                        del self.ip_to_session[session.client_ip]
                    # Remove session
                    del self.sessions[session_id]
                    removed_count += 1
                    log.debug("session_expired_removed", session_id=session_id)
        
        if removed_count > 0:
            log.info("expired_sessions_cleaned", count=removed_count)
        
        return removed_count
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID (non-async for compatibility)."""
        return self.sessions.get(session_id)
    
    def get_all_sessions(self) -> Dict[str, Session]:
        """Get all active sessions."""
        return self.sessions.copy()
    
    def get_stats(self) -> dict:
        """Get session tracker statistics."""
        return {
            "active_sessions": len(self.sessions),
            "timeout_seconds": self.timeout_seconds,
            "total_requests": sum(s.request_count for s in self.sessions.values())
        }
    
    async def _persist_session(self, session: Session) -> None:
        """
        Persist session to database (Phase 3).
        
        Args:
            session: Session object to persist
        """
        if not self.database:
            return
        
        try:
            from ...storage.models import SessionDB
            
            async with self.database.get_session() as db:
                # Check if session already exists
                from sqlalchemy import select
                result = await db.execute(
                    select(SessionDB).where(SessionDB.session_id == session.session_id)
                )
                existing = result.scalar_one_or_none()
                
                if existing:
                    # Update existing
                    existing.last_activity = session.last_activity
                    existing.request_count = session.request_count
                    log.debug("session_updated_in_db", session_id=session.session_id)
                else:
                    # Create new
                    session_db = SessionDB(
                        session_id=session.session_id,
                        client_ip=session.client_ip,
                        mac_address=session.mac_address,
                        user_agent=session.user_agent,
                        created_at=session.created_at,
                        last_activity=session.last_activity,
                        request_count=session.request_count
                    )
                    db.add(session_db)
                    log.debug("session_persisted_to_db", session_id=session.session_id)
                
                await db.commit()
        except Exception as e:
            log.error("session_persistence_error", session_id=session.session_id, error=str(e))
            # Don't raise - persistence failures shouldn't break session tracking

