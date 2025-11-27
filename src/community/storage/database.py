"""
@fileoverview Database Manager - SQLite connection and session management
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Database connection manager with sync/async wrapper for orchestrator integration.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import asyncio
from pathlib import Path
from typing import Optional
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, AsyncEngine
from sqlalchemy.orm import sessionmaker
from ..core.errors import ResourceError
from ..core.logging import get_logger

log = get_logger(__name__)


class DatabaseManager:
    """
    Database connection manager with sync/async wrapper.
    
    Provides sync start/stop methods for orchestrator compatibility,
    while using async SQLAlchemy internally for non-blocking I/O.
    """
    
    def __init__(self, db_path: str, pool_size: int = 5, max_overflow: int = 10):
        """
        Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file
            pool_size: Connection pool size (default: 5)
            max_overflow: Maximum overflow connections (default: 10)
        """
        self.db_path = Path(db_path)
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.engine: Optional[AsyncEngine] = None
        self.async_session_maker: Optional[sessionmaker] = None
        log.debug("database_manager_initialized", db_path=str(db_path), pool_size=pool_size)
    
    async def start(self) -> None:
        """
        Initialize database (async).
        
        Raises:
            ResourceError: If database initialization fails
        """
        log.info("database_start_begin", db_path=str(self.db_path))
        try:
            await self._async_start()
            log.info("database_start_complete")
        except Exception as e:
            log.error("database_start_failed", error=str(e), error_type=type(e).__name__)
            raise ResourceError(
                f"Failed to initialize database at {self.db_path}: {e}",
                None
            ) from e
    
    async def _async_start(self) -> None:
        """Async database initialization."""
        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        log.debug("database_directory_ensured", dir=str(self.db_path.parent))
        
        # Create async engine with aiosqlite
        db_url = f"sqlite+aiosqlite:///{self.db_path}"
        log.debug("database_engine_creating", url=db_url.replace(str(self.db_path), "***"))
        
        self.engine = create_async_engine(
            db_url,
            pool_size=self.pool_size,
            max_overflow=self.max_overflow,
            echo=False,  # Set to True for SQL debugging
            future=True
        )
        
        # Create session factory
        self.async_session_maker = sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Test connection
        from sqlalchemy import text
        async with self.engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        
        log.info("database_connected", path=str(self.db_path), pool_size=self.pool_size)
    
    async def stop(self) -> None:
        """Shutdown database connections."""
        if not self.engine:
            log.debug("database_stop_no_engine")
            return
        
        log.info("database_stop_begin")
        try:
            await self._async_stop()
            log.info("database_stop_complete")
        except Exception as e:
            log.error("database_stop_failed", error=str(e))
            raise ResourceError("Database shutdown failed", e)
    
    async def _async_stop(self) -> None:
        """Async database shutdown."""
        if self.engine:
            await self.engine.dispose()
            self.engine = None
            self.async_session_maker = None
            log.debug("database_engine_disposed")
    
    def get_session(self) -> AsyncSession:
        """
        Get async database session.
        
        Returns:
            AsyncSession instance
            
        Raises:
            ResourceError: If database not initialized
        """
        if not self.async_session_maker:
            raise ResourceError(
                "Database not initialized. Call start() first.",
                None
            )
        return self.async_session_maker()
    
    async def execute_in_session(self, func, *args, **kwargs):
        """
        Execute function within database session context.
        
        Args:
            func: Async function that takes session as first argument
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
            
        Returns:
            Result of func execution
        """
        async with self.get_session() as session:
            try:
                result = await func(session, *args, **kwargs)
                await session.commit()
                return result
            except Exception:
                await session.rollback()
                raise
    
    async def create_default_admin(self, username: str, password: str, role: str = "admin") -> bool:
        """
        Create default admin user if not exists.
        
        Args:
            username: Admin username
            password: Admin password (will be hashed)
            role: User role (default: admin)
            
        Returns:
            True if created, False if already exists
            
        Raises:
            ResourceError: If database not initialized
        """
        if not self.async_session_maker:
            raise ResourceError("Database not initialized", None)
        
        import uuid
        import bcrypt
        from sqlalchemy import select
        from .models import User
        
        async with self.get_session() as session:
            try:
                # Check if user exists
                result = await session.execute(
                    select(User).where(User.username == username)
                )
                existing = result.scalar_one_or_none()
                
                if existing:
                    log.info("admin_user_exists", username=username)
                    return False
                
                # Create new admin user
                user_id = str(uuid.uuid4())
                password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                
                admin_user = User(
                    id=user_id,
                    username=username,
                    password_hash=password_hash,
                    role=role,
                    active=True
                )
                
                session.add(admin_user)
                await session.commit()
                
                log.info("admin_user_auto_created", username=username, user_id=user_id)
                return True
            except Exception as e:
                await session.rollback()
                log.error("admin_user_creation_failed", username=username, error=str(e))
                raise ResourceError(f"Failed to create admin user: {e}", e)

