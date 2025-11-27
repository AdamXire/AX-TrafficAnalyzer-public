"""
@fileoverview API Dependencies - FastAPI dependency injection
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

FastAPI dependency injection for authentication and database.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..core.security import JWTManager
from ..core.errors import SecurityError
from ..storage.database import DatabaseManager
from ..storage.models import User
from ..core.logging import get_logger

log = get_logger(__name__)

security = HTTPBearer()


def get_jwt_manager(request: Request) -> JWTManager:
    """
    Get JWT manager from app state.
    
    Args:
        request: FastAPI request object
        
    Returns:
        JWTManager instance
        
    Raises:
        HTTPException: If JWT manager not initialized
    """
    jwt_manager = getattr(request.app.state, "jwt_manager", None)
    if not jwt_manager:
        log.error("jwt_manager_not_initialized")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication system not initialized"
        )
    return jwt_manager


def get_database(request: Request) -> DatabaseManager:
    """
    Get database manager from app state.
    
    Args:
        request: FastAPI request object
        
    Returns:
        DatabaseManager instance
        
    Raises:
        HTTPException: If database not initialized
    """
    db_manager = getattr(request.app.state, "database", None)
    if not db_manager:
        log.error("database_not_initialized")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not initialized"
        )
    return db_manager


async def get_db_session(
    db_manager: DatabaseManager = Depends(get_database)
) -> AsyncSession:
    """
    Get database session (async context manager).
    
    Args:
        db_manager: DatabaseManager from dependency
        
    Yields:
        AsyncSession instance
    """
    async with db_manager.get_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    jwt_manager: JWTManager = Depends(get_jwt_manager)
) -> dict:
    """
    Get current authenticated user from JWT token.
    
    Args:
        credentials: HTTP Bearer token credentials
        jwt_manager: JWTManager from dependency
        
    Returns:
        Dict with user_id and role
        
    Raises:
        HTTPException: If token invalid or missing
    """
    try:
        token = credentials.credentials
        payload = jwt_manager.verify_token(token)
        log.debug("user_authenticated", user_id=payload.get("sub"), role=payload.get("role"))
        return {
            "user_id": payload.get("sub"),
            "role": payload.get("role")
        }
    except SecurityError as e:
        log.warning("authentication_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        log.error("authentication_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user_db(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
) -> User:
    """
    Get current user from database.
    
    Args:
        current_user: User info from JWT token
        db: Database session
        
    Returns:
        User model instance
        
    Raises:
        HTTPException: If user not found
    """
    user_id = current_user["user_id"]
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user or not user.active:
        log.warning("user_not_found_or_inactive", user_id=user_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    return user


def require_role(allowed_roles: list[str]):
    """
    Dependency factory for role-based access control.
    
    Args:
        allowed_roles: List of allowed roles (e.g., ["admin", "analyst"])
        
    Returns:
        Dependency function
    """
    async def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        user_role = current_user.get("role")
        if user_role not in allowed_roles:
            log.warning("role_access_denied", user_role=user_role, allowed_roles=allowed_roles)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {allowed_roles}"
            )
        return current_user
    
    return role_checker

