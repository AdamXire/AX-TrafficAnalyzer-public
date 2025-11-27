"""
@fileoverview Authentication API - Login and token management
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Authentication endpoints for JWT token generation.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..storage.models import User
from ..api.dependencies import get_db_session, get_jwt_manager, get_current_user
from ..api.rate_limit import rate_limit_dependency
from ..core.security import JWTManager
from ..core.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    """Login request model."""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Login response model."""
    access_token: str
    token_type: str = "bearer"
    user_id: str
    role: str


@router.post("/login", response_model=LoginResponse, dependencies=[Depends(rate_limit_dependency)])
async def login(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db_session),
    jwt_manager: JWTManager = Depends(get_jwt_manager)
):
    """
    Authenticate user and return JWT token.
    
    Args:
        request: Login credentials
        db: Database session
        jwt_manager: JWT manager
        
    Returns:
        JWT token and user info
        
    Raises:
        HTTPException: If credentials invalid
    """
    log.debug("login_attempt", username=request.username)
    
    # Find user by username
    result = await db.execute(select(User).where(User.username == request.username))
    user = result.scalar_one_or_none()
    
    if not user:
        log.warning("login_failed_user_not_found", username=request.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    if not user.active:
        log.warning("login_failed_user_inactive", username=request.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive"
        )
    
    # Verify password
    if not user.verify_password(request.password):
        log.warning("login_failed_invalid_password", username=request.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Update last login
    user.last_login = datetime.utcnow()
    await db.commit()
    
    # Generate JWT token
    token = jwt_manager.create_token(user.id, user.role)
    
    log.info("login_success", user_id=user.id, username=user.username, role=user.role)
    
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user_id=user.id,
        role=user.role
    )


@router.get("/me")
async def get_current_user_info(
    current_user: dict = Depends(get_current_user)
):
    """
    Get current authenticated user information.
    
    Args:
        current_user: Authenticated user from JWT token
        
    Returns:
        User information dict with user_id and role
    """
    log.debug("get_current_user_info", user_id=current_user.get("user_id"), role=current_user.get("role"))
    return {
        "user_id": current_user.get("user_id"),
        "role": current_user.get("role"),
        "authenticated": True
    }

