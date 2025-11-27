"""
@fileoverview Sessions API - Session management endpoints
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

REST API endpoints for session management.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import Optional, List
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from ..api.dependencies import get_current_user, get_db_session, require_role
from ..api.schemas import PaginatedResponse
from ..storage.models import SessionDB
from ..core.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/v1/sessions", tags=["sessions"])


@router.get("/")
async def list_sessions(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
) -> dict:
    """
    List all sessions with pagination metadata (requires authentication).
    
    Args:
        limit: Maximum number of sessions to return
        offset: Number of sessions to skip
        current_user: Authenticated user (from dependency)
        db: Database session
        
    Returns:
        Paginated response with items, total, limit, offset, has_more
    """
    log.debug("sessions_list_request", user_id=current_user.get("user_id"), limit=limit, offset=offset)
    
    # Get total count
    count_result = await db.execute(select(func.count(SessionDB.session_id)))
    total = count_result.scalar()
    
    # Get paginated results
    result = await db.execute(
        select(SessionDB)
        .order_by(desc(SessionDB.created_at))
        .limit(limit)
        .offset(offset)
    )
    sessions = result.scalars().all()
    
    items = [session.to_dict() for session in sessions]
    
    response = PaginatedResponse.create(items=items, total=total, limit=limit, offset=offset)
    log.debug("sessions_list_response", total=total, returned=len(items), has_more=response.has_more)
    
    return response.dict()


@router.get("/{session_id}")
async def get_session(
    session_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
) -> dict:
    """
    Get session by ID.
    
    Args:
        session_id: Session ID
        current_user: Authenticated user
        db: Database session
        
    Returns:
        Session dictionary
        
    Raises:
        HTTPException: If session not found
    """
    log.debug("session_get_request", session_id=session_id, user_id=current_user.get("user_id"))
    
    result = await db.execute(
        select(SessionDB).where(SessionDB.session_id == session_id)
    )
    session = result.scalar_one_or_none()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return session.to_dict()


@router.get("/ip/{client_ip}")
async def get_sessions_by_ip(
    client_ip: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
) -> List[dict]:
    """
    Get all sessions for a client IP address.
    
    Args:
        client_ip: Client IP address
        current_user: Authenticated user
        db: Database session
        
    Returns:
        List of session dictionaries
    """
    log.debug("sessions_by_ip_request", client_ip=client_ip, user_id=current_user.get("user_id"))
    
    result = await db.execute(
        select(SessionDB)
        .where(SessionDB.client_ip == client_ip)
        .order_by(desc(SessionDB.created_at))
    )
    sessions = result.scalars().all()
    
    return [session.to_dict() for session in sessions]


@router.delete("/{session_id}")
async def delete_session(
    session_id: str,
    current_user: dict = Depends(require_role(["admin"])),
    db: AsyncSession = Depends(get_db_session)
) -> dict:
    """
    Delete session (admin only).
    
    Args:
        session_id: Session ID
        current_user: Authenticated admin user
        db: Database session
        
    Returns:
        Success message
        
    Raises:
        HTTPException: If session not found
    """
    log.info("session_delete_request", session_id=session_id, user_id=current_user.get("user_id"))
    
    result = await db.execute(
        select(SessionDB).where(SessionDB.session_id == session_id)
    )
    session = result.scalar_one_or_none()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Delete using SQLAlchemy 2.0 async API
    from sqlalchemy import delete
    await db.execute(delete(SessionDB).where(SessionDB.session_id == session_id))
    await db.commit()
    
    log.debug("entity_deleted", entity_type="session", id=session_id)
    log.info("session_deleted", session_id=session_id)
    return {"message": "Session deleted", "session_id": session_id}


@router.get("/{session_id}/pcap")
async def download_pcap(
    session_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
) -> FileResponse:
    """
    Download PCAP file for session.
    
    Args:
        session_id: Session ID
        current_user: Authenticated user
        db: Database session
        
    Returns:
        PCAP file as download
        
    Raises:
        HTTPException: If session or PCAP not found
    """
    log.debug("pcap_download_request", session_id=session_id, user_id=current_user.get("user_id"))
    
    # Verify session exists
    result = await db.execute(
        select(SessionDB).where(SessionDB.session_id == session_id)
    )
    session = result.scalar_one_or_none()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Find PCAP file
    from ..core.config import load_config
    config = load_config()
    pcap_dir = Path(config.get("capture", {}).get("pcap", {}).get("output_dir", "./captures/pcap"))
    pcap_file = pcap_dir / f"{session_id}.pcap"
    
    if not pcap_file.exists():
        log.warning("pcap_file_not_found", session_id=session_id, path=str(pcap_file))
        raise HTTPException(status_code=404, detail="PCAP file not found")
    
    file_size = pcap_file.stat().st_size
    log.info("pcap_download_success", session_id=session_id, file_size_bytes=file_size)
    
    return FileResponse(
        path=str(pcap_file),
        media_type="application/vnd.tcpdump.pcap",
        filename=f"session_{session_id}.pcap"
    )

