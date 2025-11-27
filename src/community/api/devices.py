"""
@fileoverview Devices API - Device aggregation endpoints
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

REST API endpoints for device aggregation.
"""

from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from ..api.dependencies import get_current_user, get_db_session
from ..storage.models import SessionDB
from ..core.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


@router.get("/")
async def list_devices(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
) -> List[dict]:
    """
    List devices with aggregated statistics.
    
    Args:
        limit: Maximum devices to return
        offset: Number to skip
        current_user: Authenticated user
        db: Database session
        
    Returns:
        List of device dictionaries with stats
    """
    log.debug("devices_list_request", user_id=current_user.get("user_id"), limit=limit, offset=offset)
    
    # Aggregate sessions by IP (or MAC if available)
    query = (
        select(
            SessionDB.client_ip,
            SessionDB.mac_address,
            func.count(SessionDB.session_id).label('session_count'),
            func.sum(SessionDB.request_count).label('total_requests'),
            func.max(SessionDB.last_activity).label('last_seen')
        )
        .group_by(SessionDB.client_ip, SessionDB.mac_address)
        .order_by(desc('last_seen'))
        .limit(limit)
        .offset(offset)
    )
    
    result = await db.execute(query)
    devices = result.all()
    
    device_list = []
    for device in devices:
        device_dict = {
            "client_ip": device.client_ip,
            "mac_address": device.mac_address,
            "session_count": device.session_count,
            "total_requests": device.total_requests or 0,
            "last_seen": device.last_seen.isoformat() if device.last_seen else None,
            "identifier": device.mac_address or device.client_ip  # Primary identifier
        }
        device_list.append(device_dict)
    
    log.debug("devices_list_response", count=len(device_list))
    return device_list

