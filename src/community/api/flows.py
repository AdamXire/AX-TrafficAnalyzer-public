"""
@fileoverview Flows API - HTTP flow management endpoints
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

REST API endpoints for HTTP flow management.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, and_, func
from ..api.dependencies import get_current_user, get_db_session, require_role
from ..api.schemas import PaginatedResponse
from ..storage.models import FlowDB
from ..core.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/v1/flows", tags=["flows"])


@router.get("/")
async def list_flows(
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    host: Optional[str] = Query(None, description="Filter by host"),
    method: Optional[str] = Query(None, description="Filter by HTTP method"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
) -> dict:
    """
    List HTTP flows with optional filters and pagination metadata.
    
    Args:
        session_id: Optional session ID filter
        host: Optional host filter
        method: Optional HTTP method filter
        limit: Maximum number of flows to return
        offset: Number of flows to skip
        current_user: Authenticated user
        db: Database session
        
    Returns:
        Paginated response with items, total, limit, offset, has_more
    """
    log.debug(
        "flows_list_request",
        user_id=current_user.get("user_id"),
        session_id=session_id,
        host=host,
        method=method,
        limit=limit,
        offset=offset
    )
    
    # Build filters
    filters = []
    if session_id:
        filters.append(FlowDB.session_id == session_id)
    if host:
        filters.append(FlowDB.host == host)
    if method:
        filters.append(FlowDB.method == method.upper())
    
    # Get total count with filters
    count_query = select(func.count(FlowDB.flow_id))
    if filters:
        count_query = count_query.where(and_(*filters))
    count_result = await db.execute(count_query)
    total = count_result.scalar()
    
    # Build data query
    query = select(FlowDB)
    if filters:
        query = query.where(and_(*filters))
    
    # Order by timestamp (newest first) and paginate
    query = query.order_by(desc(FlowDB.timestamp)).limit(limit).offset(offset)
    
    result = await db.execute(query)
    flows = result.scalars().all()
    
    items = [flow.to_dict() for flow in flows]
    
    response = PaginatedResponse.create(items=items, total=total, limit=limit, offset=offset)
    log.debug("flows_list_response", total=total, returned=len(items), has_more=response.has_more)
    
    return response.dict()


@router.get("/{flow_id}")
async def get_flow(
    flow_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
) -> dict:
    """
    Get flow by ID.
    
    Args:
        flow_id: Flow ID
        current_user: Authenticated user
        db: Database session
        
    Returns:
        Flow dictionary
        
    Raises:
        HTTPException: If flow not found
    """
    log.debug("flow_get_request", flow_id=flow_id, user_id=current_user.get("user_id"))
    
    result = await db.execute(
        select(FlowDB).where(FlowDB.flow_id == flow_id)
    )
    flow = result.scalar_one_or_none()
    
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    
    return flow.to_dict()


@router.delete("/{flow_id}")
async def delete_flow(
    flow_id: str,
    current_user: dict = Depends(require_role(["admin"])),
    db: AsyncSession = Depends(get_db_session)
) -> dict:
    """
    Delete flow (admin only).
    
    Args:
        flow_id: Flow ID
        current_user: Authenticated admin user
        db: Database session
        
    Returns:
        Success message
        
    Raises:
        HTTPException: If flow not found
    """
    log.info("flow_delete_request", flow_id=flow_id, user_id=current_user.get("user_id"))
    
    result = await db.execute(
        select(FlowDB).where(FlowDB.flow_id == flow_id)
    )
    flow = result.scalar_one_or_none()
    
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    
    # Delete using SQLAlchemy 2.0 async API
    from sqlalchemy import delete
    await db.execute(delete(FlowDB).where(FlowDB.flow_id == flow_id))
    await db.commit()
    
    log.debug("entity_deleted", entity_type="flow", id=flow_id)
    log.info("flow_deleted", flow_id=flow_id)
    return {"message": "Flow deleted", "flow_id": flow_id}


@router.get("/stats/summary")
async def get_flow_stats(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
) -> dict:
    """
    Get flow statistics summary.
    
    Args:
        current_user: Authenticated user
        db: Database session
        
    Returns:
        Statistics dictionary
    """
    log.debug("flow_stats_request", user_id=current_user.get("user_id"))
    
    # Get total count
    total_result = await db.execute(select(FlowDB))
    total_flows = len(total_result.scalars().all())
    
    # Get count by method
    methods_result = await db.execute(
        select(FlowDB.method, func.count(FlowDB.flow_id))
        .group_by(FlowDB.method)
    )
    methods = {row[0]: row[1] for row in methods_result.all()}
    
    # Get count by status code range
    status_ranges = {
        "2xx": 0,
        "3xx": 0,
        "4xx": 0,
        "5xx": 0,
        "other": 0
    }
    
    status_result = await db.execute(select(FlowDB.status_code))
    for status_code in status_result.scalars().all():
        if status_code:
            if 200 <= status_code < 300:
                status_ranges["2xx"] += 1
            elif 300 <= status_code < 400:
                status_ranges["3xx"] += 1
            elif 400 <= status_code < 500:
                status_ranges["4xx"] += 1
            elif 500 <= status_code < 600:
                status_ranges["5xx"] += 1
            else:
                status_ranges["other"] += 1
    
    return {
        "total_flows": total_flows,
        "by_method": methods,
        "by_status_range": status_ranges
    }

