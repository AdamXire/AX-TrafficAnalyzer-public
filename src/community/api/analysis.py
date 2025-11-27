"""
@fileoverview Analysis API Endpoints - Findings, Protocol Analysis, Reports
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

API endpoints for Phase 5 analysis features.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc
from ..storage.models import FindingDB, AnalysisResultDB
from ..api.dependencies import get_current_user, get_db_session
from ..core.logging import get_logger
from ..api.schemas import PaginatedResponse

log = get_logger(__name__)

router = APIRouter(prefix="/api/v1/analysis", tags=["analysis"])

# Production hardening: Rate limiting for analysis endpoints
# Note: Rate limiting can be added via middleware if needed


@router.get("/findings", response_model=PaginatedResponse[dict])
async def list_findings(
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    category: Optional[str] = Query(None, description="Filter by category"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results per page"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """
    List vulnerability findings with pagination.
    
    Args:
        session_id: Optional session ID filter
        severity: Optional severity filter (critical, high, medium, low, info)
        category: Optional category filter
        limit: Maximum number of results
        offset: Pagination offset
        current_user: Authenticated user
        db: Database session
        
    Returns:
        PaginatedResponse with findings
    """
    log.debug("findings_list_request", user_id=current_user.get("user_id"), session_id=session_id, severity=severity)
    
    # Build query
    query = select(FindingDB)
    filters = []
    
    if session_id:
        filters.append(FindingDB.session_id == session_id)
    if severity:
        filters.append(FindingDB.severity == severity)
    if category:
        filters.append(FindingDB.category == category)
    
    if filters:
        query = query.where(and_(*filters))
    
    # Production hardening: Optimized count query
    # Use subquery for better performance with filters
    count_query = select(func.count(FindingDB.id))
    if filters:
        count_query = count_query.where(and_(*filters))
    count_result = await db.execute(count_query)
    total = count_result.scalar_one()
    
    # Apply pagination and ordering (indexed columns for performance)
    query = query.order_by(desc(FindingDB.timestamp), desc(FindingDB.severity)).limit(limit).offset(offset)
    
    result = await db.execute(query)
    findings = result.scalars().all()
    
    log.debug("findings_list_response", count=len(findings), total=total)
    
    return PaginatedResponse(
        items=[finding.to_dict() for finding in findings],
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total
    )


@router.get("/findings/{finding_id}")
async def get_finding(
    finding_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get a specific finding by ID.
    
    Args:
        finding_id: Finding ID
        current_user: Authenticated user
        db: Database session
        
    Returns:
        Finding details
    """
    log.debug("finding_get_request", finding_id=finding_id, user_id=current_user.get("user_id"))
    
    result = await db.execute(select(FindingDB).where(FindingDB.id == finding_id))
    finding = result.scalar_one_or_none()
    
    if not finding:
        log.warning("finding_not_found", finding_id=finding_id)
        raise HTTPException(status_code=404, detail="Finding not found")
    
    log.debug("finding_get_response", finding_id=finding_id)
    return finding.to_dict()


@router.get("/protocols/{flow_id}")
async def get_protocol_analysis(
    flow_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get protocol analysis details for a specific flow.
    
    Returns HTTP headers, cookies, auth mechanisms, etc.
    
    Args:
        flow_id: Flow ID
        current_user: Authenticated user
        db: Database session
        
    Returns:
        Protocol analysis data
    """
    log.debug("protocol_analysis_request", flow_id=flow_id, user_id=current_user.get("user_id"))
    
    # Query analysis_results table for this flow_id
    result = await db.execute(
        select(AnalysisResultDB).where(AnalysisResultDB.flow_id == flow_id)
    )
    analysis_results = result.scalars().all()
    
    if not analysis_results:
        log.warning("no_analysis_results", flow_id=flow_id)
        return {
            "flow_id": flow_id,
            "analyzers": [],
            "message": "No analysis results found for this flow"
        }
    
    # Group by analyzer
    analyzer_data = {}
    for result in analysis_results:
        analyzer_data[result.analyzer_name] = result.to_dict()
    
    log.debug("protocol_analysis_response", flow_id=flow_id, analyzers=list(analyzer_data.keys()))
    
    return {
        "flow_id": flow_id,
        "analyzers": analyzer_data
    }


@router.get("/threat-intel/{domain}")
async def get_threat_intel(
    domain: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get threat intelligence for a domain.
    
    Checks cache first, then queries VirusTotal/OTX if needed.
    
    Args:
        domain: Domain to check
        current_user: Authenticated user
        db: Database session
        
    Returns:
        Threat intelligence data
    """
    log.debug("threat_intel_request", domain=domain, user_id=current_user.get("user_id"))
    
    # TODO: Query threat_intel_cache table
    # TODO: If not found or expired, query external APIs
    
    return {
        "domain": domain,
        "reputation": "unknown",
        "sources": [],
        "message": "Threat intelligence integration pending implementation"
    }


@router.get("/reports/{session_id}")
async def generate_report(
    session_id: str,
    format: str = Query("pdf", description="Report format (pdf, json)"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Generate analysis report for a session.
    
    Returns PDF report with executive summary, findings, and recommendations.
    
    Args:
        session_id: Session ID
        format: Report format (pdf or json)
        current_user: Authenticated user
        db: Database session
        
    Returns:
        Report data or download link
    """
    log.debug("report_generate_request", session_id=session_id, format=format, user_id=current_user.get("user_id"))
    
    # TODO: Implement PDF report generation
    
    return {
        "session_id": session_id,
        "format": format,
        "status": "pending",
        "message": "Report generation feature pending implementation"
    }


@router.get("/stats")
async def get_analysis_stats(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get overall analysis statistics.
    
    Returns counts of findings by severity, category, etc.
    
    Args:
        current_user: Authenticated user
        db: Database session
        
    Returns:
        Analysis statistics
    """
    log.debug("analysis_stats_request", user_id=current_user.get("user_id"))
    
    # Get total findings count
    total_result = await db.execute(select(func.count(FindingDB.id)))
    total_findings = total_result.scalar_one()
    
    # Get findings by severity
    severity_result = await db.execute(
        select(FindingDB.severity, func.count(FindingDB.id))
        .group_by(FindingDB.severity)
    )
    severity_counts = dict(severity_result.all())
    
    # Get findings by category
    category_result = await db.execute(
        select(FindingDB.category, func.count(FindingDB.id))
        .group_by(FindingDB.category)
        .limit(10)  # Top 10 categories
    )
    category_counts = dict(category_result.all())
    
    # Get orchestrator metrics if available
    orchestrator_metrics = {}
    try:
        from ...main import app
        # Try to get orchestrator from app state (if available)
        if hasattr(app.state, 'analysis_orchestrator') and app.state.analysis_orchestrator:
            orchestrator_metrics = app.state.analysis_orchestrator.get_metrics()
    except Exception:
        pass  # Metrics not available
    
    log.debug("analysis_stats_response", total=total_findings)
    
    return {
        "total_findings": total_findings,
        "by_severity": severity_counts,
        "top_categories": category_counts,
        "orchestrator_metrics": orchestrator_metrics
    }

