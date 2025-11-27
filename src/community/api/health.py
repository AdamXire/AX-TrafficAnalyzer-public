"""
@fileoverview Health check API endpoint
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

FastAPI health check endpoint with dependency injection.
"""

from fastapi import APIRouter, Depends, Request
from typing import Dict, Any
from dataclasses import dataclass
import time
from ..core.logging import get_logger
from ..api.dependencies import get_current_user

log = get_logger(__name__)

router = APIRouter(prefix="/api/health", tags=["health"])


@dataclass
class ComponentReferences:
    """Component references container."""
    hotspot: Any = None
    iptables: Any = None
    disk_monitor: Any = None
    cert_manager: Any = None
    mitmproxy: Any = None
    tcpdump: Any = None
    session_tracker: Any = None
    pcap_exporter: Any = None
    # Phase 3
    database: Any = None
    jwt_manager: Any = None
    websocket_manager: Any = None


def get_components(request: Request) -> ComponentReferences:
    """
    Dependency function to get component references from app.state.
    
    Args:
        request: FastAPI Request object (auto-injected)
        
    Returns:
        ComponentReferences with component instances
    """
    # Get components from app.state
    app = request.app
    components = getattr(app.state, "components", None)
    
    if components is None:
        # Return empty references if not set
        log.warning("components_not_initialized_in_app_state")
        return ComponentReferences()
    
    return components


@router.get("/")
async def health_check() -> Dict:
    """
    Public health check endpoint (minimal info, no auth required).
    
    Returns basic status for monitoring tools.
    
    Returns:
        Minimal health status dictionary
    """
    return {
        "status": "healthy",
        "timestamp": time.time()
        # NO component details - public endpoint
    }


@router.get("/detailed")
async def health_check_detailed(
    components: ComponentReferences = Depends(get_components),
    current_user: dict = Depends(get_current_user)
) -> Dict:
    """
    Detailed health check endpoint (requires authentication).
    
    Returns full component status with all details.
    
    Args:
        components: Component references (dependency injected)
        current_user: Authenticated user (from dependency)
        
    Returns:
        Detailed health status dictionary
    """
    start_time = time.time()
    
    status = {
        "status": "healthy",
        "timestamp": time.time(),
        "components": {}
    }
    
    # Check hotspot
    if components.hotspot:
        try:
            hotspot_status = components.hotspot.get_status()
            status["components"]["hotspot"] = {
                "status": "running" if hotspot_status["running"] else "stopped",
                "interface": hotspot_status.get("interface"),
                "ssid": hotspot_status.get("ssid"),
                "clients": hotspot_status.get("clients_connected", 0)
            }
        except Exception as e:
            status["components"]["hotspot"] = {
                "status": "error",
                "error": str(e)
            }
            status["status"] = "degraded"
            log.error("health_check_hotspot_failed", error=str(e))
    else:
        status["components"]["hotspot"] = {
            "status": "not_initialized"
        }
    
    # Check iptables
    if components.iptables:
        try:
            status["components"]["iptables"] = {
                "status": "configured" if components.iptables.rules_applied else "not_configured",
                "interface": components.iptables.interface
            }
        except Exception as e:
            status["components"]["iptables"] = {
                "status": "error",
                "error": str(e)
            }
            status["status"] = "degraded"
            log.error("health_check_iptables_failed", error=str(e))
    else:
        status["components"]["iptables"] = {
            "status": "not_initialized"
        }
    
    # Check disk space
    if components.disk_monitor:
        try:
            disk_status = components.disk_monitor.check_disk_space()
            status["components"]["disk"] = {
                "status": disk_status["status"],
                "free_gb": disk_status["free_gb"],
                "warning": disk_status.get("warning", False)
            }
            if disk_status.get("critical", False):
                status["status"] = "unhealthy"
        except Exception as e:
            status["components"]["disk"] = {
                "status": "error",
                "error": str(e)
            }
            status["status"] = "degraded"
            log.error("health_check_disk_failed", error=str(e))
    else:
        status["components"]["disk"] = {
            "status": "not_initialized"
        }
    
    # Check Phase 2b components
    if components.cert_manager:
        try:
            status["components"]["cert_manager"] = {
                "status": "initialized"
            }
        except Exception as e:
            status["components"]["cert_manager"] = {
                "status": "error",
                "error": str(e)
            }
    
    if components.mitmproxy:
        try:
            status["components"]["mitmproxy"] = {
                "status": "running" if hasattr(components.mitmproxy, "process") and components.mitmproxy.process else "stopped"
            }
        except Exception as e:
            status["components"]["mitmproxy"] = {
                "status": "error",
                "error": str(e)
            }
    
    if components.session_tracker:
        try:
            stats = components.session_tracker.get_stats()
            status["components"]["session_tracker"] = {
                "status": "running",
                "active_sessions": stats.get("active_sessions", 0)
            }
        except Exception as e:
            status["components"]["session_tracker"] = {
                "status": "error",
                "error": str(e)
            }
    
    # Check Phase 3 components
    if components.database:
        try:
            status["components"]["database"] = {
                "status": "connected" if components.database.engine else "disconnected"
            }
        except Exception as e:
            status["components"]["database"] = {
                "status": "error",
                "error": str(e)
            }
    
    if components.websocket_manager:
        try:
            status["components"]["websocket"] = {
                "status": "running",
                "connections": components.websocket_manager.get_connection_count()
            }
        except Exception as e:
            status["components"]["websocket"] = {
                "status": "error",
                "error": str(e)
            }
    
    response_time = (time.time() - start_time) * 1000  # ms
    status["response_time_ms"] = response_time
    
    if response_time > 100:
        log.warning("health_check_slow", response_time_ms=response_time)
    
    return status


@router.get("/ready")
async def readiness_check() -> Dict:
    """
    Readiness probe for Kubernetes.
    
    Returns:
        Readiness status
    """
    return {"ready": True}


@router.get("/live")
async def liveness_check() -> Dict:
    """
    Liveness probe for Kubernetes.
    
    Returns:
        Liveness status
    """
    return {"alive": True}

