"""
@fileoverview Settings API - Configuration read endpoint
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

REST API endpoint for reading system settings (read-only).
"""

from fastapi import APIRouter, Depends
from ..api.dependencies import get_current_user, require_role
from ..core.config import load_config
from ..core.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


@router.get("/")
async def get_settings(
    current_user: dict = Depends(require_role(["admin", "analyst"]))
) -> dict:
    """
    Get system settings (read-only, admin/analyst only).
    
    Args:
        current_user: Authenticated admin or analyst user
        
    Returns:
        Sanitized configuration dict (passwords removed)
    """
    log.debug("settings_get_request", user_id=current_user.get("user_id"))
    
    config = load_config()
    
    # Sanitize: remove sensitive values
    sanitized = config.copy()
    
    # Remove passwords
    if "auth" in sanitized:
        sanitized["auth"] = sanitized["auth"].copy()
        sanitized["auth"].pop("admin_password", None)
    
    if "database" in sanitized:
        # Keep path but remove sensitive connection strings if added later
        pass
    
    if "rate_limiting" in sanitized:
        # Redact Redis URL (may contain password)
        if "redis_url" in sanitized["rate_limiting"]:
            redis_url = sanitized["rate_limiting"]["redis_url"]
            if "@" in redis_url:  # Has auth
                sanitized["rate_limiting"]["redis_url"] = "redis://***:***@localhost:6379"
    
    log.debug("settings_get_response", sections=list(sanitized.keys()))
    return sanitized

