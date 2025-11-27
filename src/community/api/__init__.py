"""
@fileoverview API Module Package
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

API endpoints module.
"""

from .health import router as health_router
from .auth import router as auth_router
from .sessions import router as sessions_router
from .flows import router as flows_router
from .devices import router as devices_router
from .settings import router as settings_router
from .analysis import router as analysis_router  # Phase 5
from .websocket import ws_manager

__all__ = [
    "health_router",
    "auth_router",
    "sessions_router",
    "flows_router",
    "devices_router",
    "settings_router",
    "analysis_router",  # Phase 5
    "ws_manager"
]


