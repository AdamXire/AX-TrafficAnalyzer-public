"""
@fileoverview WebSocket Server - Real-time traffic streaming
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

WebSocket server for real-time traffic streaming.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import List, Dict, Any
from fastapi import WebSocket, WebSocketDisconnect
from ..core.logging import get_logger

log = get_logger(__name__)


class WebSocketManager:
    """
    WebSocket connection manager for real-time traffic streaming.
    
    Manages active WebSocket connections and broadcasts traffic events.
    """
    
    def __init__(self):
        """Initialize WebSocket manager."""
        self.active_connections: List[WebSocket] = []
        log.debug("websocket_manager_initialized")
    
    async def connect(self, websocket: WebSocket) -> None:
        """
        Accept and register new WebSocket connection.
        
        Args:
            websocket: WebSocket connection
        """
        await websocket.accept()
        self.active_connections.append(websocket)
        log.info("websocket_connected", total_connections=len(self.active_connections))
    
    async def disconnect(self, websocket: WebSocket) -> None:
        """
        Remove WebSocket connection.
        
        Args:
            websocket: WebSocket connection to remove
        """
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            log.info("websocket_disconnected", total_connections=len(self.active_connections))
    
    async def broadcast(self, message: Dict[str, Any]) -> None:
        """
        Broadcast message to all connected clients.
        
        Args:
            message: Message dictionary to broadcast
        """
        if not self.active_connections:
            return
        
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                log.warning("websocket_broadcast_failed", error=str(e))
                disconnected.append(connection)
        
        # Remove disconnected clients
        for conn in disconnected:
            await self.disconnect(conn)
        
        if disconnected:
            log.debug("websocket_clients_removed", count=len(disconnected))
    
    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket) -> None:
        """
        Send message to specific WebSocket connection.
        
        Args:
            message: Message dictionary
            websocket: Target WebSocket connection
        """
        try:
            await websocket.send_json(message)
        except Exception as e:
            log.warning("websocket_personal_message_failed", error=str(e))
            await self.disconnect(websocket)
    
    def get_connection_count(self) -> int:
        """Get number of active connections."""
        return len(self.active_connections)


# Global WebSocket manager instance
ws_manager = WebSocketManager()


async def websocket_endpoint(
    websocket: WebSocket,
    token: str = None
):
    """
    WebSocket endpoint for traffic streaming with JWT authentication.
    
    Args:
        websocket: WebSocket connection
        token: JWT token (from query parameter or header)
    """
    # Get token from query params or headers
    if not token:
        token = websocket.query_params.get("token")
    
    if not token:
        await websocket.close(code=1008, reason="Missing authentication token")
        log.warning("websocket_rejected_no_token")
        return
    
    # Validate JWT token
    try:
        from ..api.dependencies import get_jwt_manager
        from fastapi import Request
        
        # Get JWT manager from app state
        # Note: This is a workaround - in production, inject via dependency
        jwt_manager = None
        if hasattr(websocket.app, "state") and hasattr(websocket.app.state, "jwt_manager"):
            jwt_manager = websocket.app.state.jwt_manager
        
        if not jwt_manager:
            await websocket.close(code=1008, reason="JWT manager not available")
            log.error("websocket_rejected_no_jwt_manager")
            return
        
        payload = jwt_manager.verify_token(token)
        log.debug("websocket_auth_success", user_id=payload.get("user_id"), role=payload.get("role"))
    except Exception as e:
        await websocket.close(code=1008, reason="Invalid token")
        log.warning("websocket_rejected_invalid_token", error=str(e))
        return
    
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive by receiving messages
            data = await websocket.receive_text()
            log.debug("websocket_message_received", message=data[:100])  # Log first 100 chars
            # Echo back for ping/pong
            await websocket.send_json({"type": "pong", "message": data})
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
        log.info("websocket_client_disconnected")
    except Exception as e:
        log.error("websocket_error", error=str(e), error_type=type(e).__name__)
        await ws_manager.disconnect(websocket)

