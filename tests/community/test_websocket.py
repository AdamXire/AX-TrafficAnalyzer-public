"""
Tests for WebSocket Manager (Phase 3).
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import asyncio


class TestWebSocketManager:
    """Tests for WebSocketManager class."""
    
    @pytest.fixture
    def ws_manager(self):
        """Create WebSocket manager instance."""
        from src.community.api.websocket import WebSocketManager
        return WebSocketManager()
    
    def test_websocket_manager_initialization(self, ws_manager):
        """Test WebSocket manager initializes correctly."""
        assert ws_manager is not None
        assert len(ws_manager.active_connections) == 0
    
    @pytest.mark.asyncio
    async def test_connect(self, ws_manager):
        """Test client connection."""
        mock_websocket = AsyncMock()
        mock_websocket.accept = AsyncMock()
        
        await ws_manager.connect(mock_websocket)
        
        mock_websocket.accept.assert_called_once()
        assert mock_websocket in ws_manager.active_connections
    
    @pytest.mark.asyncio
    async def test_disconnect(self, ws_manager):
        """Test client disconnection."""
        mock_websocket = Mock()
        ws_manager.active_connections.append(mock_websocket)
        
        await ws_manager.disconnect(mock_websocket)
        
        assert mock_websocket not in ws_manager.active_connections
    
    @pytest.mark.asyncio
    async def test_disconnect_not_connected(self, ws_manager):
        """Test disconnecting non-connected client doesn't raise."""
        mock_websocket = Mock()
        
        # Should not raise
        await ws_manager.disconnect(mock_websocket)
    
    @pytest.mark.asyncio
    async def test_broadcast(self, ws_manager):
        """Test broadcasting message to all clients."""
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        ws_manager.active_connections = [mock_ws1, mock_ws2]
        
        message = {"type": "test", "data": "hello"}
        await ws_manager.broadcast(message)
        
        mock_ws1.send_json.assert_called_once_with(message)
        mock_ws2.send_json.assert_called_once_with(message)
    
    @pytest.mark.asyncio
    async def test_broadcast_removes_disconnected(self, ws_manager):
        """Test broadcast removes disconnected clients."""
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        mock_ws2.send_json.side_effect = Exception("Connection closed")
        ws_manager.active_connections = [mock_ws1, mock_ws2]
        
        await ws_manager.broadcast({"type": "test"})
        
        # mock_ws2 should be removed after error
        assert mock_ws2 not in ws_manager.active_connections
        assert mock_ws1 in ws_manager.active_connections
    
    @pytest.mark.asyncio
    async def test_send_personal_message(self, ws_manager):
        """Test sending message to specific client."""
        mock_websocket = AsyncMock()
        
        message = {"type": "test", "data": "hello"}
        await ws_manager.send_personal_message(message, mock_websocket)
        
        mock_websocket.send_json.assert_called_once_with(message)
    
    def test_get_connection_count(self, ws_manager):
        """Test getting connection count."""
        ws_manager.active_connections = [Mock(), Mock(), Mock()]
        
        count = ws_manager.get_connection_count()
        
        assert count == 3


class TestWebSocketEvents:
    """Tests for WebSocket event types."""
    
    def test_flow_event_structure(self):
        """Test flow event has correct structure."""
        event = {
            "type": "http_flow",
            "data": {
                "flow_id": "flow-123",
                "session_id": "session-456",
                "method": "GET",
                "url": "https://example.com",
                "status_code": 200
            }
        }
        
        assert event["type"] == "http_flow"
        assert "flow_id" in event["data"]
        assert "method" in event["data"]
    
    def test_client_connected_event_structure(self):
        """Test client connected event has correct structure."""
        event = {
            "type": "client_connected",
            "data": {
                "mac": "aa:bb:cc:dd:ee:ff",
                "ip": "192.168.4.100",
                "hostname": "iPhone-12"
            }
        }
        
        assert event["type"] == "client_connected"
        assert "mac" in event["data"]
        assert "ip" in event["data"]
    
    def test_finding_event_structure(self):
        """Test finding event has correct structure."""
        event = {
            "type": "finding",
            "data": {
                "id": "finding-123",
                "severity": "high",
                "title": "SQL Injection vulnerability",
                "url": "https://vulnerable.com/api"
            }
        }
        
        assert event["type"] == "finding"
        assert "severity" in event["data"]
        assert "title" in event["data"]

