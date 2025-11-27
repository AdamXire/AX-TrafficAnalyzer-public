"""
Tests for API Endpoints (Phase 3).
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from datetime import datetime


class TestHealthEndpoints:
    """Tests for health check endpoints."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        from src.community.api.health import router
        from fastapi import FastAPI
        
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)
    
    def test_health_check_basic(self, client):
        """Test basic health check endpoint."""
        response = client.get("/api/health/")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
    
    def test_readiness_check(self, client):
        """Test readiness check endpoint."""
        response = client.get("/api/health/ready")
        
        assert response.status_code == 200
        data = response.json()
        assert "ready" in data
    
    def test_liveness_check(self, client):
        """Test liveness check endpoint."""
        response = client.get("/api/health/live")
        
        assert response.status_code == 200
        data = response.json()
        assert "alive" in data


class TestAuthEndpoints:
    """Tests for authentication endpoints."""
    
    @pytest.fixture
    def mock_db_manager(self):
        """Create mock database manager."""
        db = Mock()
        
        # Mock async session context manager
        session_mock = AsyncMock()
        session_mock.__aenter__ = AsyncMock(return_value=session_mock)
        session_mock.__aexit__ = AsyncMock(return_value=None)
        session_mock.execute = AsyncMock()
        
        db.get_session = MagicMock(return_value=session_mock)
        return db
    
    @pytest.fixture
    def mock_jwt_manager(self):
        """Create mock JWT manager."""
        jwt_mgr = Mock()
        jwt_mgr.create_token = Mock(return_value="test-token-123")
        jwt_mgr.verify_token = Mock(return_value={"sub": "user-123", "role": "admin"})
        return jwt_mgr
    
    def test_login_request_structure(self):
        """Test login request structure."""
        from src.community.api.auth import LoginRequest
        
        request = LoginRequest(username="admin", password="password123")
        
        assert request.username == "admin"
        assert request.password == "password123"
    
    def test_login_response_structure(self):
        """Test login response structure."""
        from src.community.api.auth import LoginResponse
        
        response = LoginResponse(
            access_token="token123",
            token_type="bearer",
            user_id="user-123",
            role="admin"
        )
        
        assert response.access_token == "token123"
        assert response.token_type == "bearer"
        assert response.user_id == "user-123"


class TestSessionsEndpoints:
    """Tests for sessions API endpoints."""
    
    def test_session_response_structure(self):
        """Test session response structure."""
        session_data = {
            "session_id": "session-123",
            "client_ip": "192.168.1.100",
            "user_agent": "TestAgent",
            "start_time": datetime.utcnow().isoformat(),
            "flow_count": 10,
            "bytes_transferred": 5000
        }
        
        assert "session_id" in session_data
        assert "client_ip" in session_data
        assert "flow_count" in session_data


class TestFlowsEndpoints:
    """Tests for flows API endpoints."""
    
    def test_flow_response_structure(self):
        """Test flow response structure."""
        flow_data = {
            "flow_id": "flow-123",
            "session_id": "session-456",
            "method": "GET",
            "url": "https://example.com/api",
            "status_code": 200,
            "request_size": 100,
            "response_size": 500,
            "duration_ms": 50
        }
        
        assert "flow_id" in flow_data
        assert "method" in flow_data
        assert "status_code" in flow_data


class TestAnalysisEndpoints:
    """Tests for analysis API endpoints."""
    
    def test_finding_response_structure(self):
        """Test finding response structure."""
        finding_data = {
            "id": "finding-123",
            "session_id": "session-456",
            "severity": "high",
            "category": "security",
            "title": "Missing Security Header",
            "description": "HSTS header is missing",
            "recommendation": "Add Strict-Transport-Security header"
        }
        
        assert "id" in finding_data
        assert "severity" in finding_data
        assert finding_data["severity"] in ["critical", "high", "medium", "low", "info"]
    
    def test_analysis_stats_structure(self):
        """Test analysis stats response structure."""
        stats = {
            "flows_analyzed": 100,
            "findings_generated": 25,
            "by_severity": {
                "critical": 2,
                "high": 5,
                "medium": 10,
                "low": 8
            },
            "by_category": {
                "security_headers": 10,
                "cookies": 5,
                "authentication": 3
            }
        }
        
        assert "flows_analyzed" in stats
        assert "findings_generated" in stats
        assert "by_severity" in stats


class TestPaginatedResponse:
    """Tests for paginated response structure."""
    
    def test_paginated_response_structure(self):
        """Test paginated response has correct structure."""
        from src.community.api.schemas import PaginatedResponse
        
        response = PaginatedResponse(
            items=[{"id": "1"}, {"id": "2"}],
            total=100,
            limit=10,
            offset=0,
            has_more=True
        )
        
        assert len(response.items) == 2
        assert response.total == 100
        assert response.has_more is True
    
    def test_paginated_response_last_page(self):
        """Test paginated response on last page."""
        from src.community.api.schemas import PaginatedResponse
        
        response = PaginatedResponse(
            items=[{"id": "99"}, {"id": "100"}],
            total=100,
            limit=10,
            offset=90,
            has_more=False
        )
        
        assert response.has_more is False

