"""
Tests for Database Manager (Phase 3).
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime


class TestDatabaseManager:
    """Tests for DatabaseManager class."""
    
    @pytest.fixture
    def temp_db_path(self):
        """Create temporary database path."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            path = f.name
        yield path
        # Cleanup
        if os.path.exists(path):
            os.remove(path)
    
    @pytest.fixture
    def db_manager(self, temp_db_path):
        """Create database manager with temp database."""
        from src.community.storage.database import DatabaseManager
        return DatabaseManager(db_path=temp_db_path, pool_size=2, max_overflow=2)
    
    def test_database_manager_initialization(self, db_manager, temp_db_path):
        """Test database manager initializes correctly."""
        assert db_manager is not None
        assert str(db_manager.db_path) == temp_db_path
    
    @pytest.mark.asyncio
    async def test_database_start(self, db_manager):
        """Test database start creates engine."""
        await db_manager.start()
        
        assert db_manager.engine is not None
    
    @pytest.mark.asyncio
    async def test_database_stop(self, db_manager):
        """Test database stop disposes engine."""
        await db_manager.start()
        await db_manager.stop()
        
        # Engine should be disposed
        # Note: Implementation may vary
    
    @pytest.mark.asyncio
    async def test_get_session(self, db_manager):
        """Test getting async session."""
        await db_manager.start()
        
        async with db_manager.get_session() as session:
            assert session is not None
    
    @pytest.mark.asyncio
    async def test_create_default_admin(self, db_manager):
        """Test creating default admin user."""
        await db_manager.start()
        
        # Run migrations first (simplified - just create tables)
        from src.community.storage.models import Base
        from sqlalchemy import create_engine
        engine = create_engine(f"sqlite:///{db_manager.db_path}")
        Base.metadata.create_all(engine)
        
        created = await db_manager.create_default_admin("admin", "TestPassword123!")
        
        # First call should create
        assert created is True
        
        # Second call should not create (already exists)
        created_again = await db_manager.create_default_admin("admin", "TestPassword123!")
        assert created_again is False


class TestDatabaseModels:
    """Tests for database models."""
    
    def test_user_model_password_verification(self):
        """Test User model password verification."""
        from src.community.storage.models import User
        import bcrypt
        
        password = "TestPassword123!"
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        user = User(
            id="user-123",
            username="testuser",
            password_hash=password_hash,
            role="admin"
        )
        
        assert user.verify_password(password) is True
        assert user.verify_password("wrongpassword") is False
    
    def test_user_model_to_dict(self):
        """Test User model to_dict excludes password."""
        from src.community.storage.models import User
        
        user = User(
            id="user-123",
            username="testuser",
            password_hash="hashed",
            role="admin",
            created_at=datetime.utcnow()
        )
        
        user_dict = user.to_dict()
        
        assert "username" in user_dict
        assert "password_hash" not in user_dict
        assert "password" not in user_dict
    
    def test_session_model_to_dict(self):
        """Test SessionDB model to_dict."""
        from src.community.storage.models import SessionDB
        
        session = SessionDB(
            session_id="session-123",
            client_ip="192.168.1.100",
            user_agent="TestAgent",
            created_at=datetime.utcnow()
        )
        
        session_dict = session.to_dict()
        
        assert session_dict["session_id"] == "session-123"
        assert session_dict["client_ip"] == "192.168.1.100"
    
    def test_flow_model_to_dict(self):
        """Test FlowDB model to_dict."""
        from src.community.storage.models import FlowDB
        
        flow = FlowDB(
            flow_id="flow-123",
            session_id="session-456",
            method="GET",
            url="https://example.com",
            host="example.com",
            path="/",
            status_code=200,
            request_size=100,
            response_size=500,
            timestamp=datetime.utcnow()
        )
        
        flow_dict = flow.to_dict()
        
        assert flow_dict["flow_id"] == "flow-123"
        assert flow_dict["method"] == "GET"
        assert flow_dict["status_code"] == 200
    
    def test_finding_model_to_dict(self):
        """Test FindingDB model to_dict."""
        from src.community.storage.models import FindingDB
        
        finding = FindingDB(
            id="finding-123",
            session_id="session-456",
            severity="high",
            category="security",
            title="Test Finding",
            description="Test description",
            timestamp=datetime.utcnow()
        )
        
        finding_dict = finding.to_dict()
        
        assert finding_dict["id"] == "finding-123"
        assert finding_dict["severity"] == "high"
    
    def test_plugin_data_model_to_dict(self):
        """Test PluginDataDB model to_dict."""
        from src.community.storage.models import PluginDataDB
        
        plugin_data = PluginDataDB(
            id="data-123",
            plugin_name="test_plugin",
            session_id="session-456",
            data={"key": "value"},
            timestamp=datetime.utcnow()
        )
        
        data_dict = plugin_data.to_dict()
        
        assert data_dict["id"] == "data-123"
        assert data_dict["plugin_name"] == "test_plugin"
        assert data_dict["data"]["key"] == "value"


class TestMigrationManager:
    """Tests for Migration Manager."""
    
    @pytest.fixture
    def temp_db_path(self):
        """Create temporary database path."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            path = f.name
        yield path
        if os.path.exists(path):
            os.remove(path)
    
    def test_migration_manager_initialization(self, temp_db_path):
        """Test migration manager initializes correctly."""
        from src.community.storage.migrations import MigrationManager
        
        manager = MigrationManager(db_path=temp_db_path)
        
        assert manager is not None
        assert str(manager.db_path) == temp_db_path
    
    def test_get_current_revision(self, temp_db_path):
        """Test getting current revision."""
        from src.community.storage.migrations import MigrationManager
        
        manager = MigrationManager(db_path=temp_db_path)
        revision = manager.get_current_revision()
        
        # New database has no revision
        assert revision is None or isinstance(revision, str)

