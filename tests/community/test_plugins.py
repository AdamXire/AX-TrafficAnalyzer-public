"""
Tests for Plugin System (Phase 6).
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch


class TestPluginMetadata:
    """Tests for PluginMetadata."""
    
    def test_metadata_creation(self):
        """Test creating plugin metadata."""
        from src.community.plugins.base import PluginMetadata, PluginPermission
        
        metadata = PluginMetadata(
            name="test_plugin",
            version="1.0.0",
            author="Test Author",
            publisher="Test Publisher",
            license="MIT",
            description="A test plugin",
            permissions=[PluginPermission.READ_TRAFFIC]
        )
        
        assert metadata.name == "test_plugin"
        assert metadata.version == "1.0.0"
        assert PluginPermission.READ_TRAFFIC in metadata.permissions
    
    def test_metadata_to_dict(self):
        """Test metadata to_dict conversion."""
        from src.community.plugins.base import PluginMetadata, PluginPermission
        
        metadata = PluginMetadata(
            name="test_plugin",
            version="1.0.0",
            author="Test Author",
            publisher="Test Publisher",
            license="MIT",
            description="A test plugin"
        )
        
        data = metadata.to_dict()
        
        assert data["name"] == "test_plugin"
        assert data["version"] == "1.0.0"
        assert "permissions" in data


class TestPluginBase:
    """Tests for Plugin base class."""
    
    def test_plugin_without_metadata_raises(self):
        """Test that plugin without metadata raises error."""
        from src.community.plugins.base import Plugin
        
        class BadPlugin(Plugin):
            def on_load(self): pass
            def on_request(self, flow): return None
            def on_response(self, flow): return None
            def analyze(self, data): return None
            def on_unload(self): pass
        
        with pytest.raises(ValueError, match="must define metadata"):
            BadPlugin()
    
    def test_plugin_with_metadata_works(self):
        """Test that plugin with metadata works."""
        from src.community.plugins.base import Plugin, PluginMetadata
        
        class GoodPlugin(Plugin):
            metadata = PluginMetadata(
                name="good_plugin",
                version="1.0.0",
                author="Test",
                publisher="Test",
                license="MIT",
                description="Test"
            )
            
            def on_load(self): pass
            def on_request(self, flow): return None
            def on_response(self, flow): return None
            def analyze(self, data): return None
            def on_unload(self): pass
        
        plugin = GoodPlugin()
        assert plugin.get_name() == "good_plugin"
        assert plugin.get_version() == "1.0.0"


class TestPluginManager:
    """Tests for PluginManager."""
    
    @pytest.fixture
    def temp_plugin_dir(self):
        """Create temporary plugin directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def config(self):
        """Create test config."""
        return {
            "mode": "dev",
            "plugins": {
                "enabled": True,
                "sandbox": {
                    "enabled": False,
                    "require_signature": False
                }
            }
        }
    
    def test_manager_initialization(self, temp_plugin_dir, config):
        """Test plugin manager initialization."""
        from src.community.plugins.manager import PluginManager
        
        manager = PluginManager(
            plugin_dir=temp_plugin_dir,
            config=config,
            sandbox_enabled=False
        )
        
        assert manager is not None
        assert manager.mode == "dev"
    
    def test_load_all_empty_dir(self, temp_plugin_dir, config):
        """Test loading from empty directory."""
        from src.community.plugins.manager import PluginManager
        
        manager = PluginManager(
            plugin_dir=temp_plugin_dir,
            config=config,
            sandbox_enabled=False
        )
        
        loaded = manager.load_all()
        assert loaded == 0
    
    def test_load_plugin_file(self, temp_plugin_dir, config):
        """Test loading a plugin from file."""
        from src.community.plugins.manager import PluginManager
        
        # Create a test plugin file
        plugin_code = '''
from src.community.plugins.base import Plugin, PluginMetadata

class TestPlugin(Plugin):
    metadata = PluginMetadata(
        name="test_plugin",
        version="1.0.0",
        author="Test",
        publisher="Test",
        license="MIT",
        description="Test plugin"
    )
    
    def on_load(self):
        pass
    
    def on_request(self, flow):
        return None
    
    def on_response(self, flow):
        return None
    
    def analyze(self, data):
        return None
    
    def on_unload(self):
        pass
'''
        plugin_path = Path(temp_plugin_dir) / "test_plugin.py"
        plugin_path.write_text(plugin_code)
        
        manager = PluginManager(
            plugin_dir=temp_plugin_dir,
            config=config,
            sandbox_enabled=False
        )
        
        loaded = manager.load_all()
        assert loaded == 1
        assert "test_plugin" in manager.plugins
    
    def test_trigger_on_request(self, temp_plugin_dir, config):
        """Test triggering on_request for plugins."""
        from src.community.plugins.manager import PluginManager
        from src.community.plugins.base import Plugin, PluginMetadata
        
        manager = PluginManager(
            plugin_dir=temp_plugin_dir,
            config=config,
            sandbox_enabled=False
        )
        
        # Create mock plugin
        class MockPlugin(Plugin):
            metadata = PluginMetadata(
                name="mock_plugin",
                version="1.0.0",
                author="Test",
                publisher="Test",
                license="MIT",
                description="Test"
            )
            
            def on_load(self): pass
            def on_request(self, flow):
                flow["modified"] = True
                return flow
            def on_response(self, flow): return None
            def analyze(self, data): return None
            def on_unload(self): pass
        
        plugin = MockPlugin()
        plugin.on_load()
        manager.plugins["mock_plugin"] = plugin
        manager.plugin_metadata["mock_plugin"] = plugin.metadata
        
        flow = {"url": "http://example.com"}
        result = manager.trigger_on_request(flow)
        
        assert result["modified"] is True
    
    def test_unload_plugin(self, temp_plugin_dir, config):
        """Test unloading a plugin."""
        from src.community.plugins.manager import PluginManager
        from src.community.plugins.base import Plugin, PluginMetadata
        
        manager = PluginManager(
            plugin_dir=temp_plugin_dir,
            config=config,
            sandbox_enabled=False
        )
        
        # Create mock plugin
        class MockPlugin(Plugin):
            metadata = PluginMetadata(
                name="mock_plugin",
                version="1.0.0",
                author="Test",
                publisher="Test",
                license="MIT",
                description="Test"
            )
            unloaded = False
            
            def on_load(self): pass
            def on_request(self, flow): return None
            def on_response(self, flow): return None
            def analyze(self, data): return None
            def on_unload(self):
                MockPlugin.unloaded = True
        
        plugin = MockPlugin()
        manager.plugins["mock_plugin"] = plugin
        manager.plugin_metadata["mock_plugin"] = plugin.metadata
        
        manager.unload_plugin("mock_plugin")
        
        assert "mock_plugin" not in manager.plugins
        assert MockPlugin.unloaded is True


class TestPluginExceptions:
    """Tests for plugin exceptions."""
    
    def test_plugin_error(self):
        """Test PluginError exception."""
        from src.community.plugins.exceptions import PluginError
        
        error = PluginError("Test error", plugin_name="test", details={"key": "value"})
        
        assert str(error) == "Test error"
        assert error.plugin_name == "test"
        assert error.details["key"] == "value"
    
    def test_plugin_load_error(self):
        """Test PluginLoadError exception."""
        from src.community.plugins.exceptions import PluginLoadError
        
        error = PluginLoadError("Failed to load", plugin_name="test")
        
        assert "Failed to load" in str(error)
        assert error.plugin_name == "test"
    
    def test_plugin_sandbox_error(self):
        """Test PluginSandboxError exception."""
        from src.community.plugins.exceptions import PluginSandboxError
        
        error = PluginSandboxError("Sandbox failed")
        
        assert "Sandbox failed" in str(error)


class TestPluginSandbox:
    """Tests for plugin sandbox."""
    
    def test_sandbox_config(self):
        """Test SandboxConfig dataclass."""
        from src.community.plugins.sandbox import SandboxConfig
        
        config = SandboxConfig(
            memory_mb_limit=512,
            timeout_seconds=60
        )
        
        assert config.memory_mb_limit == 512
        assert config.timeout_seconds == 60
        assert config.cpu_percent_limit == 10  # Default
    
    def test_seccomp_available_check(self):
        """Test seccomp availability check."""
        from src.community.plugins.sandbox import seccomp_available
        
        # Should return bool without raising
        result = seccomp_available()
        assert isinstance(result, bool)
    
    def test_sandbox_initialization_dev_mode(self):
        """Test sandbox initialization in dev mode."""
        from src.community.plugins.sandbox import PluginSandbox, SandboxConfig
        
        config = SandboxConfig()
        
        # Should not raise in dev mode even without seccomp
        sandbox = PluginSandbox(config, mode="dev")
        assert sandbox is not None
    
    def test_sandbox_run_simple_function(self):
        """Test running simple function in sandbox."""
        from src.community.plugins.sandbox import PluginSandbox, SandboxConfig
        
        config = SandboxConfig(timeout_seconds=5)
        sandbox = PluginSandbox(config, mode="dev")
        
        def simple_func(x, y):
            return x + y
        
        result = sandbox.run(simple_func, args=(1, 2))
        assert result == 3
    
    def test_sandbox_timeout(self):
        """Test sandbox timeout."""
        from src.community.plugins.sandbox import PluginSandbox, SandboxConfig
        from src.community.plugins.exceptions import PluginSandboxError
        import time
        
        config = SandboxConfig(timeout_seconds=1)
        sandbox = PluginSandbox(config, mode="dev")
        
        def slow_func():
            time.sleep(10)
            return "done"
        
        with pytest.raises(PluginSandboxError, match="timed out"):
            sandbox.run(slow_func)

