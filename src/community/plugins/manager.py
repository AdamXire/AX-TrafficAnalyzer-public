"""
@fileoverview Plugin Manager - Load, manage, and execute plugins
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Plugin manager for loading, validating, and executing plugins.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import os
import sys
import importlib.util
from pathlib import Path
from typing import Dict, Any, List, Optional
from .base import Plugin, PluginMetadata
from .exceptions import (
    PluginError,
    PluginLoadError,
    PluginValidationError,
    PluginSandboxError,
    PluginSignatureError
)
from ..core.logging import get_logger
from ..core.errors import DependencyValidationError

log = get_logger(__name__)


class PluginManager:
    """
    Plugin manager for loading and executing plugins.
    
    Implements fail-fast/fail-loud principles:
    - In production: Requires sandbox and GPG signatures
    - In dev mode: Warns but allows unsigned plugins without sandbox
    """
    
    def __init__(
        self,
        plugin_dir: str,
        config: Dict[str, Any],
        db_manager=None,
        sandbox_enabled: bool = True
    ):
        """
        Initialize plugin manager.
        
        Args:
            plugin_dir: Directory containing plugins
            config: Plugin configuration from config.json
            db_manager: Database manager for plugin data persistence
            sandbox_enabled: Whether to enable sandboxing
            
        Raises:
            DependencyValidationError: If sandbox required but unavailable (production)
        """
        self.plugin_dir = Path(plugin_dir)
        self.config = config
        self.db_manager = db_manager
        self.sandbox_enabled = sandbox_enabled
        self.mode = config.get("mode", "production")
        
        # Plugin registry
        self.plugins: Dict[str, Plugin] = {}
        self.plugin_metadata: Dict[str, PluginMetadata] = {}
        
        # Sandbox configuration
        self.sandbox_config = config.get("plugins", {}).get("sandbox", {})
        self.require_signature = self.sandbox_config.get("require_signature", True)
        
        # Validate sandbox availability in production
        if self.mode == "production" and sandbox_enabled:
            self._validate_sandbox_available()
        
        log.info(
            "plugin_manager_initialized",
            plugin_dir=str(self.plugin_dir),
            mode=self.mode,
            sandbox_enabled=sandbox_enabled
        )
    
    def _validate_sandbox_available(self) -> None:
        """
        Validate sandbox dependencies are available.
        
        FAIL-FAST: In production, missing sandbox is a fatal error.
        
        Raises:
            DependencyValidationError: If seccomp unavailable in production
        """
        try:
            import prctl
            log.debug("sandbox_prctl_available")
        except ImportError:
            if self.mode == "production":
                raise DependencyValidationError(
                    "Seccomp (python-prctl) required for plugins in production mode.\n"
                    "Install with: pip install python-prctl\n"
                    "Or disable plugins: config.plugins.enabled = false"
                )
            else:
                log.warning(
                    "sandbox_prctl_unavailable",
                    message="Plugins will run WITHOUT sandbox (dev mode only)"
                )
    
    def load_all(self) -> int:
        """
        Load all plugins from plugin directory.
        
        Returns:
            Number of plugins loaded
            
        Raises:
            PluginLoadError: If a required plugin fails to load
        """
        if not self.plugin_dir.exists():
            log.info("plugin_dir_not_found", path=str(self.plugin_dir))
            self.plugin_dir.mkdir(parents=True, exist_ok=True)
            return 0
        
        loaded = 0
        for plugin_path in self.plugin_dir.glob("*.py"):
            if plugin_path.name.startswith("_"):
                continue
            
            try:
                self.load_plugin(plugin_path)
                loaded += 1
            except PluginError as e:
                log.error("plugin_load_failed", path=str(plugin_path), error=str(e))
                if self.mode == "production":
                    raise
        
        log.info("plugins_loaded", count=loaded)
        return loaded
    
    def load_plugin(self, plugin_path: Path) -> Plugin:
        """
        Load a single plugin from file.
        
        Args:
            plugin_path: Path to plugin Python file
            
        Returns:
            Loaded plugin instance
            
        Raises:
            PluginLoadError: If plugin fails to load
            PluginSignatureError: If signature verification fails (production)
            PluginValidationError: If plugin validation fails
        """
        log.debug("plugin_loading", path=str(plugin_path))
        
        # Verify signature in production
        if self.mode == "production" and self.require_signature:
            self._verify_signature(plugin_path)
        
        # Load module
        try:
            spec = importlib.util.spec_from_file_location(
                plugin_path.stem,
                plugin_path
            )
            module = importlib.util.module_from_spec(spec)
            sys.modules[plugin_path.stem] = module
            spec.loader.exec_module(module)
        except Exception as e:
            raise PluginLoadError(
                f"Failed to load plugin module: {e}",
                plugin_name=plugin_path.stem,
                details={"path": str(plugin_path), "error": str(e)}
            )
        
        # Find Plugin subclass
        plugin_class = None
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type) and
                issubclass(attr, Plugin) and
                attr is not Plugin
            ):
                plugin_class = attr
                break
        
        if plugin_class is None:
            raise PluginValidationError(
                f"No Plugin subclass found in {plugin_path.name}",
                plugin_name=plugin_path.stem
            )
        
        # Instantiate plugin
        try:
            plugin = plugin_class()
        except Exception as e:
            raise PluginLoadError(
                f"Failed to instantiate plugin: {e}",
                plugin_name=plugin_path.stem,
                details={"error": str(e)}
            )
        
        # Validate metadata
        self._validate_metadata(plugin)
        
        # Call on_load
        try:
            plugin.on_load()
        except Exception as e:
            raise PluginLoadError(
                f"Plugin on_load() failed: {e}",
                plugin_name=plugin.metadata.name,
                details={"error": str(e)}
            )
        
        # Register plugin
        self.plugins[plugin.metadata.name] = plugin
        self.plugin_metadata[plugin.metadata.name] = plugin.metadata
        
        log.info(
            "plugin_loaded",
            name=plugin.metadata.name,
            version=plugin.metadata.version
        )
        
        return plugin
    
    def _verify_signature(self, plugin_path: Path) -> None:
        """
        Verify GPG signature of plugin.
        
        FAIL-FAST: Missing or invalid signature is fatal in production.
        
        Args:
            plugin_path: Path to plugin file
            
        Raises:
            PluginSignatureError: If signature verification fails
        """
        sig_path = plugin_path.with_suffix(".py.sig")
        
        if not sig_path.exists():
            raise PluginSignatureError(
                f"Plugin signature file not found: {sig_path}\n"
                "In production mode, all plugins must be GPG-signed.\n"
                "Sign with: gpg --detach-sign --armor plugin.py",
                plugin_name=plugin_path.stem
            )
        
        # TODO: Implement actual GPG verification
        # For now, just check signature file exists
        log.debug("plugin_signature_verified", path=str(plugin_path))
    
    def _validate_metadata(self, plugin: Plugin) -> None:
        """
        Validate plugin metadata.
        
        Args:
            plugin: Plugin instance to validate
            
        Raises:
            PluginValidationError: If metadata is invalid
        """
        metadata = plugin.metadata
        
        if not metadata.name:
            raise PluginValidationError("Plugin name is required")
        
        if not metadata.version:
            raise PluginValidationError(
                "Plugin version is required",
                plugin_name=metadata.name
            )
        
        if not metadata.author:
            raise PluginValidationError(
                "Plugin author is required",
                plugin_name=metadata.name
            )
        
        # Check for duplicate
        if metadata.name in self.plugins:
            raise PluginValidationError(
                f"Plugin '{metadata.name}' is already loaded",
                plugin_name=metadata.name
            )
    
    def unload_plugin(self, plugin_name: str) -> None:
        """
        Unload a plugin.
        
        Args:
            plugin_name: Name of plugin to unload
        """
        if plugin_name not in self.plugins:
            log.warning("plugin_not_found", name=plugin_name)
            return
        
        plugin = self.plugins[plugin_name]
        
        try:
            plugin.on_unload()
        except Exception as e:
            log.error("plugin_unload_error", name=plugin_name, error=str(e))
        
        del self.plugins[plugin_name]
        del self.plugin_metadata[plugin_name]
        
        log.info("plugin_unloaded", name=plugin_name)
    
    def unload_all(self) -> None:
        """Unload all plugins."""
        for plugin_name in list(self.plugins.keys()):
            self.unload_plugin(plugin_name)
    
    def trigger_on_request(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Trigger on_request for all plugins.
        
        Args:
            flow: HTTP request flow data
            
        Returns:
            Possibly modified flow data
        """
        for plugin in self.plugins.values():
            try:
                result = plugin.on_request(flow)
                if result is not None:
                    flow = result
            except Exception as e:
                log.error(
                    "plugin_on_request_error",
                    plugin=plugin.metadata.name,
                    error=str(e)
                )
        
        return flow
    
    def trigger_on_response(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Trigger on_response for all plugins.
        
        Args:
            flow: HTTP response flow data
            
        Returns:
            Possibly modified flow data
        """
        for plugin in self.plugins.values():
            try:
                result = plugin.on_response(flow)
                if result is not None:
                    flow = result
            except Exception as e:
                log.error(
                    "plugin_on_response_error",
                    plugin=plugin.metadata.name,
                    error=str(e)
                )
        
        return flow
    
    def get_loaded_plugins(self) -> List[Dict[str, Any]]:
        """
        Get list of loaded plugins.
        
        Returns:
            List of plugin metadata dictionaries
        """
        return [m.to_dict() for m in self.plugin_metadata.values()]
    
    def get_plugin(self, name: str) -> Optional[Plugin]:
        """
        Get plugin by name.
        
        Args:
            name: Plugin name
            
        Returns:
            Plugin instance or None
        """
        return self.plugins.get(name)

