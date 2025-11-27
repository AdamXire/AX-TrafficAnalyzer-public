"""
@fileoverview Plugin Base - Abstract base class for all plugins
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Abstract base class that all plugins must inherit from.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from ..core.logging import get_logger

log = get_logger(__name__)


class PluginPermission(str, Enum):
    """Permissions that plugins can request."""
    READ_TRAFFIC = "read_traffic"      # Read HTTP flows
    WRITE_DB = "write_db"              # Write to database
    NETWORK_ACCESS = "network_access"  # Make outbound requests
    FILE_READ = "file_read"            # Read files
    FILE_WRITE = "file_write"          # Write files
    EXECUTE = "execute"                # Execute external commands


@dataclass
class PluginMetadata:
    """
    Plugin metadata describing the plugin.
    
    Required fields must be provided in plugin manifest.
    """
    name: str
    version: str
    author: str
    publisher: str
    license: str
    description: str
    requires_license: bool = False
    permissions: List[PluginPermission] = field(default_factory=list)
    min_api_version: str = "1.0.0"
    max_api_version: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "publisher": self.publisher,
            "license": self.license,
            "description": self.description,
            "requires_license": self.requires_license,
            "permissions": [p.value for p in self.permissions],
            "min_api_version": self.min_api_version,
            "max_api_version": self.max_api_version
        }


class Plugin(ABC):
    """
    Abstract base class for all plugins.
    
    Plugins must implement all abstract methods and provide metadata.
    
    Lifecycle:
    1. on_load() - Called when plugin is loaded
    2. on_request() / on_response() - Called for each HTTP flow
    3. analyze() - Called for custom analysis
    4. on_unload() - Called when plugin is unloaded
    """
    
    # Plugin metadata - must be set by subclass
    metadata: PluginMetadata = None
    
    def __init__(self):
        """Initialize plugin."""
        if self.metadata is None:
            raise ValueError(f"Plugin {self.__class__.__name__} must define metadata")
        log.debug("plugin_instance_created", name=self.metadata.name)
    
    @abstractmethod
    def on_load(self) -> None:
        """
        Called when plugin is loaded.
        
        Use this to initialize resources, connections, etc.
        
        Raises:
            PluginLoadError: If initialization fails
        """
        pass
    
    @abstractmethod
    def on_request(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Called for each HTTP request.
        
        Args:
            flow: HTTP flow data dictionary containing:
                - flow_id: Unique flow identifier
                - method: HTTP method (GET, POST, etc.)
                - url: Full URL
                - headers: Request headers
                - body: Request body (if any)
                
        Returns:
            Optional modified flow data, or None to pass through unchanged
        """
        pass
    
    @abstractmethod
    def on_response(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Called for each HTTP response.
        
        Args:
            flow: HTTP flow data dictionary containing:
                - flow_id: Unique flow identifier
                - status_code: HTTP status code
                - headers: Response headers
                - body: Response body (if any)
                
        Returns:
            Optional modified flow data, or None to pass through unchanged
        """
        pass
    
    @abstractmethod
    def analyze(self, data: bytes) -> Any:
        """
        Perform custom analysis on data.
        
        Args:
            data: Raw data bytes to analyze
            
        Returns:
            Analysis result (plugin-specific format)
        """
        pass
    
    @abstractmethod
    def on_unload(self) -> None:
        """
        Called when plugin is unloaded.
        
        Use this to cleanup resources, close connections, etc.
        """
        pass
    
    def get_name(self) -> str:
        """Get plugin name."""
        return self.metadata.name
    
    def get_version(self) -> str:
        """Get plugin version."""
        return self.metadata.version
    
    def get_permissions(self) -> List[PluginPermission]:
        """Get requested permissions."""
        return self.metadata.permissions

