"""
@fileoverview Abstract base class for WiFi hotspot implementations
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Abstract base class for platform-specific hotspot implementations.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class ClientInfo:
    """Information about a connected client."""
    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    connected_at: Optional[float] = None
    bytes_sent: int = 0
    bytes_received: int = 0


class HotspotBase(ABC):
    """Abstract base class for hotspot implementations."""
    
    @abstractmethod
    def start(self) -> None:
        """Start the WiFi hotspot."""
        raise NotImplementedError
    
    @abstractmethod
    def stop(self) -> None:
        """Stop the WiFi hotspot."""
        raise NotImplementedError
    
    @abstractmethod
    def restart(self) -> None:
        """Restart the WiFi hotspot."""
        raise NotImplementedError
    
    @abstractmethod
    def is_running(self) -> bool:
        """Check if hotspot is running."""
        raise NotImplementedError
    
    @abstractmethod
    def get_clients(self) -> List[ClientInfo]:
        """Get list of connected clients."""
        raise NotImplementedError
    
    @abstractmethod
    def get_status(self) -> Dict:
        """Get hotspot status information."""
        raise NotImplementedError

