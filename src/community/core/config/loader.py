"""
@fileoverview Configuration Loader
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Configuration loader.
"""

import json
from pathlib import Path
from typing import Optional
from ..errors import ConfigurationError
from .validator import validate_config


_config_instance: Optional[dict] = None


def load_config(config_path: str = "config/config.json") -> dict:
    """
    Load and validate configuration.
    
    Args:
        config_path: Path to config file
        
    Returns:
        Validated configuration dict
        
    Raises:
        ConfigurationError: If config invalid or missing
    """
    global _config_instance
    
    path = Path(config_path)
    
    if not path.exists():
        raise ConfigurationError(
            f"Configuration file not found: {config_path}",
            None
        )
    
    try:
        with open(path, "r") as f:
            config = json.load(f)
    except json.JSONDecodeError as e:
        raise ConfigurationError(
            f"Invalid JSON in config file: {e}",
            None
        )
    
    validate_config(config)
    _config_instance = config
    return config


def get_config() -> dict:
    """Get loaded configuration (singleton)."""
    if _config_instance is None:
        raise ConfigurationError(
            "Configuration not loaded. Call load_config() first.",
            None
        )
    return _config_instance

