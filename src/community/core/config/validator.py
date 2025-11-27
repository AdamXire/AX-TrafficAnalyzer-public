"""
@fileoverview Configuration Validation
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Configuration validation.
"""

import jsonschema
from pathlib import Path
from ..errors import ConfigurationError
from .schema import ConfigSchema


def validate_config(config: dict) -> None:
    """
    Validate configuration against schema.
    
    Raises:
        ConfigurationError: If validation fails
    """
    schema = ConfigSchema.get_schema()
    
    try:
        jsonschema.validate(config, schema)
    except jsonschema.ValidationError as e:
        raise ConfigurationError(
            f"Configuration validation failed: {e.message}",
            None
        )
    
    # Additional validations
    _validate_password_strength(config.get("hotspot", {}).get("password", ""))
    _validate_paths_writable(config)


def _validate_password_strength(password: str) -> None:
    """Validate WPA2 password requirements."""
    if len(password) < 8:
        raise ConfigurationError(
            "WiFi password must be at least 8 characters (WPA2 requirement)",
            None
        )


def _validate_paths_writable(config: dict) -> None:
    """Validate all configured paths are writable."""
    # Add path validation here
    pass

