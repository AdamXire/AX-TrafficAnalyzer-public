"""
@fileoverview Configuration Schema Definition
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Configuration schema definition.
"""

CONFIG_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["hotspot", "capture", "storage", "api"],
    "properties": {
        "hotspot": {
            "type": "object",
            "required": ["interface", "ssid", "password"],
            "properties": {
                "interface": {"type": "string", "minLength": 1},
                "ssid": {"type": "string", "minLength": 1, "maxLength": 32},
                "password": {"type": "string", "minLength": 8},
                "channel": {"type": ["integer", "string"]},
                "ip_range": {"type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+$"},
                "gateway": {"type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+\\.\\d+$"},
                "dhcp_range": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+\\.\\d+$"},
                        "end": {"type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+\\.\\d+$"}
                    }
                },
                "dns": {
                    "type": "object",
                    "properties": {
                        "primary": {"type": "string"},
                        "secondary": {"type": "string"}
                    }
                },
                "max_clients": {"type": "integer", "minimum": 1, "maximum": 100},
                "hide_ssid": {"type": "boolean"},
                "encryption": {"type": "string", "enum": ["WPA2-PSK"]}
            }
        },
        "capture": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "mitmproxy": {
                    "type": "object",
                    "properties": {
                        "port": {"type": "integer", "minimum": 1024, "maximum": 65535},
                        "mode": {"type": "string", "enum": ["transparent"]}
                    }
                },
                "tcpdump": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "filter": {"type": "string"}
                    }
                },
                "pcap": {
                    "type": "object",
                    "properties": {
                        "buffer_size_mb": {"type": "integer", "minimum": 1, "maximum": 100},
                        "output_dir": {"type": "string"}
                    }
                },
                "session": {
                    "type": "object",
                    "properties": {
                        "timeout_seconds": {"type": "integer", "minimum": 60, "maximum": 86400}
                    }
                }
            }
        },
        "storage": {"type": "object"},
        "api": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer", "minimum": 1024, "maximum": 65535},
                "use_ssl": {"type": "boolean"},
                "ssl_keyfile": {"type": "string"},
                "ssl_certfile": {"type": "string"}
            }
        },
        "database": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "path": {"type": "string"},
                "pool_size": {"type": "integer", "minimum": 1, "maximum": 50},
                "max_overflow": {"type": "integer", "minimum": 0, "maximum": 100},
                "isolation_level": {"type": "string", "enum": ["READ_UNCOMMITTED", "READ_COMMITTED", "REPEATABLE_READ", "SERIALIZABLE"]},
                "echo": {"type": "boolean"}
            },
            "required": ["enabled", "path"]
        },
        "auth": {
            "type": "object",
            "properties": {
                "admin_username": {"type": "string", "minLength": 3},
                "admin_password": {"type": "string", "minLength": 8},
                "token_expiry_hours": {"type": "integer", "minimum": 1, "maximum": 168},
                "jwt_algorithm": {"type": "string", "enum": ["HS256", "HS384", "HS512"]}
            },
            "required": ["token_expiry_hours"]
        },
        "rate_limiting": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "redis_url": {"type": "string"},
                "login_max_attempts": {"type": "integer", "minimum": 1, "maximum": 100},
                "login_window_seconds": {"type": "integer", "minimum": 60, "maximum": 3600}
            },
            "required": ["enabled"]
        },
        "ui": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "dev_server_port": {"type": "integer", "minimum": 1024, "maximum": 65535},
                "build_on_startup": {"type": "boolean"},
                "theme": {"type": "string", "enum": ["light", "dark", "auto"]},
                "auto_reload": {"type": "boolean"}
            },
            "required": ["enabled"]
        },
        "mode": {
            "type": "string",
            "enum": ["dev", "production"],
            "default": "production"
        }
    }
}


class ConfigSchema:
    """Configuration schema wrapper."""
    
    @staticmethod
    def get_schema():
        return CONFIG_SCHEMA

