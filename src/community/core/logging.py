"""
@fileoverview Logging Infrastructure
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education
@version 1.0.0
@created 2025-11-18
@modified 2025-11-18

Structured logging with backward compatibility.
This file is part of AX-TrafficAnalyzer Community Edition.
Licensed under MIT License. See LICENSE-COMMUNITY for details.

INNOVATION:
- World-class structured logging with structlog
- Backward compatible with print() statements
- Dual mode: dev (human-readable) / production (JSON)
"""

import sys
import structlog
from pathlib import Path
from typing import Optional


def setup_logging(
    mode: str = "dev",
    log_file: Optional[str] = None,
    enable_print: bool = None
):
    """
    Setup structured logging.
    
    Args:
        mode: "dev" or "production"
        log_file: Path to log file (optional)
        enable_print: Force enable/disable print output (None = auto)
    """
    if enable_print is None:
        enable_print = (mode == "dev")
    
    processors = [
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    if mode == "dev":
        processors.append(structlog.dev.ConsoleRenderer())
    else:
        processors.append(structlog.processors.JSONRenderer())
    
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str):
    """Get a logger instance."""
    return structlog.get_logger(name)


# Initialize with dev mode by default
setup_logging(mode="dev")

