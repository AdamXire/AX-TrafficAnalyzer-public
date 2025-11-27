"""
@fileoverview Migration Manager - Alembic migration runner
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Manages database migrations using Alembic.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import os
from pathlib import Path
from alembic.config import Config
from alembic import command
from alembic.script import ScriptDirectory
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine
from ..core.errors import ConfigurationError
from ..core.logging import get_logger

log = get_logger(__name__)


class MigrationManager:
    """
    Manages database migrations using Alembic.
    
    Auto-migrates in dev mode, requires manual approval in production.
    """
    
    def __init__(self, config_path: str = "alembic.ini", db_path: str = None):
        """
        Initialize migration manager.
        
        Args:
            config_path: Path to alembic.ini
            db_path: Path to database file (for version checking)
        """
        self.config_path = Path(config_path)
        self.db_path = db_path
        if not self.config_path.exists():
            raise ConfigurationError(
                f"Alembic config not found: {config_path}",
                None
            )
        self.alembic_cfg = Config(str(self.config_path))
        log.debug("migration_manager_initialized", config_path=str(config_path))
    
    def get_current_revision(self) -> str:
        """Get current database revision."""
        if not self.db_path or not Path(self.db_path).exists():
            return None
        
        try:
            engine = create_engine(f"sqlite:///{self.db_path}")
            with engine.connect() as conn:
                context = MigrationContext.configure(conn)
                current_rev = context.get_current_revision()
                return current_rev
        except Exception as e:
            log.error("migration_current_revision_error", error=str(e))
            raise ConfigurationError("Failed to get current migration revision", e)
    
    def get_head_revision(self) -> str:
        """Get head (latest) revision."""
        try:
            script = ScriptDirectory.from_config(self.alembic_cfg)
            head = script.get_current_head()
            return head
        except Exception as e:
            log.error("migration_head_revision_error", error=str(e))
            raise ConfigurationError("Failed to get head migration revision", e)
    
    def run_migrations(self, mode: str = "production") -> None:
        """
        Run migrations based on mode.
        
        Args:
            mode: "dev" (auto-migrate) or "production" (check only)
            
        Raises:
            ConfigurationError: If production mode and database outdated
        """
        log.info("migration_check_begin", mode=mode)
        
        current = self.get_current_revision()
        head = self.get_head_revision()
        
        log.debug("migration_revisions", current=current, head=head)
        
        if current == head:
            log.info("migration_up_to_date", revision=current)
            return
        
        if mode == "dev":
            # Auto-migrate in dev mode
            log.info("migration_auto_applying", current=current, target=head)
            try:
                command.upgrade(self.alembic_cfg, "head")
                log.info("migration_auto_complete", new_revision=head)
            except Exception as e:
                log.error("migration_auto_failed", error=str(e))
                raise ConfigurationError(
                    f"Auto-migration failed: {e}",
                    None
                ) from e
        else:
            # Production mode: fail-fast with instructions
            raise ConfigurationError(
                f"Database schema outdated: {current} (current) vs {head} (latest). "
                f"Run migration manually: alembic upgrade head",
                None
            )

