"""
@fileoverview First Run Detection - Setup wizard
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

First-run detection and setup wizard.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from pathlib import Path
from typing import Optional
from sqlalchemy import select, create_engine
from ..core.logging import get_logger

log = get_logger(__name__)


class FirstRunDetector:
    """
    Detects first run and manages initialization flag.
    
    Uses both database check and flag file for robustness.
    """
    
    def __init__(self, db_path: str, flag_file: str = ".initialized"):
        """
        Initialize first-run detector.
        
        Args:
            db_path: Path to database file
            flag_file: Path to initialization flag file
        """
        self.db_path = Path(db_path)
        self.flag_file = Path(flag_file)
        log.debug("first_run_detector_initialized", db_path=str(db_path), flag_file=str(flag_file))
    
    def is_first_run(self) -> bool:
        """
        Check if this is first run.
        
        Returns:
            True if first run (no DB, no flag, or empty users table)
        """
        db_exists = self.db_path.exists()
        flag_exists = self.flag_file.exists()
        
        # If neither exists, definitely first run
        if not db_exists and not flag_exists:
            log.info("first_run_detected", reason="no_db_no_flag")
            return True
        
        # If DB exists, check if users table is empty
        if db_exists:
            try:
                engine = create_engine(f"sqlite:///{self.db_path}")
                with engine.connect() as conn:
                    # Check if users table exists and has records
                    from sqlalchemy import text
                    result = conn.execute(text("SELECT COUNT(*) FROM users"))
                    user_count = result.scalar()
                    
                    if user_count == 0:
                        log.info("first_run_detected", reason="no_users_in_db")
                        return True
                    else:
                        log.debug("first_run_check", users_found=user_count, is_first_run=False)
                        return False
            except Exception as e:
                # If table doesn't exist or error, treat as first run
                log.debug("first_run_check_error", error=str(e), treating_as_first_run=True)
                return True
        
        # Flag exists but no DB - treat as first run (DB might have been deleted)
        if flag_exists and not db_exists:
            log.info("first_run_detected", reason="flag_exists_but_no_db")
            return True
        
        # Both exist - not first run
        log.debug("first_run_check", is_first_run=False, reason="db_and_flag_exist")
        return False
    
    def mark_initialized(self) -> None:
        """
        Create flag file after successful setup.
        
        Raises:
            IOError: If flag file cannot be created
        """
        try:
            self.flag_file.touch()
            log.info("first_run_complete", flag_file=str(self.flag_file))
        except Exception as e:
            log.error("first_run_flag_creation_failed", flag_file=str(self.flag_file), error=str(e))
            raise IOError(f"Failed to create initialization flag: {e}") from e

