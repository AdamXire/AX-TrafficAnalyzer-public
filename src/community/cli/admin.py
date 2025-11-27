"""
@fileoverview Admin CLI - Admin user creation tool
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

CLI command for creating admin users.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import asyncio
import sys
import getpass
from pathlib import Path
from ..storage.database import DatabaseManager
from ..core.logging import get_logger

log = get_logger(__name__)


def create_admin_user(
    username: str = None,
    password: str = None,
    db_path: str = "./data/ax-traffic.db",
    role: str = "admin"
) -> None:
    """
    Create admin user via CLI.
    
    Args:
        username: Admin username (prompts if not provided)
        password: Admin password (prompts if not provided)
        db_path: Database path
        role: User role (default: admin)
    """
    log.info("admin_cli_start", db_path=db_path)
    
    # Prompt for username if not provided
    if not username:
        username = input("Enter admin username: ").strip()
        if not username:
            print("ERROR: Username cannot be empty", file=sys.stderr)
            sys.exit(1)
    
    # Prompt for password if not provided
    if not password:
        password = getpass.getpass("Enter admin password: ")
        if not password:
            print("ERROR: Password cannot be empty", file=sys.stderr)
            sys.exit(1)
        
        password_confirm = getpass.getpass("Confirm admin password: ")
        if password != password_confirm:
            print("ERROR: Passwords do not match", file=sys.stderr)
            sys.exit(1)
    
    # Validate password strength
    if len(password) < 8:
        print("ERROR: Password must be at least 8 characters", file=sys.stderr)
        sys.exit(1)
    
    # Initialize database
    db_path_obj = Path(db_path)
    if not db_path_obj.exists():
        print(f"ERROR: Database not found at {db_path}", file=sys.stderr)
        print("Hint: Run the main application first to create the database", file=sys.stderr)
        sys.exit(1)
    
    db_manager = DatabaseManager(db_path=db_path, pool_size=1)
    
    try:
        # Start database
        db_manager.start()
        log.debug("database_connected_for_cli")
        
        # Create admin user
        async def _create():
            created = await db_manager.create_default_admin(username, password, role)
            if created:
                print(f"✓ Admin user '{username}' created successfully")
                log.info("admin_user_cli_created", username=username)
            else:
                print(f"⚠ Admin user '{username}' already exists")
                log.info("admin_user_cli_exists", username=username)
        
        asyncio.run(_create())
        
        # Stop database
        db_manager.stop()
        
    except Exception as e:
        print(f"ERROR: Failed to create admin user: {e}", file=sys.stderr)
        log.error("admin_cli_failed", error=str(e), error_type=type(e).__name__)
        sys.exit(1)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Create admin user for AX-TrafficAnalyzer")
    parser.add_argument("--username", help="Admin username")
    parser.add_argument("--password", help="Admin password (not recommended)")
    parser.add_argument("--db-path", default="./data/ax-traffic.db", help="Database path")
    parser.add_argument("--role", default="admin", help="User role")
    
    args = parser.parse_args()
    create_admin_user(
        username=args.username,
        password=args.password,
        db_path=args.db_path,
        role=args.role
    )

