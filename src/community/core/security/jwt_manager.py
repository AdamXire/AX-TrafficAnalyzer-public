"""
@fileoverview JWT Manager - JWT token generation and verification
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

JWT token management with secure secret storage in keyring.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict
from jose import jwt, JWTError  # python-jose package imports as 'jose'
from .keyring_manager import KeyringManager
from ..errors import SecurityError
from ..logging import get_logger

log = get_logger(__name__)

# JWT secret key name in keyring
JWT_SECRET_KEY = "jwt-secret"
JWT_ALGORITHM = "HS256"


class JWTManager:
    """
    JWT token manager with secure secret storage.
    
    Stores JWT secret in system keyring (encrypted at rest).
    Generates new secret on first run if not exists.
    """
    
    def __init__(self, keyring_manager: KeyringManager, token_expiry_hours: int = 24):
        """
        Initialize JWT manager.
        
        Args:
            keyring_manager: KeyringManager instance for secret storage
            token_expiry_hours: Token expiry time in hours (default: 24)
        """
        self.keyring_manager = keyring_manager
        self.token_expiry_hours = token_expiry_hours
        self.secret_key = self._get_or_create_secret()
        log.debug("jwt_manager_initialized", expiry_hours=token_expiry_hours)
    
    def _get_or_create_secret(self) -> str:
        """
        Get JWT secret from keyring or create new one.
        
        Returns:
            JWT secret key string
            
        Raises:
            SecurityError: If keyring unavailable
        """
        # Dev mode fallback: use env var or generate ephemeral secret
        if self.keyring_manager is None:
            import os
            secret = os.environ.get("JWT_SECRET")
            if secret:
                log.warning("jwt_secret_from_env", message="Using JWT_SECRET from environment (dev mode)")
                return secret
            # Generate ephemeral secret (will change on restart)
            secret = secrets.token_urlsafe(64)
            log.warning("jwt_secret_ephemeral", message="Generated ephemeral JWT secret (dev mode - will change on restart)")
            return secret
        
        try:
            secret = self.keyring_manager.retrieve_key(JWT_SECRET_KEY)
            if secret:
                log.debug("jwt_secret_retrieved_from_keyring")
                return secret
            
            # First run: generate new secret
            log.info("jwt_secret_not_found_generating")
            secret = secrets.token_urlsafe(64)  # 64 bytes = 86 chars base64
            self.keyring_manager.store_key(JWT_SECRET_KEY, secret)
            log.info("jwt_secret_generated_and_stored")
            return secret
            
        except Exception as e:
            log.error("jwt_secret_retrieval_failed", error=str(e))
            raise SecurityError(
                f"Failed to get or create JWT secret: {e}",
                None
            ) from e
    
    def create_token(
        self,
        user_id: str,
        role: str,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT token for user.
        
        Args:
            user_id: User ID
            role: User role (admin, analyst, viewer)
            expires_delta: Optional custom expiry time
            
        Returns:
            JWT token string
        """
        if expires_delta is None:
            expires_delta = timedelta(hours=self.token_expiry_hours)
        
        expire = datetime.utcnow() + expires_delta
        
        payload = {
            "sub": user_id,  # Subject (user ID)
            "role": role,
            "exp": expire,  # Expiration time
            "iat": datetime.utcnow(),  # Issued at
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=JWT_ALGORITHM)
        log.debug("jwt_token_created", user_id=user_id, role=role, expires_at=expire.isoformat())
        return token
    
    def verify_token(self, token: str) -> Dict:
        """
        Verify and decode JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload (dict with sub, role, exp, iat)
            
        Raises:
            SecurityError: If token invalid, expired, or verification fails
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[JWT_ALGORITHM]
            )
            log.debug("jwt_token_verified", user_id=payload.get("sub"), role=payload.get("role"))
            return payload
        except JWTError as e:
            log.warning("jwt_token_verification_failed", error=str(e))
            raise SecurityError(
                f"Invalid or expired token: {e}",
                None
            ) from e
        except Exception as e:
            log.error("jwt_token_verification_error", error=str(e), error_type=type(e).__name__)
            raise SecurityError(
                f"Token verification failed: {e}",
                None
            ) from e
    
    def get_user_from_token(self, token: str) -> Dict:
        """
        Get user information from token.
        
        Args:
            token: JWT token string
            
        Returns:
            Dict with user_id and role
            
        Raises:
            SecurityError: If token invalid
        """
        payload = self.verify_token(token)
        return {
            "user_id": payload.get("sub"),
            "role": payload.get("role")
        }

