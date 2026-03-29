"""
api/auth.py
===========
Authentication module cho Ransomware Detector REST API.

Cung cap:
  - JWT Bearer Token authentication
  - API Key authentication (X-API-Key header)
  - Role-based access control (RBAC): admin, reader

Users/Keys are configured in data/config.json under "api" section.
"""

import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from jose import JWTError, jwt

logger = logging.getLogger(__name__)

# ─── Password hashing (bcrypt direct — bypasses broken passlib/bcrypt compatibility) ─

def _hash_password(password: str) -> str:
    """Hash password with bcrypt directly (bypasses broken passlib/bcrypt compatibility)."""
    try:
        import bcrypt
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    except Exception as e:
        logger.error(f"bcrypt hash failed: {e}. Using UNSAFE plaintext placeholder.")
        return f"PLAIN:{password}"


def _verify_password(plain: str, hashed: str) -> bool:
    """Verify password against a bcrypt (or plaintext sentinel) hash."""
    if hashed.startswith("PLAIN:"):
        return plain == hashed[6:]
    try:
        import bcrypt
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

# ─── Security configs (loaded from config) ────────────────────────────────────

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ─── Default API Users (can be overridden in config) ─────────────────────────
# NOTE: hashed_passwords are pre-computed bcrypt hashes so they are NOT
# re-hashed at import time (avoids bcrypt/passlib version conflicts).

DEFAULT_USERS: Dict[str, Dict[str, Any]] = {
    "admin": {
        "username": "admin",
        # bcrypt hash of "ransomware_detector_admin"
        "hashed_password": "$2b$12$n6AJqOGEzWb1o5C9hThyW.7SHef2ADE9vtGvYYjYSJuxQDnHIT8UK",
        "role": "admin",
        "disabled": False,
    },
    "reader": {
        "username": "reader",
        # bcrypt hash of "ransomware_detector_reader"
        "hashed_password": "$2b$12$YOv6tj7piJxBnTZFB49xJ.Rn5PNOu4V5dCrAX3boo2.u2a3Cy4YwG",
        "role": "reader",
        "disabled": False,
    },
}

# ─── API Keys store (also from config) ────────────────────────────────────────

_api_keys_db: Dict[str, Dict[str, Any]] = {}


def _load_users_from_config() -> Dict[str, Dict[str, Any]]:
    """Load users từ config hoặc dùng defaults."""
    try:
        from core.config_manager import config
        api_config = config.get("api", {})
        users_config = api_config.get("users", {})
        if users_config:
            result = {}
            for key, user_data in users_config.items():
                result[key] = {
                    "username": user_data.get("username", key),
                    "hashed_password": user_data.get("hashed_password", ""),
                    "role": user_data.get("role", "reader"),
                    "disabled": user_data.get("disabled", False),
                }
            return result
    except Exception:
        pass
    return DEFAULT_USERS


def _load_api_keys_from_config() -> Dict[str, Dict[str, Any]]:
    """Load API keys từ config."""
    try:
        from core.config_manager import config
        api_config = config.get("api", {})
        keys_config = api_config.get("api_keys", {})
        if keys_config:
            result = {}
            for key, data in keys_config.items():
                result[data.get("key", "")] = {
                    "name": data.get("name", key),
                    "role": data.get("role", "reader"),
                    "created_at": data.get("created_at", datetime.now(timezone.utc).isoformat()),
                    "disabled": data.get("disabled", False),
                }
            return result
    except Exception:
        pass
    return _api_keys_db


# ─── Password utilities ────────────────────────────────────────────────────────

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    return _verify_password(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return _hash_password(password)


def generate_api_key() -> str:
    """Generate a secure random API key."""
    return secrets.token_urlsafe(32)


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate user by username and password."""
    users = _load_users_from_config()
    user = users.get(username)
    if not user:
        return None
    if user.get("disabled"):
        return None
    if not verify_password(password, user.get("hashed_password", "")):
        return None
    return user


def authenticate_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """Authenticate by API key."""
    keys = _load_api_keys_from_config()
    key_data = keys.get(api_key)
    if not key_data:
        return None
    if key_data.get("disabled"):
        return None
    return {
        "type": "api_key",
        "name": key_data.get("name", "Unknown"),
        "role": key_data.get("role", "reader"),
    }


# ─── JWT Token Management ─────────────────────────────────────────────────────

def create_access_token(data: Dict[str, Any],
                        expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.

    Args:
        data: Payload data (must include "sub" for username and "role")
        expires_delta: Token expiration time

    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    })

    # Get JWT secret from config
    try:
        from core.config_manager import config
        jwt_secret = config.get("api.jwt_secret", "ransomware_detector_jwt_secret_change_me")
    except Exception:
        jwt_secret = "ransomware_detector_jwt_secret_change_me"

    encoded_jwt = jwt.encode(to_encode, jwt_secret, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def verify_jwt(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify and decode a JWT token.

    Returns:
        Decoded payload dict or None if invalid
    """
    try:
        from core.config_manager import config
        jwt_secret = config.get("api.jwt_secret", "ransomware_detector_jwt_secret_change_me")
    except Exception:
        jwt_secret = "ransomware_detector_jwt_secret_change_me"

    try:
        payload = jwt.decode(token, jwt_secret, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError as e:
        logger.debug(f"JWT verification failed: {e}")
        return None


# ─── FastAPI Dependencies ─────────────────────────────────────────────────────

# API Key header scheme
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# OAuth2 scheme (for Swagger UI)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)


def get_current_user_api_key(x_api_key: str = Depends(api_key_header)) -> Optional[Dict[str, Any]]:
    """Dependency: Get current user from API Key header."""
    if not x_api_key:
        return None
    return authenticate_api_key(x_api_key)


def get_current_user_jwt(token: str = Depends(oauth2_scheme)) -> Optional[Dict[str, Any]]:
    """Dependency: Get current user from JWT Bearer token."""
    if not token:
        return None
    payload = verify_jwt(token)
    if not payload:
        return None
    return {
        "type": "jwt",
        "username": payload.get("sub"),
        "role": payload.get("role", "reader"),
    }


def get_current_user(
    api_key_user: Optional[Dict[str, Any]] = Depends(get_current_user_api_key),
    jwt_user: Optional[Dict[str, Any]] = Depends(get_current_user_jwt),
) -> Dict[str, Any]:
    """
    Dependency: Get current user from either API Key or JWT.

    Raises HTTPException if neither is provided.
    """
    user = api_key_user or jwt_user
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated — provide X-API-Key header or Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_role(required_role: str):
    """
    Dependency factory: Require specific role.

    Usage:
        @app.get("/admin", dependencies=[Depends(require_role("admin"))])
    """
    def role_checker(current_user: Dict[str, Any] = Depends(get_current_user)):
        user_role = current_user.get("role", "reader")

        # Role hierarchy: admin > reader
        if required_role == "admin" and user_role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required",
            )
        # reader can access everything except admin-only endpoints
        return current_user

    return role_checker


def require_admin(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Dependency: Require admin role."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user
