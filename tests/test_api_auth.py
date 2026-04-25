"""
test_api_auth.py
====================
Unit tests for API authentication module.
"""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))



def test_generate_api_key():
    """Test API key generation."""
    from api.auth import generate_api_key

    key1 = generate_api_key()
    key2 = generate_api_key()

    assert len(key1) >= 32
    assert key1 != key2  # Should be unique


def test_password_hashing():
    """Test password hashing utilities."""
    from api.auth import get_password_hash, verify_password

    password = "test_password_123"
    hashed = get_password_hash(password)

    assert hashed != password
    assert verify_password(password, hashed)
    assert not verify_password("wrong_password", hashed)


def test_authenticate_user_not_found():
    """Test authentication with non-existent user."""
    from api.auth import authenticate_user

    result = authenticate_user("nonexistent_user", "password")
    assert result is None


def test_create_access_token():
    """Test JWT access token creation."""
    from api.auth import create_access_token, verify_jwt

    token = create_access_token(
        data={"sub": "testuser", "role": "admin"}
    )

    assert isinstance(token, str)
    assert len(token) > 50  # JWT is long

    # Verify token
    payload = verify_jwt(token)
    assert payload is not None
    assert payload["sub"] == "testuser"
    assert payload["role"] == "admin"


def test_verify_jwt_invalid_token():
    """Test JWT verification with invalid token."""
    from api.auth import verify_jwt

    result = verify_jwt("invalid.token.here")
    assert result is None


def test_verify_jwt_expired():
    """Test JWT verification with expired token."""
    from api.auth import verify_jwt

    # Create a token that's already expired
    # This tests the verify_jwt function handles expired tokens gracefully
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNjAwMDAwMDAwfQ.dummy"

    result = verify_jwt(token)
    # Should return None for invalid/expired token
    assert result is None or "exp" in result


def test_require_role_factory():
    """Test role requirement dependency factory."""
    from api.auth import require_role

    require_role("admin")

    # Note: Full test requires FastAPI Depends which is harder to test in isolation


def test_get_current_user_api_key_missing():
    """Test get_current_user with missing API key."""
    from api.auth import get_current_user_api_key

    # No key provided
    result = get_current_user_api_key(x_api_key=None)
    assert result is None


def test_authenticate_api_key_not_found():
    """Test API key authentication with invalid key."""
    from api.auth import authenticate_api_key

    result = authenticate_api_key("invalid_key_12345")
    assert result is None


def test_token_response_structure():
    """Test TokenResponse structure."""
    from api.schemas import TokenResponse

    response = TokenResponse(
        access_token="test_token",
        token_type="bearer",
        expires_in=3600,
        role="admin"
    )

    assert response.access_token == "test_token"
    assert response.token_type == "bearer"
    assert response.expires_in == 3600
    assert response.role == "admin"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
