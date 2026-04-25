"""Phase 1 regression tests for api/auth.py hardening."""

from __future__ import annotations

import importlib


def _reset_auth_with_env(monkeypatch, secret: str):
    """Reset the auth module state with a known JWT secret in the env."""
    monkeypatch.setenv("RANSOMWARE_JWT_SECRET", secret)
    import api.auth as auth
    # nothing module-level caches the secret, but reload to be safe
    importlib.reload(auth)
    return auth


# ─── PLAIN: fallback removed ──────────────────────────────────────────────────

def test_hash_password_returns_bcrypt_only():
    from api.auth import _hash_password
    h = _hash_password("test_password_123")
    assert h.startswith("$2")  # bcrypt prefix
    assert not h.startswith("PLAIN:")


def test_legacy_plain_hash_still_verifies_but_warns(caplog):
    """Legacy users created by the previous insecure version must still log in
    once so they can rotate their password — but a warning must be emitted."""
    from api.auth import _verify_password
    with caplog.at_level("WARNING"):
        assert _verify_password("hello", "PLAIN:hello") is True
        assert _verify_password("nope", "PLAIN:hello") is False
    assert any("legacy PLAIN" in r.message for r in caplog.records)


# ─── DEFAULT_USERS removed ───────────────────────────────────────────────────

def test_default_users_is_empty():
    from api.auth import DEFAULT_USERS
    assert DEFAULT_USERS == {}


def test_authenticate_user_fails_when_no_users_configured(monkeypatch, tmp_path):
    """An unconfigured installation must never succeed at authentication."""
    from core import config_manager as cm
    monkeypatch.setitem(cm.config._config["api"], "users", {})

    from api.auth import authenticate_user
    assert authenticate_user("admin", "ransomware_detector_admin") is None
    assert authenticate_user("anything", "anything") is None


# ─── JWT secret enforcement ──────────────────────────────────────────────────

def test_jwt_secret_uses_env_var(monkeypatch):
    auth = _reset_auth_with_env(monkeypatch, "X" * 48)
    token = auth.create_access_token({"sub": "tester", "role": "reader"})
    payload = auth.verify_jwt(token)
    assert payload is not None
    assert payload["sub"] == "tester"


def test_jwt_token_signed_with_other_secret_rejected(monkeypatch):
    auth = _reset_auth_with_env(monkeypatch, "secret-A" + "x" * 40)
    token = auth.create_access_token({"sub": "alice", "role": "admin"})

    # Switch secrets — token must no longer verify
    auth = _reset_auth_with_env(monkeypatch, "secret-B" + "y" * 40)
    assert auth.verify_jwt(token) is None
