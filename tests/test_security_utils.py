"""Tests for core/security_utils.py — Phase 1 hardening helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core.security_utils import (
    PathSafetyError,
    atomic_write_json,
    compute_sha256,
    load_or_generate_secret,
    resolve_safe_path,
    safe_read_json,
)


# ─── compute_sha256 ───────────────────────────────────────────────────────────

def test_compute_sha256_deterministic(tmp_path: Path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"hello world")
    expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert compute_sha256(p) == expected


def test_compute_sha256_streams_large_file(tmp_path: Path):
    """The streaming impl must not load the whole file into memory."""
    p = tmp_path / "big.bin"
    # ~3 MiB written in chunks — bigger than the default 1 MiB chunk size
    payload = b"x" * (1024 * 1024)
    with open(p, "wb") as f:
        for _ in range(3):
            f.write(payload)
    digest = compute_sha256(p)
    assert len(digest) == 64
    assert digest.isalnum()


def test_compute_sha256_missing_file():
    assert compute_sha256("/nonexistent/path/file.bin") == ""


# ─── atomic_write_json / safe_read_json ──────────────────────────────────────

def test_atomic_write_json_roundtrip(tmp_path: Path):
    target = tmp_path / "a" / "b" / "c.json"
    data = {"hello": "world", "n": 1}
    assert atomic_write_json(target, data) is True
    assert json.loads(target.read_text(encoding="utf-8")) == data


def test_atomic_write_json_replaces_atomically(tmp_path: Path):
    target = tmp_path / "x.json"
    target.write_text('{"old": true}', encoding="utf-8")
    assert atomic_write_json(target, {"new": True}) is True
    assert safe_read_json(target) == {"new": True}
    # No leftover .tmp files
    leftover = list(tmp_path.glob("*.tmp"))
    assert leftover == []


def test_safe_read_json_missing_returns_default(tmp_path: Path):
    assert safe_read_json(tmp_path / "missing.json", default={}) == {}


def test_safe_read_json_bad_json_returns_default(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text("not json", encoding="utf-8")
    assert safe_read_json(p, default=[]) == []


# ─── resolve_safe_path ───────────────────────────────────────────────────────

def test_resolve_safe_path_inside_root(tmp_path: Path):
    sub = tmp_path / "sub"
    sub.mkdir()
    resolved = resolve_safe_path(str(sub), [tmp_path])
    assert resolved == sub.resolve()


def test_resolve_safe_path_traversal_rejected(tmp_path: Path):
    outside = tmp_path.parent
    with pytest.raises(PathSafetyError):
        resolve_safe_path(str(outside), [tmp_path])


def test_resolve_safe_path_rejects_unc(tmp_path: Path):
    if os.name != "nt":
        pytest.skip("UNC paths only meaningful on Windows")
    with pytest.raises(PathSafetyError):
        resolve_safe_path(r"\\evil-server\share", [tmp_path])


def test_resolve_safe_path_empty():
    with pytest.raises(PathSafetyError):
        resolve_safe_path("", ["/tmp"])


# ─── load_or_generate_secret ─────────────────────────────────────────────────

def test_load_or_generate_secret_prefers_env(monkeypatch):
    monkeypatch.setenv("RDET_TEST_SECRET", "env-supplied-secret-1234567890")
    val = load_or_generate_secret("RDET_TEST_SECRET", "api.jwt_secret")
    assert val == "env-supplied-secret-1234567890"


def test_load_or_generate_secret_generates_when_blank(monkeypatch, tmp_path):
    monkeypatch.delenv("RDET_GEN_SECRET", raising=False)
    # Point ConfigManager at a fresh file so we don't pollute the user's config
    from core import config_manager as cm

    fresh_cfg = cm.ConfigManager.__new__(cm.ConfigManager)
    import threading
    import copy
    fresh_cfg._lock = threading.Lock()
    fresh_cfg._defaults = copy.deepcopy(cm.DEFAULT_CONFIG)
    fresh_cfg._config = copy.deepcopy(cm.DEFAULT_CONFIG)
    fresh_cfg._config["api"]["jwt_secret"] = ""
    # Override CONFIG_FILE so save writes to temp
    fresh_cfg.CONFIG_FILE = str(tmp_path / "cfg.json")

    monkeypatch.setattr(cm, "_config_instance", fresh_cfg)
    monkeypatch.setattr(cm, "config", fresh_cfg)

    val = load_or_generate_secret("RDET_GEN_SECRET", "api.jwt_secret")
    assert val and len(val) >= 32
    # Persisted
    assert fresh_cfg.get("api.jwt_secret") == val
