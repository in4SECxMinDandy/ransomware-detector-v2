"""Tests for core/auto_responder.py — including the new countdown logic."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest


@pytest.fixture
def isolated_responder(tmp_path, monkeypatch):
    """An AutoResponder rooted at tmp_path so we don't pollute the repo."""
    monkeypatch.chdir(tmp_path)  # quarantine_dir + manifest live under cwd
    from core.auto_responder import AutoResponder
    return AutoResponder()


def test_quarantine_file_persists_manifest_atomically(isolated_responder, tmp_path):
    target = tmp_path / "evil.bin"
    target.write_bytes(b"BADBAD" * 100)

    result = isolated_responder.quarantine_file(str(target), reason="unit-test")
    assert result["success"] is True

    manifest_path = Path(isolated_responder.MANIFEST_FILE)
    assert manifest_path.is_file()
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert any(entry["original_path"] == str(target) for entry in payload.values())
    # No leftover .tmp files
    assert list(manifest_path.parent.glob("*.tmp")) == []


def test_quarantine_with_countdown_aborts_via_callback(isolated_responder, tmp_path, monkeypatch):
    target = tmp_path / "fp.bin"
    target.write_bytes(b"benign")

    isolated_responder.set_abort_callback(lambda _path: True)
    # Force a short countdown so the test stays fast
    from core.config_manager import config as cfg
    monkeypatch.setitem(cfg._config["auto_response"], "countdown_seconds", 2)

    t0 = time.monotonic()
    result = isolated_responder.quarantine_with_countdown(str(target), seconds=2)
    elapsed = time.monotonic() - t0

    assert result["aborted"] is True
    assert result["success"] is False
    # File must still exist on disk — abort means do NOT quarantine
    assert target.exists()
    # Should have aborted within ~1 polling tick (< 2s ceiling)
    assert elapsed < 3.0


def test_quarantine_with_countdown_proceeds_when_no_callback(isolated_responder, tmp_path):
    target = tmp_path / "real-malware.bin"
    target.write_bytes(b"\x00" * 64)

    result = isolated_responder.quarantine_with_countdown(str(target), seconds=0)
    assert result["aborted"] is False
    assert result["success"] is True
    # Original path is gone (moved into quarantine)
    assert not target.exists()
