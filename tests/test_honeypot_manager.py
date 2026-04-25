"""
test_honeypot_manager.py
==========================
Unit tests for Honeypot Manager module.
"""

import sys
import os
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.honeypot_manager import (
    HoneypotManager, HoneypotFile, HoneypotAccessEvent,
    DEFAULT_HONEYPOT_NAMES, INNOCUOUS_CONTENT,
)


def test_honeypot_file_creation():
    """Test HoneypotFile dataclass creation and record_access."""
    from datetime import datetime

    hp = HoneypotFile(
        id="HP_test_001",
        name="passwords.xlsx",
        path="C:/Users/Test/Documents/passwords.xlsx",
        extension=".xlsx",
        created_at=datetime.now().isoformat(),
    )

    assert hp.access_count == 0
    assert not hp.is_triggered

    hp.record_access(pid=1234, process_name="test.exe", event_type="modified")
    assert hp.access_count == 1
    assert hp.last_accessed is not None
    assert not hp.is_triggered


def test_honeypot_access_event():
    """Test HoneypotAccessEvent dataclass."""

    event = HoneypotAccessEvent(
        timestamp="2025-03-21T10:00:00",
        honeypot_id="HP_test_001",
        honeypot_name="passwords.xlsx",
        honeypot_path="C:/test/passwords.xlsx",
        event_type="modified",
        pid=1234,
        process_name="malware.exe",
        severity="CRITICAL",
        action_taken="Kill process PID=1234",
    )

    assert event.severity == "CRITICAL"
    assert event.pid == 1234
    d = event.to_dict()
    assert d["event_type"] == "modified"


def test_manager_init(temp_dir, monkeypatch):
    """Test HoneypotManager initialization with isolated registry."""
    # Use isolated registry path to avoid interference from existing data
    registry_path = temp_dir / "honeypot_registry.json"
    manager = HoneypotManager(registry_path=str(registry_path))

    assert manager.get_active_count() == 0
    assert manager.get_triggered_count() == 0
    assert isinstance(manager.honeypot_names, list)
    assert len(manager.honeypot_names) > 0


def test_deploy_honeypots(temp_dir, monkeypatch):
    """Test deploying honeypot files with isolated registry."""
    # Use isolated registry path
    registry_path = temp_dir / "honeypot_registry.json"
    manager = HoneypotManager(registry_path=str(registry_path))

    # Create target directory structure
    desktop = temp_dir / "Desktop"
    desktop.mkdir()
    docs = temp_dir / "Documents"
    docs.mkdir()

    deployed = manager.deploy(str(temp_dir), max_per_location=2)

    assert len(deployed) > 0
    assert manager.get_active_count() == len(deployed)

    # Check that files were actually created
    for hp in deployed:
        assert os.path.isfile(hp.path)


def test_remove_all_honeypots(temp_dir, monkeypatch):
    """Test removing all honeypot files with isolated registry."""
    registry_path = temp_dir / "honeypot_registry.json"
    manager = HoneypotManager(registry_path=str(registry_path))

    # Create honeypots
    desktop = temp_dir / "Desktop"
    desktop.mkdir()
    manager.deploy(str(temp_dir), max_per_location=2)

    assert manager.get_active_count() > 0

    removed = manager.remove_all()

    assert removed > 0
    assert manager.get_active_count() == 0


def test_is_honeypot(temp_dir, monkeypatch):
    """Test is_honeypot() method with isolated registry."""
    registry_path = temp_dir / "honeypot_registry.json"
    manager = HoneypotManager(registry_path=str(registry_path))

    desktop = temp_dir / "Desktop"
    desktop.mkdir()
    deployed = manager.deploy(str(temp_dir), max_per_location=1)

    assert len(deployed) > 0
    hp_path = deployed[0].path

    assert manager.is_honeypot(hp_path)
    assert not manager.is_honeypot(str(temp_dir / "nonexistent.txt"))


def test_get_status(temp_dir, monkeypatch):
    """Test get_status() method with isolated registry."""
    registry_path = temp_dir / "honeypot_registry.json"
    manager = HoneypotManager(registry_path=str(registry_path))

    desktop = temp_dir / "Desktop"
    desktop.mkdir()
    deployed = manager.deploy(str(temp_dir), max_per_location=1)

    status = manager.get_status()
    assert len(status) == len(deployed)
    assert status[0].name in DEFAULT_HONEYPOT_NAMES


def test_access_history(temp_dir, monkeypatch):
    """Test access history tracking with isolated registry."""
    registry_path = temp_dir / "honeypot_registry.json"
    manager = HoneypotManager(registry_path=str(registry_path))

    desktop = temp_dir / "Desktop"
    desktop.mkdir()
    deployed = manager.deploy(str(temp_dir), max_per_location=1)

    hp_path = deployed[0].path

    # Simulate access
    manager.on_file_event(hp_path, "accessed", pid=9999, process_name="test.exe")

    history = manager.get_access_history(limit=10)
    assert len(history) == 1
    assert history[0].event_type == "accessed"


def test_get_triggered_count(temp_dir, monkeypatch):
    """Test triggered count in 24h with isolated registry."""
    registry_path = temp_dir / "honeypot_registry.json"
    manager = HoneypotManager(registry_path=str(registry_path))

    assert manager.get_triggered_count(hours=24) == 0


def test_default_honeypot_names():
    """Test that default honeypot names include _DECOY_ prefix (Phase 1 security fix)."""
    # Names should now have _DECOY_ prefix to avoid user confusion
    assert "_DECOY_passwords.xlsx" in DEFAULT_HONEYPOT_NAMES
    assert "_DECOY_wallet_keys.txt" in DEFAULT_HONEYPOT_NAMES
    assert "_DECOY_company_secrets.txt" in DEFAULT_HONEYPOT_NAMES
    assert len(DEFAULT_HONEYPOT_NAMES) >= 7


def test_innocuous_content_templates():
    """Test that innocuous content templates exist for supported extensions."""
    assert ".txt" in INNOCUOUS_CONTENT
    assert ".pdf" in INNOCUOUS_CONTENT
    assert ".xlsx" in INNOCUOUS_CONTENT
    assert ".docx" in INNOCUOUS_CONTENT
    assert ".pem" in INNOCUOUS_CONTENT

    # Verify content contains placeholders
    assert "{doc_id}" in INNOCUOUS_CONTENT[".txt"]
    assert "{date}" in INNOCUOUS_CONTENT[".txt"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
