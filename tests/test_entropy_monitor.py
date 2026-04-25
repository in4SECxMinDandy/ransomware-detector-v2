"""
test_entropy_monitor.py
=========================
Unit tests for Entropy monitoring in watchdog_monitor.py.
"""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.watchdog_monitor import RealTimeMonitor, ThreatEvent, _EventHandler


def test_entropy_stats_initial_state():
    """Test that entropy stats start in correct state."""
    monitor = RealTimeMonitor()
    stats = monitor.get_entropy_stats()

    assert stats["enabled"]
    assert stats["consecutive_count"] == 0
    assert not stats["is_above_threshold"]
    assert not stats["alert_triggered"]
    assert stats["threshold"] == 7.5


def test_entropy_threshold_defaults():
    """Test default entropy threshold values."""
    monitor = RealTimeMonitor()

    assert monitor._entropy_threshold == 7.5
    assert monitor._entropy_consecutive == 5
    assert monitor._entropy_window_seconds == 30.0


def test_compute_shannon_entropy(temp_dir):
    """Test Shannon entropy computation."""
    # Test with a low-entropy text file
    low_entropy_file = temp_dir / "low_entropy.txt"
    low_entropy_file.write_bytes(b"AAAAAA")

    monitor = RealTimeMonitor()
    entropy = monitor._compute_shannon_entropy(str(low_entropy_file))

    # Text files have low entropy
    assert 0 <= entropy <= 4

    # Test with random data (high entropy)
    import numpy as np
    high_entropy_file = temp_dir / "high_entropy.bin"
    high_entropy_file.write_bytes(np.random.bytes(1024))

    entropy = monitor._compute_shannon_entropy(str(high_entropy_file))

    # Random data has high entropy
    assert 7.0 <= entropy <= 8.0


def test_check_entropy_burst_not_triggered(temp_dir):
    """Test entropy burst detection with normal files."""
    from core.scanner import ScanResult

    monitor = RealTimeMonitor()
    monitor._entropy_history.clear()

    # Simulate low entropy files (not triggering alert)
    result = ScanResult("test.txt")
    result.risk_level = "SAFE"

    for i in range(3):
        monitor._check_entropy_burst(f"file_{i}.txt", 3.5, result)

    stats = monitor.get_entropy_stats()
    assert stats["consecutive_count"] == 0  # Low entropy not counted
    assert not stats["is_above_threshold"]


def test_check_entropy_burst_triggered(temp_dir):
    """Test entropy burst detection with high entropy files."""
    from core.scanner import ScanResult

    monitor = RealTimeMonitor()
    monitor._entropy_history.clear()
    monitor._entropy_alert_logged = False

    result = ScanResult("encrypted.bin")
    result.risk_level = "CRITICAL"

    # Simulate 5 high entropy files
    for i in range(5):
        monitor._check_entropy_burst(f"encrypted_{i}.bin", 7.8, result)

    stats = monitor.get_entropy_stats()
    assert stats["consecutive_count"] == 5
    assert stats["is_above_threshold"]


def test_reset_entropy_state(temp_dir):
    """Test resetting entropy state."""
    from core.scanner import ScanResult

    monitor = RealTimeMonitor()
    result = ScanResult("test.bin")
    result.risk_level = "HIGH"

    # Add some entropy entries
    for i in range(3):
        monitor._check_entropy_burst(f"file_{i}.bin", 7.8, result)

    assert monitor.get_entropy_stats()["consecutive_count"] == 3

    monitor.reset_entropy_state()

    stats = monitor.get_entropy_stats()
    assert stats["consecutive_files"] == 0


def test_threat_event_to_dict():
    """Test ThreatEvent to_dict() serialization."""
    from core.scanner import ScanResult

    result = ScanResult("test.exe")
    result.probability = 0.85
    result.risk_level = "HIGH"
    result.entropy = 7.5

    event = ThreatEvent(result, "created")
    d = event.to_dict()

    assert d["event_type"] == "created"
    assert d["filename"] == "test.exe"
    assert d["probability"] == 0.85
    assert d["risk_level"] == "HIGH"
    assert d["entropy"] == 7.5


def test_entropy_alert_callback(temp_dir):
    """Test entropy alert callback mechanism."""
    from core.scanner import ScanResult

    monitor = RealTimeMonitor()
    alert_received = []

    def on_entropy_alert(alert_info):
        alert_received.append(alert_info)

    monitor.on_entropy_alert = on_entropy_alert
    result = ScanResult("test.bin")
    result.risk_level = "CRITICAL"

    # Trigger alert
    for i in range(5):
        monitor._check_entropy_burst(f"file_{i}.bin", 7.8, result)

    # Alert should be fired
    assert len(alert_received) == 1
    assert alert_received[0]["consecutive_files"] == 5


def test_event_handler_skips_ignored_internal_paths(temp_dir):
    """Ignored project roots should never enqueue events."""
    ignored_dir = temp_dir / "logs"
    ignored_dir.mkdir()
    sample = ignored_dir / "detector.json"
    sample.write_bytes(b'{"ok": true}')

    handler = _EventHandler(
        file_queue=__import__("queue").Queue(),
        debounce_cache={},
        ignored_roots=[str(ignored_dir)],
    )

    assert handler._should_process(str(sample)) is False


def test_record_process_event_skips_pid_lookup_for_low_risk(temp_dir, monkeypatch):
    """Low-risk monitor events should not trigger expensive system-wide PID scans."""
    monitor = RealTimeMonitor()
    calls = {"count": 0}
    captured = {}

    def fake_lookup(_path):
        calls["count"] += 1
        return 1234

    def fake_record(event):
        captured["pid"] = event.pid
        captured["entropy"] = event.entropy

    monkeypatch.setattr(monitor, "_get_file_process_pid", fake_lookup)
    monkeypatch.setattr(monitor._process_monitor, "record_event", fake_record)

    monitor._record_process_event(
        str(temp_dir / "sample.txt"),
        "modified",
        [3.2] + [0.0] * 15,
        128,
        0.05,
    )

    assert calls["count"] == 0
    assert captured["pid"] is None
    assert captured["entropy"] == 3.2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
