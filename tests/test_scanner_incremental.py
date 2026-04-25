"""
test_scanner_incremental.py
===========================
Unit tests for incremental scan cache behavior.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_mark_scanned_can_defer_cache_flush(temp_dir, monkeypatch):
    import core.scanner as scanner

    sample = temp_dir / "sample.bin"
    sample.write_bytes(b"abc123")

    scanner._INCREMENTAL_CACHE.clear()
    calls = {"count": 0}

    def fake_save():
        calls["count"] += 1

    monkeypatch.setattr(scanner, "_save_incremental_cache", fake_save)

    scanner.mark_scanned(str(sample), persist=False)
    assert calls["count"] == 0
    assert str(sample) in scanner._INCREMENTAL_CACHE

    scanner.flush_incremental_cache()
    assert calls["count"] == 1
