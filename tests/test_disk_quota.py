"""
test_disk_quota.py
==================
Audit P3-15 regression tests for ``AutoResponder._check_disk_quota`` +
``_log_action`` thread safety.
"""

import os
import threading
from collections import namedtuple

import pytest

from core.auto_responder import AutoResponder


_FakeUsage = namedtuple("FakeUsage", ["total", "used", "free"])


@pytest.fixture
def responder(tmp_path, monkeypatch):
    """An AutoResponder anchored to a tmp_path so the suite never touches
    the real ``quarantine/`` or ``logs/`` folders."""
    qdir = tmp_path / "quarantine"
    audit = tmp_path / "logs" / "audit.log"
    monkeypatch.setattr(AutoResponder, "QUARANTINE_DIR", str(qdir) + os.sep)
    monkeypatch.setattr(AutoResponder, "AUDIT_LOG", str(audit))
    monkeypatch.setattr(
        AutoResponder, "MANIFEST_FILE", str(tmp_path / "manifest.json")
    )
    return AutoResponder()


class TestDiskQuotaGuard:
    def test_plenty_of_space_returns_none(self, responder, tmp_path, monkeypatch):
        target = tmp_path / "sample.bin"
        target.write_bytes(b"x" * 1024)

        # 100 GiB total, 90 GiB free — comfortably above floors.
        gib = 1024 ** 3
        monkeypatch.setattr(
            "shutil.disk_usage",
            lambda p: _FakeUsage(total=100 * gib, used=10 * gib, free=90 * gib),
        )
        assert responder._check_disk_quota(str(target)) is None

    def test_low_free_fraction_blocks(self, responder, tmp_path, monkeypatch):
        target = tmp_path / "sample.bin"
        target.write_bytes(b"x" * 1024)

        # 5% free is below the 10% floor.
        gib = 1024 ** 3
        monkeypatch.setattr(
            "shutil.disk_usage",
            lambda p: _FakeUsage(total=100 * gib, used=95 * gib, free=5 * gib),
        )
        err = responder._check_disk_quota(str(target))
        assert err is not None
        assert "insufficient disk space" in err

    def test_absolute_floor_blocks_even_with_high_fraction(
        self, responder, tmp_path, monkeypatch
    ):
        """A 50%-free 1 GiB volume still has < 1 GiB absolute headroom."""
        target = tmp_path / "sample.bin"
        target.write_bytes(b"x" * 1024)

        mib = 1024 ** 2
        monkeypatch.setattr(
            "shutil.disk_usage",
            lambda p: _FakeUsage(total=1024 * mib, used=512 * mib, free=512 * mib),
        )
        err = responder._check_disk_quota(str(target))
        assert err is not None  # 512 MiB free < 1 GiB absolute floor

    def test_disk_usage_failure_refuses(self, responder, tmp_path, monkeypatch):
        target = tmp_path / "sample.bin"
        target.write_bytes(b"x" * 16)

        def _raise(_path):
            raise OSError("permission denied")
        monkeypatch.setattr("shutil.disk_usage", _raise)

        err = responder._check_disk_quota(str(target))
        assert err is not None and "disk_usage failed" in err

    def test_quarantine_refused_when_quota_exhausted(
        self, responder, tmp_path, monkeypatch
    ):
        """End-to-end: quarantine_file returns success=False with a quota error."""
        target = tmp_path / "victim.txt"
        target.write_bytes(b"ransomware payload" * 10)

        gib = 1024 ** 3
        monkeypatch.setattr(
            "shutil.disk_usage",
            lambda p: _FakeUsage(total=10 * gib, used=9.95 * gib, free=0.05 * gib),
        )

        result = responder.quarantine_file(str(target), reason="test")
        assert result["success"] is False
        assert "insufficient disk space" in result["error"]
        # The original file must still exist — we refused before touching it.
        assert target.exists()


class TestAuditLogThreadSafety:
    def test_concurrent_log_action_writes_no_corruption(
        self, responder, tmp_path
    ):
        """Audit P3-15: 50 threads × 10 log actions ⇒ exactly 500 lines.

        Pre-fix the un-locked ``open(..., 'a')`` could interleave partial
        writes from concurrent quarantines.  With ``self._audit_lock`` we
        get atomic line-level writes.
        """
        n_threads, n_calls = 50, 10

        def _worker(idx):
            for j in range(n_calls):
                responder._log_action(
                    f"ACTION_{idx}_{j}",
                    detail="x" * 200,  # long enough to expose interleaving
                )

        threads = [threading.Thread(target=_worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Every line must end with '\n' and contain exactly one timestamp prefix.
        with open(responder.AUDIT_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()
        assert len(lines) == n_threads * n_calls
        for line in lines:
            assert line.endswith("\n")
            # "[YYYY-MM-DD HH:MM:SS] ACTION_..." — exactly one '[' before the
            # action name, no fragments from other writers.
            assert line.count("] ACTION_") == 1, f"corrupted line: {line!r}"
