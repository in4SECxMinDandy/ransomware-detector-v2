"""
test_virustotal_client.py
============================
Unit tests for VirusTotal API client.
"""

import sys
import pytest
import time
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_virustotal_client_init():
    """Test VirusTotalClient initialization."""
    from core.virustotal_client import VirusTotalClient

    # Without API key
    vt = VirusTotalClient("")
    assert vt.api_key == ""
    assert not vt.is_configured()

    # With API key
    vt = VirusTotalClient("test_api_key_12345678901234567890")
    assert vt.is_configured()


def test_rate_limiter():
    """Test rate limiter."""
    from core.virustotal_client import RateLimiter

    limiter = RateLimiter(rpm=4)

    # First request should not wait
    start = time.time()
    limiter.wait()
    elapsed = time.time() - start
    assert elapsed < 0.5  # Should be near instant


def test_vt_file_report_dataclass():
    """Test VTFileReport dataclass."""
    from core.virustotal_client import VTFileReport

    report = VTFileReport(
        sha256="a" * 64,
        md5="b" * 32,
        sha1="c" * 40,
        file_type="PE",
        file_size=1024000,
        malicious_count=15,
        suspicious_count=3,
        total_engines=72,
    )

    assert report.is_malicious(threshold=10)
    assert not report.is_malicious(threshold=20)
    assert report.is_suspicious(threshold=2)
    assert "15/72" in report.get_badge()
    assert report.get_risk_color() == "red"  # 15 >= 10


def test_vt_report_risk_colors():
    """Test risk color determination."""
    from core.virustotal_client import VTFileReport

    # Red: >= 10
    report = VTFileReport(sha256="a", md5="b", sha1="c",
                         file_type="", file_size=0,
                         malicious_count=12, total_engines=70)
    assert report.get_risk_color() == "red"

    # Orange: >= 5
    report.malicious_count = 7
    assert report.get_risk_color() == "orange"

    # Yellow: >= 2
    report.malicious_count = 3
    assert report.get_risk_color() == "yellow"

    # Green: < 2
    report.malicious_count = 0
    report.suspicious_count = 0
    assert report.get_risk_color() == "green"


def test_cache_entry_expiry():
    """Test CacheEntry expiration check."""
    from core.virustotal_client import CacheEntry
    from datetime import datetime, timedelta

    # Not expired
    entry = CacheEntry(
        sha256="abc",
        report={},
        cached_at=datetime.now().isoformat(),
        expires_at=(datetime.now() + timedelta(hours=24)).isoformat(),
    )
    assert not entry.is_expired()

    # Expired
    entry2 = CacheEntry(
        sha256="def",
        report={},
        cached_at=datetime.now().isoformat(),
        expires_at=(datetime.now() - timedelta(hours=1)).isoformat(),
    )
    assert entry2.is_expired()


def test_compute_sha256(temp_dir):
    """Test SHA256 computation in VT client."""
    from core.virustotal_client import VirusTotalClient

    test_file = temp_dir / "test.bin"
    test_file.write_bytes(b"Hello World")

    sha = VirusTotalClient._compute_sha256(str(test_file))
    assert len(sha) == 64
    assert sha.isalnum()


def test_virustotal_client_stats():
    """Test client statistics tracking."""
    from core.virustotal_client import VirusTotalClient

    vt = VirusTotalClient("test_key_1234567890")
    stats = vt.get_stats()

    assert "total_queries" in stats
    assert "cache_hits" in stats
    assert "cache_misses" in stats
    assert "cache_size" in stats
    assert "rate_limit_wait" in stats


def test_clear_cache():
    """Test cache clearing."""
    from core.virustotal_client import VirusTotalClient

    vt = VirusTotalClient("test_key")

    # Manually add to cache (via internal method)
    vt._cache["test_hash"] = MagicMock()

    assert len(vt._cache) > 0

    # Clear cache
    vt.clear_cache()

    assert len(vt._cache) == 0


def test_get_file_report_not_configured(temp_dir):
    """Test that querying without API key returns None gracefully."""
    from core.virustotal_client import VirusTotalClient

    vt = VirusTotalClient("")

    # Should not make any requests, just return None
    result = vt.get_file_report("a" * 64)
    assert result is None

    stats = vt.get_stats()
    assert stats["errors"] == 1  # API request made but returns 401 (no key)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
