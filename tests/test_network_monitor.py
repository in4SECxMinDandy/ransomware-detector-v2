"""
test_network_monitor.py
=======================
Audit P2-12 regression tests for ``core.network_monitor.NetworkAnalyzer``.

Focused on the pure-Python heuristics — DGA entropy, beacon CoV, threat-
intel blocklist, and the new CDN whitelist (audit P4-11) — without
touching live ``psutil`` connections.
"""

import json
import math

import pytest

from core.network_monitor import NetworkAnalyzer


@pytest.fixture
def analyzer(tmp_path, monkeypatch):
    """A NetworkAnalyzer pointed at an empty blocklist."""
    blocklist = tmp_path / "feodo_ips.json"
    blocklist.write_text(json.dumps({"ips": []}))
    monkeypatch.setattr(NetworkAnalyzer, "FEODO_BLOCKLIST", str(blocklist))
    return NetworkAnalyzer()


# ─── DGA detection ────────────────────────────────────────────────────────────

class TestDgaDetection:
    def test_short_random_label_flagged(self, analyzer):
        """High-entropy random label crosses the 0.60 normalised threshold.

        Entropy normalisation = -Σ p·log2(p) / log2(256) (=8). For uniformly
        distributed labels, entropy_norm = log2(distinct_chars)/8.  We need
        ≥0.60 ⇒ ≥2^(0.60·8) = 2^4.8 ≈ 27.86 ⇒ at least 28 distinct chars.
        Use 32 distinct lower-case letters/digits, each appearing once.
        """
        # 32 distinct chars (a-z + 0-5), each unique ⇒ entropy = log2(32)/8 = 0.625
        label = "abcdefghijklmnopqrstuvwxyz012345"
        assert analyzer.detect_dga_domain(label + ".xyz") is True

    def test_low_entropy_label_not_flagged(self, analyzer):
        """A real word has low entropy and must NOT be flagged."""
        assert analyzer.detect_dga_domain("google.com") is False
        assert analyzer.detect_dga_domain("microsoft.com") is False

    def test_empty_or_invalid_domain(self, analyzer):
        assert analyzer.detect_dga_domain("") is False
        assert analyzer.detect_dga_domain("localhost") is False  # 1 part

    def test_cdn_subdomain_whitelisted_p4_11(self, analyzer):
        """High-entropy CDN subdomains must be exempted (audit P4-11)."""
        # These hosts have high-entropy labels (account / region IDs) but
        # are legitimate; pre-fix they tripped the detector.
        for host in [
            "d1a2b3c4d5e6f7.cloudfront.net",
            "abc123xyz789-mybucket.s3.amazonaws.com",
            "a1b2c3d4e5f6.akamaihd.net",
            "abcdef1234567890.githubusercontent.com",
            "x9y8z7w6.sentry.io",
        ]:
            assert analyzer.detect_dga_domain(host) is False, (
                f"{host} should be whitelisted but was flagged as DGA"
            )

    def test_bare_whitelist_suffix_not_flagged(self, analyzer):
        """The suffix itself must also be whitelisted, not just subdomains."""
        assert analyzer._is_whitelisted_domain("cloudfront.net") is True
        assert analyzer._is_whitelisted_domain("cloudfront.NET") is True  # case-insensitive

    def test_lookalike_suffix_not_whitelisted(self, analyzer):
        """``evilcloudfront.net`` must NOT match ``cloudfront.net``."""
        assert analyzer._is_whitelisted_domain("evilcloudfront.net") is False


# ─── Beacon detection ─────────────────────────────────────────────────────────

class TestBeaconDetection:
    def test_too_few_samples_returns_false(self, analyzer):
        assert analyzer.detect_beacon([1.0, 2.0]) is False

    def test_perfectly_regular_intervals_flagged(self, analyzer):
        """CoV ~0 < 0.10 ⇒ beacon."""
        # 60s interval, 6 calls — covariance is 0.
        timestamps = [i * 60.0 for i in range(6)]
        assert analyzer.detect_beacon(timestamps) is True

    def test_irregular_intervals_not_flagged(self, analyzer):
        """Human browsing intervals have CoV ≫ 0.10."""
        timestamps = [0.0, 5.0, 65.0, 80.0, 200.0, 210.0]
        assert analyzer.detect_beacon(timestamps) is False

    def test_zero_mean_interval_short_circuits(self, analyzer):
        # All timestamps identical ⇒ mean_interval == 0 ⇒ early False.
        assert analyzer.detect_beacon([10.0] * 5) is False


# ─── Threat intel blocklist ───────────────────────────────────────────────────

class TestThreatIntel:
    def test_known_bad_ip_match(self, tmp_path, monkeypatch):
        blocklist = tmp_path / "feodo_ips.json"
        blocklist.write_text(json.dumps({"ips": ["1.2.3.4", "5.6.7.8"]}))
        monkeypatch.setattr(NetworkAnalyzer, "FEODO_BLOCKLIST", str(blocklist))
        a = NetworkAnalyzer()

        result = a.check_threat_intel("1.2.3.4")
        assert result is not None
        assert result["ip"] == "1.2.3.4"
        assert result["source"] == "Feodo Tracker"

    def test_unknown_ip_returns_none(self, analyzer):
        assert analyzer.check_threat_intel("8.8.8.8") is None

    def test_empty_ip_returns_none(self, analyzer):
        assert analyzer.check_threat_intel("") is None


# ─── Entropy helper sanity ────────────────────────────────────────────────────

class TestEntropyMath:
    def test_normalised_range(self, analyzer):
        # Worst-case (every byte different) approaches 1.0; mono is 0.0.
        assert analyzer._calculate_entropy("") == 0.0
        assert analyzer._calculate_entropy("aaaa") == 0.0
        assert analyzer._calculate_entropy("a" * 256) == 0.0

    def test_entropy_bounded_by_one(self, analyzer):
        # 26 distinct lowercase letters ⇒ entropy = log2(26)/8 ≈ 0.587.
        e = analyzer._calculate_entropy("abcdefghijklmnopqrstuvwxyz")
        assert 0.0 < e <= 1.0
        # Sanity vs. the analytical value.
        assert math.isclose(e, math.log2(26) / 8.0, rel_tol=1e-6)
