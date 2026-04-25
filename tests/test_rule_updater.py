"""Tests for core/rule_updater.py — Phase 1 hardening (SHA pinning, HTTPS-only)."""

from __future__ import annotations

import hashlib

import pytest


@pytest.fixture
def updater(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from core.rule_updater import YARARuleUpdater
    return YARARuleUpdater()


def _fake_response(payload: bytes):
    """Minimal stand-in for urllib.request.urlopen()."""
    class FakeResp:
        def read(self, n: int = -1):
            return payload if n == -1 else payload[:n]
    return FakeResp()


def test_fetch_refuses_http_url(updater):
    assert updater.fetch_and_validate("http://example.com/evil.yar") is False


def test_fetch_accepts_pinned_sha(updater, monkeypatch):
    rule_text = b"rule example { strings: $a = \"x\" condition: $a }"
    expected = hashlib.sha256(rule_text).hexdigest()

    monkeypatch.setattr("urllib.request.urlopen",
                        lambda url, timeout=30: _fake_response(rule_text))
    monkeypatch.setattr(updater, "_compile_rules", lambda content: True)

    assert updater.fetch_and_validate(
        "https://example.com/x.yar", expected_sha256=expected,
    ) is True


def test_fetch_rejects_sha_mismatch(updater, monkeypatch):
    rule_text = b"rule mismatch { condition: false }"

    monkeypatch.setattr("urllib.request.urlopen",
                        lambda url, timeout=30: _fake_response(rule_text))
    monkeypatch.setattr(updater, "_compile_rules", lambda content: True)

    bad_sha = "0" * 64
    assert updater.fetch_and_validate(
        "https://example.com/x.yar", expected_sha256=bad_sha,
    ) is False


def test_fetch_payload_size_capped(updater, monkeypatch):
    too_big = b"A" * (16 * 1024 * 1024 + 100)
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda url, timeout=30: _fake_response(too_big))
    monkeypatch.setattr(updater, "_compile_rules", lambda content: True)

    assert updater.fetch_and_validate("https://example.com/big.yar") is False


def test_default_sources_disabled_until_pinned(updater):
    """Hardening: default community sources must be disabled out of the box."""
    for src in updater.SOURCES:
        assert src["enabled"] is False, (
            "Community YARA sources must be opt-in after the operator pins a SHA"
        )
