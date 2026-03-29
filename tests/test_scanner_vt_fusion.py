"""Tests for VirusTotal + ML risk fusion in scanner."""

from core.scanner import apply_vt_risk_fusion, VT_BINARY_EXTENSIONS


def test_apply_vt_risk_fusion_downgrades_critical_when_clean_vt():
    new_risk, note = apply_vt_risk_fusion(
        "CRITICAL",
        vt_malicious=0,
        vt_suspicious=0,
        vt_total_engines=68,
        vt_error="",
        fusion_min_engines=40,
        fusion_max_suspicious=2,
        fusion_downgrade=True,
        yara_boosted=False,
        injection_found=False,
    )
    assert new_risk == "MEDIUM"
    assert "VT_consensus_clean" in note


def test_apply_vt_risk_fusion_skips_when_malicious_detections():
    new_risk, note = apply_vt_risk_fusion(
        "CRITICAL",
        vt_malicious=3,
        vt_suspicious=0,
        vt_total_engines=68,
        vt_error="",
        fusion_min_engines=40,
        fusion_max_suspicious=2,
        fusion_downgrade=True,
        yara_boosted=False,
        injection_found=False,
    )
    assert new_risk == "CRITICAL"
    assert note == ""


def test_apply_vt_risk_fusion_skips_on_yara():
    new_risk, note = apply_vt_risk_fusion(
        "CRITICAL",
        vt_malicious=0,
        vt_suspicious=0,
        vt_total_engines=68,
        vt_error="",
        fusion_min_engines=40,
        fusion_max_suspicious=2,
        fusion_downgrade=True,
        yara_boosted=True,
        injection_found=False,
    )
    assert new_risk == "CRITICAL"
    assert note == ""


def test_apply_vt_risk_fusion_skips_low_engine_count():
    new_risk, note = apply_vt_risk_fusion(
        "CRITICAL",
        vt_malicious=0,
        vt_suspicious=0,
        vt_total_engines=12,
        vt_error="",
        fusion_min_engines=40,
        fusion_max_suspicious=2,
        fusion_downgrade=True,
        yara_boosted=False,
        injection_found=False,
    )
    assert new_risk == "CRITICAL"
    assert note == ""


def test_vt_binary_extensions_contains_exe():
    assert ".exe" in VT_BINARY_EXTENSIONS
    assert ".dll" in VT_BINARY_EXTENSIONS
