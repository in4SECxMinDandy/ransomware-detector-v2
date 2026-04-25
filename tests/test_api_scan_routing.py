"""
test_api_scan_routing.py
========================
Audit P1-Code-Quality regression test.

Pre-fix the ``/api/v1/scan/file`` endpoint open-coded its own copy of
the per-file detection pipeline that was missing the
``threat_intel_client`` and PE-injection stages. After the refactor
the endpoint must delegate to ``core.scanner.Scanner.scan_single_file``
so the same pipeline runs whether the caller is the GUI, the CLI or
the REST API.

Strategy: spy on ``Scanner.scan_single_file`` via monkeypatch and
assert the API actually invokes it for every collected file, *and*
that fields produced only by the unified pipeline (``ti_available``,
``pe_info``) are propagated through the JSON response.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Any, List

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient


# ─── Helpers ──────────────────────────────────────────────────────────────────

_TEST_USERNAME = "scan_routing_admin"
_TEST_PASSWORD = "ScanRoute123!@#"


@pytest.fixture
def api_client():
    try:
        from api.main import app
    except ImportError:
        pytest.skip("FastAPI app not available")
    return TestClient(app)


@pytest.fixture
def admin_token(api_client):
    """Inject a transient admin into config, return a Bearer token,
    restore previous state on teardown.
    """
    from core import config_manager as cm
    from api.auth import _hash_password

    api_cfg = cm.config._config["api"]
    original_users = api_cfg.get("users", {}).copy()
    api_cfg["users"] = {
        _TEST_USERNAME: {
            "username": _TEST_USERNAME,
            "hashed_password": _hash_password(_TEST_PASSWORD),
            "role": "admin",
            "disabled": False,
        }
    }
    try:
        login = api_client.post(
            "/api/v1/auth/token",
            data={"username": _TEST_USERNAME, "password": _TEST_PASSWORD},
        )
        assert login.status_code == 200, login.text
        yield login.json()["access_token"]
    finally:
        api_cfg["users"] = original_users


@pytest.fixture
def scan_target_dir(tmp_path, monkeypatch):
    """Return an allowed scan root populated with two innocent files.

    Allowlist (``api.allowed_scan_roots``) is patched to permit only
    this directory so we exercise the real path-traversal guard.
    """
    target = tmp_path / "scan_root"
    target.mkdir()
    (target / "alpha.bin").write_bytes(b"hello world\n")
    (target / "beta.bin").write_bytes(b"\x00" * 64)

    from core import config_manager as cm
    monkeypatch.setitem(
        cm.config._config["api"], "allowed_scan_roots", [str(target)],
    )
    return str(target)


@pytest.fixture
def fake_scan_result_dict() -> Dict[str, Any]:
    """Minimal ScanResult.to_dict()-shaped payload.

    Includes the TI/PE keys that the legacy duplicated pipeline used
    to drop. The presence of these keys in the response is what proves
    the API now goes through Scanner.
    """
    return {
        "path": "<filled_in_per_call>",
        "filename": "<filled_in_per_call>",
        "size": 64,
        "extension": ".bin",
        "label": 0,
        "probability": 0.10,
        "risk_level": "SAFE",
        "entropy": 1.5,
        "scan_time_ms": 1.0,
        "error": None,
        "raw_probability": 0.10,
        "fp_adjusted": False,
        "effective_threshold": 0.65,
        "fp_reason": "delegated_to_scanner",
        "sha256": "a" * 64,
        "vt_available": False,
        "vt_malicious_count": 0,
        "vt_suspicious_count": 0,
        "vt_total_engines": 0,
        "vt_detection_ratio": "0/0",
        "vt_permalink": "",
        "vt_from_cache": False,
        "vt_error": "",
        "vt_pending": False,
        # Keys that ONLY the unified pipeline produces — proof of routing.
        "ti_available": True,
        "ti_mb_available": False,
        "ti_mb_family": "",
        "ti_mb_signature": "",
        "ti_mb_first_seen": "",
        "ti_mb_tags": [],
        "ti_mb_delivery_method": "",
        "ti_tf_available": False,
        "ti_tf_threat_type": "",
        "ti_tf_malware_family": "",
        "ti_tf_confidence": 0,
        "ti_tf_tags": [],
        "ti_otx_available": False,
        "ti_otx_pulse_count": 0,
        "ti_otx_pulse_names": [],
        "ti_otx_analysis_metadata": {},
        "ti_error": "",
        "pe_info": {"rwx_sections": [], "suspicious_sections": [], "is_packed": False},
        "yara_boosted": False,
        "yara_match_count": 0,
        "yara_rule_names": [],
        "yara_severities": [],
        "features_b64": "",
    }


# ─── Tests ────────────────────────────────────────────────────────────────────

class TestScanFileGoesThroughScanner:
    def test_endpoint_calls_scanner_scan_single_file(
        self,
        api_client,
        admin_token,
        scan_target_dir,
        fake_scan_result_dict,
        monkeypatch,
    ):
        """``POST /scan/file`` must invoke ``Scanner.scan_single_file``
        for every collected file. Old duplicate pipeline never did.
        """
        from core import scanner as _scanner_mod

        called_paths: List[str] = []

        def _fake_scan_single_file(self, file_path: str):
            called_paths.append(file_path)
            # Build a fresh ScanResult populated from the dict so the
            # router's ``to_dict()`` round-trip works without monkey-
            # patching ScanResult internals.
            sr = _scanner_mod.ScanResult(file_path)
            payload = dict(fake_scan_result_dict)
            payload["path"] = file_path
            payload["filename"] = Path(file_path).name
            for k, v in payload.items():
                if k in sr.__slots__:
                    setattr(sr, k, v)
            return sr

        monkeypatch.setattr(
            _scanner_mod.Scanner, "scan_single_file",
            _fake_scan_single_file, raising=True,
        )

        resp = api_client.post(
            "/api/v1/scan/file",
            headers={"Authorization": f"Bearer {admin_token}"},
            data={"directory": scan_target_dir, "recursive": "true"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()

        # Both files were routed through Scanner exactly once.
        assert len(called_paths) == 2
        assert {Path(p).name for p in called_paths} == {"alpha.bin", "beta.bin"}

        # The unified-pipeline-only keys made it into the response —
        # this is the bit that the old duplicated implementation
        # silently dropped.
        for entry in body["results"]:
            assert "ti_available" in entry, "TI fields missing → API still duplicates pipeline"
            assert entry["ti_available"] is True
            assert "pe_info" in entry
            # threat_level is the legacy-compatibility mirror of risk_level.
            assert entry.get("threat_level") == entry.get("risk_level")

        assert body["summary"]["clean"] == 2
        assert body["threats_found"] == 0

    def test_pipeline_crash_is_isolated_to_one_file(
        self,
        api_client,
        admin_token,
        scan_target_dir,
        monkeypatch,
    ):
        """If ``scan_single_file`` raises for one file the other files
        must still be scanned and the failure surfaced as an ERROR row.
        """
        from core import scanner as _scanner_mod

        call_idx = {"n": 0}

        def _flaky(self, file_path: str):
            call_idx["n"] += 1
            if call_idx["n"] == 1:
                raise RuntimeError("simulated upstream failure")
            sr = _scanner_mod.ScanResult(file_path)
            sr.risk_level = "SAFE"
            return sr

        monkeypatch.setattr(
            _scanner_mod.Scanner, "scan_single_file", _flaky, raising=True,
        )

        resp = api_client.post(
            "/api/v1/scan/file",
            headers={"Authorization": f"Bearer {admin_token}"},
            data={"directory": scan_target_dir, "recursive": "true"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()

        threat_levels = [r["threat_level"] for r in body["results"]]
        assert "ERROR" in threat_levels
        assert "SAFE" in threat_levels
        assert body["summary"]["errors"] == 1


class TestScanFileAuthAndAllowlist:
    def test_requires_auth(self, api_client):
        resp = api_client.post(
            "/api/v1/scan/file",
            data={"directory": "C:/", "recursive": "true"},
        )
        assert resp.status_code == 401

    def test_rejects_path_outside_allowlist(
        self, api_client, admin_token, tmp_path, monkeypatch
    ):
        from core import config_manager as cm
        # Allowlist points elsewhere.
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        forbidden = tmp_path / "forbidden"
        forbidden.mkdir()
        monkeypatch.setitem(
            cm.config._config["api"], "allowed_scan_roots", [str(allowed)],
        )

        resp = api_client.post(
            "/api/v1/scan/file",
            headers={"Authorization": f"Bearer {admin_token}"},
            data={"directory": str(forbidden), "recursive": "true"},
        )
        assert resp.status_code == 403
