# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `scripts/dev/` package with curated diagnostic helpers:
  `probe_threat_intel.py`, `check_config.py`, `check_git_tracking.py`,
  `run_pytest_capture.py`, `gui_diagnostic.py`. All probes load API
  keys from environment variables only.
- `CONTRIBUTING.md` with setup, lint/type/test workflow, commit
  conventions, and security-issue routing.
- `CHANGELOG.md` (this file).

### Changed
- `core/auto_responder.py`: `_safe_quarantine_move` now performs
  `copy2 → fsync → SHA256 verify → delete with retries` to make
  cross-volume quarantine durable against partial writes.
- `core/auto_responder.py`: `unblock_network` mirrors `block_network`
  sanitisation so firewall rules created at block-time are correctly
  located at unblock-time (prevents orphan-rule accumulation / DoS).
- `core/auto_responder.py`: `_log_action` writes serialised through a
  `threading.Lock` to keep audit-log entries atomic under concurrent
  quarantine actions.
- `core/auto_responder.py`: added `_check_disk_quota` so quarantine
  refuses to write when free space would drop under the configured
  threshold (default 10%).
- Hardened type-safety across the codebase: pyright now reports
  **0 errors / 0 warnings**. Optional dependencies (`psutil`, `yara`,
  `stix2`, `oletools`, `fitz`, `python-docx`, `python-pptx`, `openpyxl`,
  `imblearn`, `win10toast`, `plyer`) are wrapped in
  `if TYPE_CHECKING` shims with graceful runtime fallbacks.
- ML training (`core/ml_engine.py`) now imports `pandas` at module
  scope, casts `auc` / `fpr` to `float` for JSON-safe metrics, and
  passes `np.asarray(...)` into SMOTE to satisfy stub typing.
- `Dockerfile` upgraded to multi-stage `python:3.11-slim-bookworm`
  with a non-root `app` user, `tini` PID 1, and a HEALTHCHECK that
  treats `401` from `/health` as a healthy authenticated endpoint.

### Deprecated
- Root-level helper scripts (`_api_test.py`, `_api_test2.py`,
  `_check_config.py`, `_check_git.py`, `_run_pytest.py`,
  `debug_gui.py`, `test_injection.py`) have been replaced with
  deprecation stubs that point at the new `scripts/dev/` modules.
  These stubs will be removed in a future release.

### Security
- **Removed leaked API keys** from `_api_test.py` and `_api_test2.py`
  (ThreatFox + AlienVault OTX). The replacement
  `scripts/dev/probe_threat_intel.py` reads keys from
  `THREATFOX_API_KEY` / `OTX_API_KEY` only.
  > **⚠️ Operator action required**: rotate the previously committed
  > ThreatFox and OTX API keys — they remain visible in the git
  > history of any clone made before this release.
- Confirmed `.gitignore` excludes `ransomeware/`, `quarantine/`,
  `*.quarantined`, `*.elf`, and `debug-*.log`. No malware artefacts
  are present in the current working tree.

### Tooling
- CI (`.github/workflows/ci.yml`): runs `ruff` over
  `core api tests scripts gui main.py train_model.py`, enforces
  `pytest --cov=core --cov=api --cov-fail-under=60`, and runs
  `pip-audit` against both runtime and dev requirements.

## [2.0.0] — Initial public-ready snapshot

This release represents the first hardened cut of the project. See
the audit report (`audit-report-v2.md`) for the full inventory of
detection engines, ML pipeline, and security mitigations included.
