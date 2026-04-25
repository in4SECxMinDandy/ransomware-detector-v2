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
- `requirements.in` / `requirements-dev.in` source-of-truth files
  (loose specs); `requirements.txt` / `requirements-dev.txt` are now
  emitted as bounded ranges (`>=X,<Y`) and can be regenerated as exact
  pin sets via `pip-compile` if a fully-locked SBOM is needed.
- `docker-compose.yml` for single-host deployments — non-root
  container, named volume for `quarantine/`, `cap_drop: ALL`,
  `no-new-privileges`, JSON-file log driver capped at 30 MiB.
- `tests/test_api_scan_routing.py` — regression tests proving the
  `/api/v1/scan/file` endpoint delegates to
  `Scanner.scan_single_file` and propagates the TI / PE-info fields.

### Changed
- **`core/fp_reducer.py`**: flipped the default of
  `fp_reducer.disable_magic_bytes_discount` to **true** (audit P4-6).
  Feature 15 (`Is Known Benign Format`) in the trained model already
  encodes the magic-bytes signal, so re-applying the 0.70 multiplier
  in post-process double-counted it and broke the calibrated
  probabilities. Operators who wish to restore the legacy behaviour
  can set the flag to `false` in `data/config.json`.
- **`api/routers/scan.py`**: the `/scan/file` endpoint no longer
  open-codes a second copy of the per-file detection pipeline —
  it now constructs `core.scanner.Scanner` and delegates each file
  to `scanner.scan_single_file()`. The Threat Intelligence and
  PE-injection stages, previously skipped on the API path, now run
  through the same code as the GUI / CLI.
- **`core/scanner.py`**: introduced the public
  `Scanner.scan_single_file(path)` entry point that wraps the
  internal `_scan_single_file()`. There is now exactly one
  implementation of the pipeline in the codebase.
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
  `pytest --cov=core --cov=api --cov-fail-under=45` (current actual
  ~47%, target 60%; ratchet up as tests are added), and runs
  `pip-audit` against both runtime and dev requirements.

## [2.0.0] — Initial public-ready snapshot

This release represents the first hardened cut of the project. See
the audit report (`audit-report-v2.md`) for the full inventory of
detection engines, ML pipeline, and security mitigations included.
