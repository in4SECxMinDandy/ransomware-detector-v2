# scripts/dev/

Throwaway diagnostic / probe scripts used during development.

> ⚠️ **Not part of the public API.** These files are excluded from
> `ruff` strict mode for the package surface and are *not* picked up
> by `pytest`. Treat them as one-off scratchpads.

## Inventory

| Script | Purpose |
| ------ | ------- |
| `probe_threat_intel.py` | Smoke-test MalwareBazaar / ThreatFox / OTX connectivity (replaces `_api_test*.py`). Reads API keys from `THREATFOX_API_KEY`, `OTX_API_KEY` env vars — never hard-code keys. |
| `check_config.py`       | Quick `data/config.json` sanity check (existence + valid JSON). |
| `check_git_tracking.py` | Verifies that `ransomeware/`, `quarantine/`, `*.quarantined` are *not* tracked by git. |
| `run_pytest_capture.py` | Wrapper that runs `pytest` and dumps stdout/stderr to a text file (useful when invoked from a tool that can't capture interactive terminal output). |
| `gui_diagnostic.py`     | Manual GUI smoke tests (CTk window, import path, launch). |

## Usage

```cmd
:: Run from repo root
python -m scripts.dev.probe_threat_intel
python -m scripts.dev.check_config
python -m scripts.dev.check_git_tracking
python -m scripts.dev.run_pytest_capture tests/test_scanner.py
python -m scripts.dev.gui_diagnostic
```

## Migration note

The historical scripts at the repository root (`_api_test.py`,
`_api_test2.py`, `_check_config.py`, `_check_git.py`,
`_run_pytest.py`, `debug_gui.py`) were superseded by the modules in
this folder. The originals have been emptied to a deprecation stub —
delete them once your local workflows have been updated.
