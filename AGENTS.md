# AGENTS.md — Project Reference for AI Coding Assistants

This file records commands, conventions, and architecture notes useful for
automated agents (Devin, Copilot Workspace, etc.) working on this repo.

---

## Quick Start

```cmd
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

---

## Commands

### Run tests
```cmd
pytest tests --disable-warnings -q
```

### Run tests with coverage
```cmd
pytest tests --cov=core --cov=api --cov-report=term-missing --cov-fail-under=45
```

### Lint
```cmd
ruff check core api tests scripts gui main.py train_model.py
```

### Type check
```cmd
pyright core api
```

### Run the GUI application
```cmd
python main.py
```

### Run the API server
```cmd
uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

### Train model from CLI
```cmd
python main.py --train
```

### CLI scan
```cmd
python main.py --scan PATH
```

---

## Project Structure

```
ransomware-detector-v2/
├── core/               # Business logic: scanner, ML engine, YARA, TI, etc.
│   ├── scanner.py      # Main scan pipeline (8-step, multi-threaded)
│   ├── ml_engine.py    # Random Forest + threshold optimizer + feedback
│   ├── feature_extractor.py  # 16 features for ML
│   ├── yara_engine.py  # YARA signature engine
│   ├── fp_reducer.py   # False-positive reduction (per-extension thresholds)
│   ├── pe_analyzer.py  # PE structural analysis
│   ├── virustotal_client.py  # VT API integration
│   ├── threat_intel_client.py  # MalwareBazaar, ThreatFox, OTX
│   ├── auto_responder.py     # Quarantine, process kill, firewall
│   ├── logger_setup.py       # CANONICAL logging import surface
│   └── logging_setup.py      # JSON formatter (imported by logger_setup)
├── api/                # FastAPI REST API
│   ├── main.py         # App, CORS, rate limiting, auth endpoints
│   ├── auth.py         # JWT + API Key auth, bcrypt, RBAC
│   ├── schemas.py      # Pydantic models
│   └── routers/        # scan.py, status.py, honeypots.py, reports.py
├── gui/                # PyQt5 desktop GUI
│   └── main_window.py  # Main window (2841 lines — known tech debt)
├── scripts/
│   ├── cmd/            # Windows batch/cmd wrapper scripts
│   └── dev/
│       ├── manual_tests/    # Ad-hoc smoke tests (NOT in pytest suite)
│       └── *.py             # Diagnostic helpers
├── tests/              # Official pytest test suite (39 files)
├── data/               # Runtime data (gitignored except template + large binaries)
│   ├── config.json           # Active config (gitignored)
│   ├── config.json.template  # Template for fresh installs
│   ├── malware_hashes.db     # 159 MB SQLite hash store (LFS)
│   └── yara_rules.json       # 3.5 MB compiled YARA rules
├── models/             # ML model files (LFS)
└── web/                # Single-page web dashboard
    └── index.html
```

---

## Key Conventions

### Imports
- Logging: always `from core.logger_setup import get_logger` — do NOT use
  `core.logging_setup` for new code (kept for backward compat only).
- Config: `from core.config_manager import config` then `config.get("key", default)`.

### Scan pipeline order (scanner.py `_scan_single_file`)
1. Whitelist check
2. Local hash DB lookup (thread-local SQLite pool)
3. Feature extraction (16 features)
4. ML prediction (CalibratedClassifierCV Random Forest)
5. FP reduction (per-extension threshold + magic bytes discount)
6. YARA signature scan
7. VirusTotal lookup (HIGH/CRITICAL or binary files)
8. Threat Intelligence correlation (MalwareBazaar, ThreatFox, OTX)

### Named constants (scanner.py)
| Constant | Value | Purpose |
|----------|-------|---------|
| `TEXT_FILE_PROB_CAP` | 0.45 | Max ML prob for text/script files |
| `KNOWN_FORMAT_DISCOUNT` | 0.65 | Multiplier for compressed/media FP reduction |
| `INJECTION_BOOST` | 0.20 | Extra boost when PE injection indicators found |

### Configuration keys
| Key | Default | Description |
|-----|---------|-------------|
| `api.cors_allow_null_origin` | `false` | Allow file:// origin (dev only) |
| `api.global_rate_limit_per_minute` | `120` | Global IP rate limit |
| `api.auth_rate_limit_per_minute` | `10` | Auth endpoint rate limit |
| `ml.class_weight_enc` | `10.0` | Cost of missing ransomware (FN) |
| `ml.class_weight_safe` | `3.0` | Cost of false positive |

---

## Test Coverage Gaps (target: 60%)

Current floor: **45%**. Priority files to add tests for:

| File | Current coverage | Priority |
|------|-----------------|----------|
| `core/scanner.py` | ~23% | HIGH |
| `api/routers/scan.py` | ~8% | HIGH |
| `core/auto_responder.py` | ~37% | HIGH |
| `core/injection_detector.py` | ~23% | MEDIUM |
| `core/dataset_generator.py` | 0% | MEDIUM |
| `core/forensic_exporter.py` | 0% | LOW |
| `core/pdf_reporter.py` | 0% | LOW |
| `core/report_generator.py` | 0% | LOW |

---

## Security Notes

- **Model integrity**: `models/rf_ransomware_detector.joblib.sha256` must stay
  in sync with the model file. The engine verifies SHA256 before loading.
- **JWT secret**: set `RANSOMWARE_JWT_SECRET` env var in production.
  Never rely on the auto-generated fallback in `data/config.json`.
- **Scan roots**: `api.allowed_scan_roots` must be configured before the
  `/api/v1/scan/file` endpoint will accept requests.
- **Malware samples**: `Malware/`, `quarantine/`, `*.quarantined`, `*.elf`
  are gitignored — never commit them.

---

## Git LFS

The following file types are tracked via Git LFS (`.gitattributes`):

```
*.db *.joblib *.pkl *.pickle *.quarantined *.elf *.mp4 *.msi
```

To migrate existing large files in history:
```cmd
git lfs migrate import --include="*.db,*.joblib,*.mp4,*.msi,*.elf,*.quarantined"
```
**Warning**: this rewrites history — coordinate with team before running.
