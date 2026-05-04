# PROJECT STATUS — Ransomware Detector v2.0
> **Cập nhật:** 2026-05-04 | **Branch:** `main` | **Người thực hiện:** Devin AI (audit + sprint cleanup)

---

## TRẠNG THÁI TỔNG QUAN

| Metric | Trước audit | Sau Sprint 1–5 | Mục tiêu |
|--------|------------|----------------|---------|
| Test coverage | ~45% | **49%** | 60% |
| Tests passing | 322/322 | **322/322** ✅ | — |
| Git repo size (tracked) | ~790 MB+ binaries | Malware untracked, LFS setup | LFS migrate |
| Root directory clutte | 9 test_.py + 11 .cmd + misc | **Cleaned** ✅ | — |
| Security issues (Critical) | 4 open | **2 resolved, 2 remain** | 0 |
| Version string | `1.0.0` (wrong) | **`2.0.0`** ✅ | — |
| Production readiness | Needs Work | Needs Work (improving) | Ready |

---

## LỊCH SỬ SPRINT ĐÃ HOÀN THÀNH

### Sprint 1 — Commit `e0df7f4` (2026-05-04)
> *Quick wins + Critical cleanup*

| # | Nhiệm vụ | Trạng thái | Chi tiết |
|---|---------|-----------|---------|
| 1.1 | Untrack malware/quarantine files | ✅ Done | `Malware/`, `quarantine/`, `ransomeware/` đã xóa khỏi git index. Nội dung vẫn còn local |
| 1.2 | Setup Git LFS | ✅ Done | `.gitattributes` đã tạo. `*.db`, `*.joblib`, `*.quarantined`, `*.elf`, `*.mp4`, `*.msi` → LFS. Model đã convert sang LFS pointer |
| 1.3 | Xóa `ransomeware/` typo dir | ✅ Done | Directory đã xóa, `.elf` file di chuyển về `Malware/` (local only) |
| 1.4 | Fix version string | ✅ Done | `core/__init__.py`: `1.0.0` → `2.0.0` |
| 1.5 | Fix config inconsistency | ✅ Done | `config.json` + template: `class_weight_enc: 1.0` → `10.0`; `default_threshold` float artifact fixed |
| 1.6 | Cleanup root directory | ✅ Done | `files_to_delete.txt` (3453 dòng) xóa. 11 `.cmd/.bat` → `scripts/cmd/`. 9 `test_*.py` → `scripts/dev/manual_tests/` |

---

### Sprint 2 — Commit `ebf0a72` (2026-05-04)
> *Security hardening*

| # | Nhiệm vụ | Trạng thái | Chi tiết |
|---|---------|-----------|---------|
| 2.1 | CORS `"null"` origin opt-in | ✅ Done | `api/main.py`: `"null"` origin chỉ được thêm khi `api.cors_allow_null_origin=true` (default `false`) |
| 2.2 | PII sanitization scan_history | ✅ Done | `training_dataset_builder.py`: `_sanitize_record_paths()` lưu basename-only vào JSONL |
| 2.3 | Global API rate limiting | ✅ Done | `api/main.py`: middleware 120 req/min per-IP; health/ping exempt; config: `api.global_rate_limit_per_minute` |
| 2.4 | Pyright type checking in CI | ✅ Done | `.github/workflows/ci.yml`: bước pyright mới, `continue-on-error: true` (warnings-only) |

---

### Sprint 3 — Commit `ebf0a72` (2026-05-04)
> *Code quality*

| # | Nhiệm vụ | Trạng thái | Chi tiết |
|---|---------|-----------|---------|
| 3.1 | Merge logger/logging setup | ✅ Done | `logger_setup.py` re-exports `configure_logging` + `JsonFormatter`. `logging_setup.py` giữ lại cho backward compat |
| 3.2 | Extract duplicate VT code | ✅ Done | `Scanner._apply_vt_results()` thay 3 đoạn ~12 dòng lặp |
| 3.3 | Extract magic numbers | ✅ Done | `TEXT_FILE_PROB_CAP=0.45`, `KNOWN_FORMAT_DISCOUNT=0.65`, `INJECTION_BOOST=0.20` |
| 3.4 | Fix global warnings suppress | ✅ Done | `ml_engine.py` + `smote_trainer.py`: targeted filters thay blanket ignore |
| 3.5 | Fix YARA fusion security bug | ✅ Done | `apply_vt_risk_fusion`: khi `yara_boosted=True` nhưng match names unknown → fail-safe (không downgrade) |

---

### Sprint 4 — Commit `ebf0a72` (2026-05-04)
> *Performance + file hygiene*

| # | Nhiệm vụ | Trạng thái | Chi tiết |
|---|---------|-----------|---------|
| 4.1 | SQLite connection pool | ✅ Done | `core/scanner.py`: thread-local pool (`_HASH_DB_TLS`), WAL mode, open 1 lần/thread thay vì mỗi file |
| 4.2 | Move root JSON files | ✅ Done | `malware_analysis.json` + `pkg_list.txt` → `data/` |
| 4.3 | Update `.gitignore` | ✅ Done | Thêm entries cho cấu trúc mới, root paths cũ |

---

### Sprint 5 — Commit `ebf0a72` (2026-05-04)
> *Documentation*

| # | Nhiệm vụ | Trạng thái | Chi tiết |
|---|---------|-----------|---------|
| 5.1 | Update `CHANGELOG.md` | ✅ Done | Đầy đủ Sprint 1–5 theo Keep a Changelog format |
| 5.2 | Tạo `AGENTS.md` | ✅ Done | Commands, architecture, conventions, test gaps, security notes |

---

## TEST COVERAGE HIỆN TẠI (49%)

> Floor CI: 45% | Mục tiêu tiếp theo: **60%**

### Modules cần test gấp (ưu tiên cao)

| Module | Coverage | Dòng code | Priority | Lý do |
|--------|---------|-----------|----------|-------|
| `core/scanner.py` | **23%** | 557 | 🔴 HIGH | Core pipeline — mọi scan đi qua đây |
| `api/routers/scan.py` | **8%** | ~150 | 🔴 HIGH | REST API endpoint chính |
| `core/auto_responder.py` | **37%** | 313 | 🔴 HIGH | Privileged actions (quarantine, process kill, firewall) |
| `core/injection_detector.py` | **23%** | 291 | 🟡 MEDIUM | Phát hiện code injection |
| `core/dataset_generator.py` | **0%** | 104 | 🟡 MEDIUM | Sinh synthetic dataset |
| `core/forensic_exporter.py` | **0%** | 123 | 🟡 MEDIUM | — |
| `core/pdf_reporter.py` | **0%** | 94 | 🟠 LOW | — |
| `core/report_generator.py` | **0%** | 143 | 🟠 LOW | — |
| `core/yara_engine.py` | **34%** | 164 | 🟡 MEDIUM | YARA scan engine |
| `core/office_doc_analyzer.py` | **22%** | 390 | 🟡 MEDIUM | Office macro analysis |
| `core/pe_analyzer.py` | **28%** | 338 | 🟡 MEDIUM | PE structural analysis |
| `gui/main_window.py` | **0%** | 2841 | 🔴 HIGH (tech debt) | God class — không có test nào |

### Modules đã có coverage tốt

| Module | Coverage | Ghi chú |
|--------|---------|---------|
| `core/fp_reducer.py` | **88%** | ✅ Tốt |
| `core/config_manager.py` | **82%** | ✅ Tốt |
| `core/external_dataset_builder.py` | **82%** | ✅ Tốt |
| `core/security_utils.py` | **83%** | ✅ Tốt |
| `core/logging_setup.py` | **87%** | ✅ Tốt |
| `core/feature_extractor.py` | **78%** | ✅ Khá |
| `core/ml_engine.py` | **69%** | ✅ Khá |
| `api/auth.py` | ~75% | ✅ Khá |

---

## VẤN ĐỀ CÒN TỒN TẠI

### 🔴 Critical — Cần giải quyết sớm

| # | Vấn đề | File | Tác động | Cách fix |
|---|--------|------|---------|---------|
| C1 | **Git history vẫn chứa ~790MB binary files** | `data/malware_hashes.db` (159MB), `data/full_sha256.txt` (71MB), `full.csv/full.csv` (495MB), quarantine files trong history | Clone repo rất chậm; GitHub có thể từ chối push | Chạy `git lfs migrate import` (rewrite history) — cần coordinate với team |
| C2 | **`full.csv/` directory ở root** (495MB) | `full.csv/full.csv` | Vẫn tracked bình thường | `git rm --cached full.csv/ && echo "full.csv/" >> .gitignore` |

### 🟡 High — Cần làm trong sprint tiếp

| # | Vấn đề | File | Mô tả |
|---|--------|------|-------|
| H1 | **GUI God Class** `main_window.py` 2,841 dòng | `gui/main_window.py` | 0% test coverage, vi phạm SRP, rủi ro regression cao khi thêm features |
| H2 | **Test coverage chỉ 49%**, gate CI là 45% | `tests/` | Cần +11% để đạt mục tiêu 60%. Ưu tiên scanner.py, scan.py router, auto_responder.py |
| H3 | **`_api_test.py`, `_api_test2.py`, `_check_config.py`, `_check_git.py`, `_run_pytest.py`** vẫn ở root | root | 5 file debug/test còn sót, chưa bị ruff scan (excluded trong pyproject.toml) |
| H4 | **`ransomware_files.txt`** ở root | `ransomware_files.txt` | 1680 bytes, không rõ mục đích, chưa move/xóa |

### 🟠 Medium — Sprint sau

| # | Vấn đề | File | Mô tả |
|---|--------|------|-------|
| M1 | **`ml_engine.py` 1,402 dòng** | `core/ml_engine.py` | Training + prediction + feedback + versioning trong 1 file |
| M2 | **Web dashboard `index.html` 529 dòng** single file | `web/index.html` | Không tách components, thiếu CSRF, thiếu a11y |
| M3 | **`debug_csv.py`, `debug_gui.py`** ở root | root | Debug scripts chưa được classify/move |
| M4 | **ADR (Architecture Decision Records)** chưa có | `docs/` | Không có documentation cho các quyết định thiết kế quan trọng |
| M5 | **scan_history.jsonl hiện tại** vẫn chứa PII cũ | `data/scan_history.jsonl` | Fix chỉ áp dụng cho records mới. Records cũ vẫn có full path |
| M6 | **`data/config.json.template` host = `127.0.0.1`** nhưng template Docker cần `0.0.0.0` | template | Dockerfile expose 0.0.0.0 nhưng template có 127.0.0.1 |
| M7 | **CI coverage gate 45% quá thấp** | `.github/workflows/ci.yml` | Nâng lên ≥ 55% khi đã thêm tests |

### 🔵 Low — Backlog

| # | Vấn đề | Mô tả |
|---|--------|-------|
| L1 | `api/main.py` có dòng trắng thừa (dòng 150-152) | Minor formatting |
| L2 | `pyproject.toml` pyright config chỉ include `core/`, không include `api/` | Khai báo không nhất quán với CI step |
| L3 | `PIPELINE_CHI_TIET.md` (38KB) cần verify là up-to-date với code | |
| L4 | `TONG_QUAN_TAI_5GB_VA_TRAINING.md` (25KB) cần verify | |
| L5 | `analyze_malware_samples.py` (10KB) ở root — nên move vào `scripts/` | |
| L6 | `collect_malware_samples.py`, `collect_safe_samples.py`, `filter_ransomware.py`, `restore_ransomware.py` ở root | Nên move vào `scripts/` |
| L7 | `build_auto_dataset.py`, `prepare_dataset.py`, `quick_start_pipeline.py`, `train_model.py` ở root | Nên move vào `scripts/` |
| L8 | CD (Continuous Deployment) chưa có | CI có, nhưng chưa auto-release |
| L9 | OpenAPI schema chưa có versioning strategy | `/api/v1/*` hardcoded |
| L10 | Không có E2E tests cho web dashboard | `web/index.html` |

---

## SPRINT TIẾP THEO — Đề xuất

### Sprint 6 — Git History Cleanup + Root Cleanup (1-2 ngày)
> **Ưu tiên:** Giải quyết C1, C2, H3, L5-L7

```
[ ] C2: git rm --cached full.csv/ + .gitignore
[ ] H3: Move _api_test*.py, _check_*.py, _run_pytest.py → scripts/dev/
[ ] H4: Xóa ransomware_files.txt (hoặc move vào data/)
[ ] L5-L7: Move root scripts → scripts/
        analyze_malware_samples.py → scripts/
        collect_malware_samples.py → scripts/
        collect_safe_samples.py → scripts/
        filter_ransomware.py → scripts/
        restore_ransomware.py → scripts/
        build_auto_dataset.py → scripts/
        prepare_dataset.py → scripts/
        quick_start_pipeline.py → scripts/
        train_model.py → scripts/ (hoặc giữ ở root nếu là CLI entry point)
[ ] C1: (Advanced) git lfs migrate import cho existing large files
        Warning: rewrite history, coordinate với team trước
```

### Sprint 7 — Test Coverage (3-5 ngày)
> **Ưu tiên:** H2 — từ 49% → 60%

```
[ ] Viết tests cho core/scanner.py (target: 50%+)
    - test _scan_single_file happy path
    - test whitelist bypass
    - test local hash match → CRITICAL
    - test VT fallback khi ML fails
    - test YARA boost
    - test FP reduction pipeline
[ ] Viết tests cho api/routers/scan.py (target: 60%+)
    - test POST /scan/file với allowed_scan_roots
    - test path traversal rejection
    - test scan result propagation (TI fields, PE fields)
[ ] Viết tests cho core/auto_responder.py (target: 60%+)
    - test quarantine happy path
    - test disk quota check
    - test process kill (mock)
    - test firewall block/unblock (mock)
[ ] Nâng CI coverage gate: 45% → 55%
```

### Sprint 8 — Code Refactor: ml_engine.py split (2-3 ngày)
> **Ưu tiên:** M1

```
[ ] Tách core/ml_engine.py (1402 dòng) thành:
    - core/ml_predictor.py   — predict(), get_threshold(), get_risk_level()
    - core/ml_trainer.py     — train(), optimize_threshold(), calibrate()
    - core/ml_feedback.py    — add_feedback(), get_feedback_stats(), retrain_from_feedback()
    - core/ml_versioning.py  — backup_model(), list_versions(), restore_version()
    - core/ml_engine.py      — facade: re-export + RansomwareMLEngine class
[ ] Update tất cả imports (không break backward compat)
[ ] Verify tests vẫn pass
```

### Sprint 9 — GUI Refactor (1 tuần)
> **Ưu tiên:** H1

```
[ ] Tách gui/main_window.py (2841 dòng) thành:
    - gui/tabs/tab_scan.py
    - gui/tabs/tab_monitor.py
    - gui/tabs/tab_settings.py
    - gui/tabs/tab_training.py
    - gui/tabs/tab_reports.py
    - gui/app.py — main window shell
[ ] Viết test cho ít nhất 1 tab component
[ ] Verify GUI launches correctly
```

### Sprint 10 — Security: PII cleanup + Docker hardening (1 ngày)
> **Ưu tiên:** M5, M6

```
[ ] M5: Script để sanitize existing scan_history.jsonl (replace full paths với basename)
[ ] M6: Tạo config template riêng cho Docker (host = 0.0.0.0)
        hoặc document rõ sự khác biệt trong AGENTS.md/README
[ ] Review auto_responder.py privilege escalation paths (audit item S8)
```

---

## THỐNG KÊ DỰ ÁN

### Codebase size

| Package | Files | Dòng code | Coverage |
|---------|-------|-----------|---------|
| `core/` | 34 | ~16,600 | 49% |
| `api/` | 6 | ~1,400 | ~45% |
| `gui/` | 8 | ~5,700 | <5% |
| `scripts/` | ~15 | ~4,500 | 0% |
| `tests/` | 39 | ~4,500 | N/A |
| **Tổng** | **~110** | **~32,700** | **49%** |

### Commits trong dự án

```
ebf0a72  feat: Sprint 2-5 — security hardening, code quality, performance
e0df7f4  chore: Sprint 1 cleanup — untrack malware, fix versions, setup LFS
9e17ba7  fix: eliminate FP for legitimate installers and text files
1f9f276  feat: remove minimum sample requirements for ML training
ffb6a3b  fix: feedback pipeline now persists features independently of original files
ba75204  feat: add CRITICAL confirmation flow to feed scan results into ML training
5ccd425  fix: eliminate entropy-only FP and ensure VT always called for HIGH/CRITICAL
2b7aeee  fix: VirusTotal API not called after scan
...
```

### Scoring sau audit (updated)

| Dimension | Trước audit | Sau Sprint 1–5 | Mục tiêu |
|-----------|------------|----------------|---------|
| Architecture | 7/10 | **7/10** | 8/10 |
| Code Quality | 6/10 | **7/10** (+1) | 8/10 |
| Security | 6/10 | **7/10** (+1) | 9/10 |
| ML Pipeline | 7/10 | **7/10** | 8/10 |
| Testing | 5/10 | **5.5/10** (+0.5) | 7/10 |
| API & Web | 7/10 | **7.5/10** (+0.5) | 8/10 |
| Performance | 7/10 | **7.5/10** (+0.5) | 8/10 |
| Documentation | 7/10 | **8/10** (+1) | 9/10 |
| DevOps | 7/10 | **7.5/10** (+0.5) | 8/10 |
| Data Management | 3/10 | **4/10** (+1) | 7/10 |
| Project Hygiene | 4/10 | **6.5/10** (+2.5) | 8/10 |
| **Tổng** | **68/100** | **73/100** (+5) | **85/100** |

---

## HƯỚNG DẪN TIẾP TỤC

### Nếu muốn tiếp tục ngay (lệnh cụ thể)

```bash
# Kiểm tra trạng thái hiện tại
git status
python -m pytest tests -q --disable-warnings

# Sprint 6: xóa full.csv khỏi git
git rm --cached -r "full.csv/"
echo "full.csv/" >> .gitignore
git add .gitignore
git commit -m "chore: remove full.csv from git tracking"

# Sprint 7: chạy coverage để xác định file cần test
python -m pytest tests --cov=core --cov=api --cov-report=html
# Mở htmlcov/index.html để xem line-by-line gaps

# Nâng CI gate sau khi thêm tests
# Sửa --cov-fail-under=45 → --cov-fail-under=55 trong ci.yml
```

### Files quan trọng cần đọc trước khi tiếp tục

| File | Mục đích |
|------|---------|
| `AGENTS.md` | Commands, conventions, architecture reference |
| `CHANGELOG.md` | Lịch sử thay đổi |
| `core/scanner.py` | Pipeline scan chính — đọc trước khi sửa bất kỳ detection logic |
| `tests/conftest.py` | Shared fixtures — đọc trước khi viết test mới |
| `data/config.json` | Config hiện tại (gitignored, chứa API keys) |
| `.github/workflows/ci.yml` | CI pipeline |

---

*File này được tạo tự động bởi Devin AI sau khi hoàn thành Sprint 1–5.*  
*Cập nhật file này mỗi khi hoàn thành một sprint mới.*
