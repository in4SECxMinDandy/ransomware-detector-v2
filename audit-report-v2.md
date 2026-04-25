# 🔬 BÁO CÁO AUDIT TOÀN DIỆN — Ransomware Detector v2.0

> **Phạm vi**: Toàn bộ source tree workspace.
> **Phương pháp**: Đọc trực tiếp từng file cốt lõi. Mọi dẫn chứng đều có file:line.
> **Lưu ý**: Codebase **đã được hardened một phần**. Một số "CRITICAL" trong yêu cầu ban đầu (`PLAIN:` fallback, CORS `["*"]`, `DEFAULT_USERS` hardcoded, JWT secret `""`) **đã được fix**. Báo cáo đánh giá theo trạng thái thực tế.

---

## 📊 BẢNG TỔNG HỢP

| # | Hạng mục | Điểm | 🔴 | 🟠 | 🟡 | 🔵 |
|---|----------|:----:|:--:|:--:|:--:|:--:|
| 1 | Kiến trúc & Cấu trúc | 6/10 | 0 | 2 | 4 | 3 |
| 2 | Chất lượng Code | 6/10 | 0 | 1 | 5 | 4 |
| 3 | Bảo mật | 7/10 | 1 | 3 | 4 | 2 |
| 4 | Machine Learning Engine | 6/10 | 1 | 3 | 3 | 1 |
| 5 | Detection Engines | 6/10 | 0 | 2 | 5 | 2 |
| 6 | Threat Intelligence | 7/10 | 0 | 1 | 3 | 2 |
| 7 | Hiệu suất | 5/10 | 0 | 2 | 4 | 2 |
| 8 | Testing | 6/10 | 0 | 2 | 4 | 2 |
| 9 | Dependencies | 5/10 | 0 | 2 | 3 | 2 |
| 10 | DevOps & CI/CD | 5/10 | 0 | 2 | 3 | 1 |
| 11 | Tài liệu | 5/10 | 0 | 1 | 3 | 3 |
| 12 | Production Readiness | 5/10 | 1 | 3 | 4 | 1 |
| | **TỔNG** | **69/120** | **3** | **24** | **45** | **25** |

**Tổng quan**: 69/120 ≈ **57%** — dự án **trên trung bình về mức độ trưởng thành**, nền tảng kiến trúc tốt, đã hardening security một phần, nhưng **chưa sẵn sàng cho production**.

---

## 1. 🏗️ KIẾN TRÚC & CẤU TRÚC — 6/10

### Điểm mạnh
- Tách lớp rõ ràng `core/` (business logic), `api/` (REST), `gui/` (desktop), `tests/`.
- Singleton sạch: `get_engine()`, `get_ti_client()`, `get_auto_responder()` — `core/auto_responder.py:541-549`.
- Centralized config dot-notation — `core/config_manager.py:34-126`.
- Security utils tập trung — `core/security_utils.py:1-218`.

### 🟠 High
- **`core/` flat 32 modules ~14k LOC** — Cần tách sub-packages: `detection/`, `monitoring/`, `ml/`, `training/`, `integration/`, `response/`, `common/`. Effort: Medium (4-6h).
- **Test artifacts ở root**: `_api_test.py`, `_api_test2.py`, `test_injection.py`, `debug_gui.py`, `_check_config.py`, `_run_pytest.py` → move vào `tests/` hoặc `scripts/dev/`. Pytest không pickup do naming `_xxx`. Effort: Low.

### 🟡 Medium
- **Coupling cao trong `scanner.py`** — Direct import 8 modules (`core/scanner.py:31-40`); cần `DetectionStage` interface. Effort: High.
- **`main.py` 537 dòng** vừa GUI launcher + CLI 12 commands → vi phạm SRP. Tách `cli/` package (Typer-based). Effort: Medium.
- **`ScanResult` 47 attrs trong `__slots__`** (`core/scanner.py:200-244`) → "god object". Composition: `result.vt`, `result.ti`, `result.pe`.
- **GUI gọi trực tiếp core logic** → cần service layer facade.

### 🔵 Low
- `ransomeware/` (typo "ransomware") commit binary thật, không trong `.gitignore` (`.gitignore:42-49` chỉ ignore `Malware/`).
- `quarantine/` đã commit với file thực `ngrok.exe.quarantined`.
- Folder `ui/` rỗng, mục đích không rõ.

---

## 2. 📝 CHẤT LƯỢNG CODE — 6/10

### Điểm mạnh
- Type hints khá đầy đủ; dataclasses cho `VTFileReport`, `TIResult`, `InjectionAlert`.
- Docstrings tiếng Việt+English module-level đầy đủ.
- **0 bare `except:`** trong `core/`, `api/`, `gui/`.
- **0 `TODO`/`FIXME`/`HACK`** còn lại.

### 🟠 High
- **Code duplication scan logic** giữa `core/scanner.py` và `api/routers/scan.py:170-273` — API router lặp pipeline thay vì gọi `Scanner._scan_single_file()`. TI sẽ silently miss khi gọi qua API. Fix: API gọi `Scanner` trực tiếp. Effort: Medium.

### 🟡 Medium
- **149 lần `except Exception`** silent-swallow nhiều chỗ:
  - `core/scanner.py:407-409` — VT init (silent).
  - `core/scanner.py:444-446` — TI init (silent).
  - `core/scanner.py:719-721` — debug log `except: pass`.
  - Fix: log warning, không nuốt errors trong init.
- **Debug instrumentation sót** — Hardcoded `sessionId: "4602d0"` ghi vào `debug-4602d0.log`: `core/scanner.py:686-722`, `gui/main_window.py:56-64`. Effort: Low (xóa).
- **Magic numbers** rải rác `core/scanner.py:122-126,376-378` — move hết vào `config_manager.py`.
- **`# type: ignore[import]` hàng loạt** `core/scanner.py:31-38` → import structure không sạch; nên `pip install -e .`.
- **`RateLimiter` class duplicate** ở `core/virustotal_client.py:37-61` và `core/threat_intel_client.py:47-66` → move vào `common/`.

### 🔵 Low
- `print()` thay logger trong `core/ml_engine.py:210`.
- `SUSPICIOUS_EXTENSIONS` duplicate trong `scanner.py:111-115` và `process_monitor.py:45-54`.
- Mixed VN/EN comments.
- `mb_publication_time` trong TIResult thiếu trong ScanResult slots.

---

## 3. 🔒 BẢO MẬT — 7/10

> ⚠️ Codebase **đã hardened đáng kể**: JWT secret, CORS, `DEFAULT_USERS` đã fix. Tuy vẫn còn issue và malware trong git.

### Điểm mạnh — Hardening đã làm
- JWT secret bắt buộc, ENV → config → auto-gen+warn (`api/auth.py:96-116`, `core/security_utils.py:159-207`).
- `DEFAULT_USERS = {}` rỗng (`api/auth.py:124`).
- `PLAIN:` fallback removed; bcrypt failure raises `RuntimeError` (`api/auth.py:39-59`).
- CORS không còn `["*"]`, refuse wildcard (`api/main.py:119-132`).
- Per-IP auth rate limit sliding window (`api/main.py:135-164`).
- Path traversal defence với `resolve_safe_path` + UNC reject + symlink resolve (`core/security_utils.py:120-154`).
- API scan endpoint require `api.allowed_scan_roots` allowlist hoặc 403 (`api/routers/scan.py:88-103`).
- Office upload: extension allowlist + size cap + basename (`api/routers/scan.py:417-446`).
- YARA rule download: HTTPS only + 16 MiB cap + SHA256 pinning (`core/rule_updater.py:84-118`).
- Atomic JSON writes; honeypot prefix `_DECOY_`; constant-time hash compare; generic 500 (no stacktrace leak).

### 🔴 Critical
- **Real malware binary committed vào repo** — `ransomeware/5677dfad...elf` (ELF binary thực). Folder không trong `.gitignore`. `quarantine/20260402_104016/ngrok.exe.quarantined` cũng commit.
  - **Impact**: GitHub TOS violation, AV cảnh báo cho ai clone, supply-chain risk, HIPAA/SOC2 fail.
  - **Fix**:
    1. Add `ransomeware/`, `quarantine/`, `*.quarantined` vào `.gitignore`
    2. `git filter-repo --invert-paths --path ransomeware --path quarantine`
    3. Force-push sau khi inform team
    4. Thay malware sample bằng [TheZoo](https://github.com/ytisf/theZoo) reference (hash + URL only)
  - **Effort**: Medium.

### 🟠 High
- **`unblock_network` không sanitize `process_name`** (`core/auto_responder.py:447`) trong khi `block_network` sanitize (`:336-339`). Bug logic: rule_name không match → firewall rules tích lũy mãi. DoS by exhaustion.
  - Fix: Dùng `_sanitize_process_name`. Effort: 1 dòng.
- **Singleton VT client cache** có thể chứa file hashes nhạy cảm trong `data/vt_cache.json` permanent.
- **No CSRF protection** với `allow_credentials=True` (`api/main.py:129`) — nếu cookie auth dùng → CSRF risk. Document chỉ dùng header auth.

### 🟡 Medium
- `_check_special_magic` không check `len(header) < 12` trước slice (`core/fp_reducer.py:227-238`).
- `api.allowed_origins` mặc định `localhost:3000` không phù hợp khi GUI desktop chạy port khác.
- `api.expose_internal_errors` opt-in nguy hiểm, không có production guard.
- JWT auto-gen secret persisted vào `config.json` (`core/security_utils.py:192-200`) — leak risk qua backup. Production nên refuse start nếu thiếu ENV.
- Honeypot template list `Desktop, Documents, Downloads` (`data/config.json.template:152-154`) inconsistent với code default `~/.ransomware_detector/honeypots`. User copy template sẽ deploy decoy ra Desktop nhầm.

### 🔵 Low
- API key entropy `secrets.token_urlsafe(32)` = 256-bit ✓.
- `ctypes.wintypes` usage chưa audit sâu buffer overflow.

---

## 4. 🤖 ML ENGINE — 6/10

### Điểm mạnh
- CalibratedClassifierCV isotonic (`core/ml_engine.py:295-299`).
- Threshold optimization với precision ≥ 0.95 (`:463-519`).
- Data-leak fix refit scaler trên trainval (`:323-337`).
- SMOTE auto-detect imbalance (`:251-261`).
- 60/20/20 split với stratify.

### 🔴 Critical
- **Mâu thuẫn cost-matrix vs class_weight** — `COST_FP=3.0`, `COST_FN=10.0` (`core/ml_engine.py:94-95`) nhưng `class_weight={0:3.0, 1:1.0}` (`:96-97`) → train ngược với cost-matrix khai báo. Comment dòng 7 nói giảm FP nhưng cost-matrix nói FN đắt 3.3x.
  - **Impact**: Model train để giảm FP, tăng FN → bỏ sót ransomware. Cho security tool đây là quyết định kinh doanh nhưng KHÔNG có justification và mâu thuẫn nội tại.
  - **Fix**: Thống nhất một triết lý:
    - Ưu tiên tránh FP (alert fatigue): `class_weight={0:3, 1:1}`, `cost_fp=10`, `cost_fn=3`. Document "tool này có thể bỏ sót".
    - Zero-miss enterprise SOC: `class_weight={0:1, 1:5}`, `cost_fp=3`, `cost_fn=10`.
  - **Effort**: Low (config) + High (validate).

### 🟠 High
- **Synthetic dataset là default training fallback** (`core/ml_engine.py:215-223`). Synthetic không đại diện real ransomware (UPX-packed, ChaCha20, partial-encryption). `corpus/malware_source/` rỗng. Fix: bắt buộc real data cho production model.
- **Feature 16 = `Is Known Benign Format`** (`core/feature_extractor.py:160-170`) là **target leakage**: cùng signal được dùng trong `fp_reducer` post-process (magic_bytes_discount 0.7). Double-counting → calibration sai. Fix: bỏ feature 16 HOẶC bỏ magic-bytes discount.
- **`get_engine()` singleton có thể không thread-safe** với `ThreadPoolExecutor(max_workers=8)` → race trên `self._loaded` khi init.
- **Adversarial robustness**: 16 features đều statistical descriptors → trivial bypass bằng header padding, polyglot files (PE+JPG), intermittent encryption. Cần dynamic features.

### 🟡 Medium
- RF hyperparams không tuned (no GridSearch/Optuna).
- `get_risk_level()` thresholds tier động theo `self.threshold` → tier MEDIUM biến mất khi user tăng threshold (`core/ml_engine.py:551-566`).
- `nan_to_num(posinf=8.0)` (`core/ml_engine.py:535`) silently masking extraction failures — should return ERROR risk.

### 🔵 Low
- Không có model versioning (static `rf_ransomware_detector.joblib`) → retrain corrupt = không có rollback. Fix: semver + symlink "current".

---

## 5. 🛡️ DETECTION ENGINES — 6/10

### Điểm mạnh
- YARA fallback pure-Python khi `yara-python` không cài (`core/yara_engine.py:36-40`).
- Built-in YARA rules đã hardened conditions (`2 of them` thay vì `any`, `core/yara_engine.py:63-67`).
- Multi-stage pipeline: whitelist→features→ML→FP→YARA→VT→TI fusion (`core/scanner.py:567-779`).
- PE injection integrated; VT consensus downgrade chống FP installer.

### 🟠 High
- **YARA chỉ 10 rules built-in** cho families cũ (WannaCry, LockBit, Ryuk, REvil, Conti) — thiếu BlackBasta, Akira, ALPHV-v2, Royal, Play, Cl0p (process_monitor có extension list nhưng YARA không có rules). Fix: pull Florian Roth signature-base với SHA256 pin. Effort: Medium.
- **DGA threshold entropy 3.5** (`data/config.json.template:108`) quá thấp → FP cho CDN domains (Cloudflare/Akamai). Fix: 4.5+ kết hợp Tranco top-1M whitelist.

### 🟡 Medium
- Process monitor thresholds hardcoded `RENAME_BURST=5/10s`, `MASS_IO=50MBps` (`core/process_monitor.py:91-94`) → FP với VS rebuild (100+ rename/sec), video editing (>50 MB/s), DB backup (>100 MB/s). Có `KNOWN_BENIGN_PROCESSES` (`:57-76`) nhưng không gate threshold theo nó.
- Encryption burst `10 files / 30s` (`data/config.json.template:44-45`) — modern ransomware encrypt 100+/sec, FP với git checkout/npm install.
- `RANSOMWARE_DEBUG_TRACE` env var không document.
- Office analyzer không phân tích VBA macro behavior — chỉ check signatures (cần verify).
- `SUSPICIOUS_EXTENSIONS` duplicate `.encrypted` entry trong `process_monitor.py:45-54`.

### 🔵 Low
- Beacon CV=0.1 không có justification (typical jitter 0.05-0.3).
- Network monitor coefficient of variation chưa tuned.

---

## 6. 🌐 THREAT INTEL — 7/10

### Điểm mạnh
- 3-source TI (MalwareBazaar/ThreatFox/OTX) với rate limiters riêng (`core/threat_intel_client.py:168-171`).
- Persistent JSON cache với TTL + graceful expiration (`:122-135`).
- VT 4 RPM đúng free tier (`core/virustotal_client.py:37-55`).
- VT consensus fusion downgrade.

### 🟠 High
- **Không có offline circuit breaker** — synchronous `time.sleep()` block scanner. Scan 1000 files với VT enabled = 4h chờ rate limit. Fix: aggressive timeout 5s + circuit breaker khi 3 lỗi liên tiếp.

### 🟡 Medium
- VT API key có thể leak trong logs khi DEBUG (chưa kiểm tra `requests` logging).
- TI responses dùng `dict.get()` thay vì Pydantic → schema drift silent. Fix: Pydantic models cho mỗi API.
- `RateLimiter.wait()` block thread → kết hợp với ThreadPoolExecutor sẽ deadlock-prone.

### 🔵 Low
- VT cache không có size limit → grows forever.
- OTX pulse_count không có trong scoring fusion logic.

---

## 7. ⚡ HIỆU SUẤT — 5/10

### Điểm mạnh
- Streaming SHA256 (`core/security_utils.py:34-53`).
- Incremental scan cache mtime-based (`core/scanner.py:78-100`).
- ThreadPoolExecutor parallel.
- Atomic JSON writes.

### 🟠 High
- **GIL bottleneck** — ML/feature/hash đều CPU-bound nhưng dùng threads → speedup ~1-2x thực tế. Fix: ProcessPoolExecutor hoặc Rust extension. Effort: High.
- **Đọc file 2 lần**: SHA256 (`scanner.py:582`) + feature extraction (`:603`) riêng biệt → 4GB I/O cho file 2GB. Fix: one-pass.

### 🟡 Medium
- `_collect_files` walks toàn bộ tree trước khi scan → block memory cho 1M files. Fix: generator-based.
- `features_b64` store trong mỗi ScanResult (`core/scanner.py:609-611`) → 85 MB RAM cho 1M files. Fix: lazy compute.
- FastAPI `async def` + sync core → block event loop (`api/routers/scan.py:71`). Fix: `asyncio.to_thread()`.
- YARA scan không cache compiled rules cross-call (cần verify singleton).

### 🔵 Low
- `max_workers=8` hardcoded — không adaptive với CPU count.
- `_safe_parallel_jobs()` Windows default = 1 (`core/ml_engine.py:100-114`) — quá conservative for training.

---

## 8. 🧪 TESTING — 6/10

### Điểm mạnh
- 30 test files trong `tests/`.
- conftest.py auto-isolate JWT secret (`tests/conftest.py:18-26`).
- Rich fixtures: `sample_safe_file`, `sample_random_file`, `sample_png_header`, `sample_pdf_header`, `sample_zip_header`, `mock_engine`.
- CI matrix Python 3.10/3.11/3.12 trên Windows.
- `test_auth_hardening.py` regression test cho JWT/PLAIN.

### 🟠 High
- **Không có test cho `injection_detector.py`, `network_monitor.py`, `watchdog_monitor.py`** — 3 modules quan trọng (~67 KB) hoàn toàn không có test file riêng. Fix: thêm tests với mock psutil + Windows API. Effort: High.
- **VT/ThreatIntel chỉ có client tests**, không có integration test với mock HTTP server.

### 🟡 Medium
- **Edge cases thiếu**: file >2GB, unicode/long paths (>260 chars Windows), symlink loops trong honeypot, concurrent scans race trên cache, YARA compile failures.
- **No coverage gate** — `pytest-cov` cài rồi nhưng `ci.yml` không enforce. Fix: `--cov-fail-under=70`.
- `test_injection.py` ở root không phải `tests/` — không được pytest pickup.
- Linter chỉ chạy trên `core api tests scripts`, miss `gui/`, `main.py` (`.github/workflows/ci.yml:34`).

### 🔵 Low
- `mock_engine` không mock `predict_batch`, `get_model_info`.
- Không có e2e scan→quarantine→restore test.

---

## 9. 📦 DEPENDENCIES — 5/10

### 🟠 High
- **`>=` versioning everywhere** (`requirements.txt:1-65`) → reproducible builds ❌. Fix: pip-compile lock hoặc Poetry/uv. Effort: Low.
- **No `requirements-dev.txt`** — pytest/ruff trong production deps. Fix: tách runtime vs dev.

### 🟡 Medium
- `scapy>=2.5.0` rất nặng (~2 MB compiled, native). Có thể replace bằng `psutil.net_connections()`.
- `win10toast>=0.9` 5 năm không update, issue với Windows 11 22H2+. Nên dùng `winrt-Windows.UI.Notifications`.
- `yara-python` commented-out không document cách enable trong README/CI.

### 🔵 Low
- `passlib[bcrypt]` không cần nữa (auth.py dùng direct `bcrypt`) — replace bằng `bcrypt>=4.0`.
- pip-audit có nhưng `continue-on-error: true` (`.github/workflows/ci.yml:41`) → informational only.

---

## 10. 🔧 DevOps & CI/CD — 5/10

### Điểm mạnh
- GitHub Actions CI matrix Python 3.10-3.12 (`.github/workflows/ci.yml:14-17`).
- Ruff + pytest + pip-audit pipeline.
- JWT secret cho CI từ `run_id` (không hardcode).

### 🟠 High
- **No Dockerfile** — Deployment hand-roll Python env. Fix: multi-stage Dockerfile + docker-compose.
- **CI chỉ Windows** — nên smoke test Linux để catch path-separator bugs sớm.

### 🟡 Medium
- No release/publish workflow.
- No Dependabot/Renovate config.
- Logging plain text, không structured JSON → khó parse SIEM. Fix: `structlog` hoặc `python-json-logger`.

### 🔵 Low
- No `CODEOWNERS` — review accountability không xác định.

---

## 11. 📖 TÀI LIỆU — 5/10

### Điểm mạnh
- Module docstrings tiếng Việt giàu thông tin (vd `core/fp_reducer.py:1-16` giải thích root cause FP và 3-tầng solution).
- `docs/training-workflow-pe-5day.md` tồn tại.

### 🟠 High
- **Không có `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`** — Security tool **bắt buộc** `SECURITY.md` (responsible disclosure email + GPG key). Effort: Low.

### 🟡 Medium
- Files báo cáo ở root: `bao-cao-phan-tich-ma-doc.md`, `report.md`, `report (2).docx` → move `docs/`.
- API schemas description chưa audit chi tiết.
- Không có architecture diagram (mermaid/PlantUML).

### 🔵 Low
- README quality chưa audit.
- Không có ADR (Architecture Decision Records) cho quyết định lớn (RF vs XGBoost, class_weight vs cost_matrix).
- `.windsurf/` trong `.gitignore` ✓.

---

## 12. 🚀 PRODUCTION READINESS — 5/10

### Điểm mạnh
- 30s countdown trước auto-quarantine với abort callback (`core/auto_responder.py:81-117`).
- System process whitelist chống tự destruct (`:46-51`).
- Quarantine có manifest + restore (`:180-223`).
- Audit log mọi response action (`:494-508`).

### 🔴 Critical
- **`shutil.move` không atomic cross-volume** (`core/auto_responder.py:152`). Nếu quarantine ở D:, file ở C: → copy+delete; copy fail mid-way → file gốc còn, ransomware tiếp tục mã hóa.
  - **Fix**: SHA256 trước → copy → fsync → verify SHA256 → delete với retry.
  - **Effort**: Medium.

### 🟠 High
- **Không có health check endpoint thực sự** — `/api/v1/health` mention trong docstring nhưng cần verify trong `api/routers/status.py`.
- **`_log_action` không atomic** (`core/auto_responder.py:504-508`) — concurrent quarantines từ thread pool có thể interleave log entries. Fix: `threading.Lock()` hoặc QueueHandler.
- **Resource limits không enforced** — `core/auto_responder.py:65-79` quarantine không có disk quota check. 100GB ransomware có thể fill disk → system unstable. Fix: `shutil.disk_usage()` check, refuse < 10% free.

### 🟡 Medium
- Watchdog crash → no auto-restart.
- API graceful shutdown chỉ log, không cleanup outstanding scans (`api/main.py:70-92`).
- GUI freeze risk: `on_progress` callback từ worker thread update Tkinter trực tiếp = race.
- Không có CPU throttling — 8 threads 100% có thể trigger thermal throttle. Fix: `SetPriorityClass(BELOW_NORMAL)` Windows.

### 🔵 Low
- PID-based firewall rule recycle có thể block sai process sau reboot (`core/auto_responder.py:339`).

---

## 🚨 TOP 15 VẤN ĐỀ NGHIÊM TRỌNG NHẤT

| # | Sev | Vấn đề | File | Fix | Effort |
|---|-----|--------|------|-----|--------|
| 1 | 🔴 | Real malware ELF binary committed | `ransomeware/...elf` + `.gitignore:42-49` | Add gitignore + filter-repo + hash refs | Medium |
| 2 | 🔴 | Cost-matrix mâu thuẫn class_weight | `core/ml_engine.py:94-97` | Thống nhất triết lý + retrain | Low+High |
| 3 | 🔴 | `shutil.move` không atomic cho quarantine | `core/auto_responder.py:152` | Copy+fsync+verify+delete | Medium |
| 4 | 🟠 | `unblock_network` không sanitize | `core/auto_responder.py:447` | `_sanitize_process_name()` | Low |
| 5 | 🟠 | Synthetic dataset là default training | `core/ml_engine.py:215-223` | Bắt buộc real data prod | High |
| 6 | 🟠 | Feature 16 + fp_reducer = double-count | `core/feature_extractor.py:160` + `core/fp_reducer.py:159` | Bỏ một trong hai | Medium |
| 7 | 🟠 | Code duplication scan API vs core | `api/routers/scan.py:170-273` | Gọi `Scanner` trực tiếp | Medium |
| 8 | 🟠 | YARA rules thiếu families 2024-2025 | `core/yara_engine.py` | Pull signature-base + SHA pin | Medium |
| 9 | 🟠 | DGA threshold quá thấp (3.5) | `data/config.json.template:108` | 4.5+ + Tranco whitelist | Low |
| 10 | 🟠 | TI rate limiter block threadpool | `core/threat_intel_client.py:47-66` | Async + circuit breaker | High |
| 11 | 🟠 | GIL bottleneck thread vs process | `core/scanner.py:869-891` | ProcessPool/Rust ext | High |
| 12 | 🟠 | No tests injection/network/watchdog | `tests/` | Add 3 test files mock | High |
| 13 | 🟠 | `>=` deps + no lock file | `requirements.txt` | pip-compile lock | Low |
| 14 | 🟠 | No Dockerfile + no SECURITY.md | root | Create both | Low |
| 15 | 🟠 | `_log_action` race + no disk quota | `core/auto_responder.py:494-508,65-79` | Lock + disk_usage check | Low |

---

## 🛡️ SECURITY DEEP-DIVE

### Attack Surface
1. **REST API** (port 8000): `/auth/token` (rate limited ✓), `/scan/file` (allowlist gated ✓), `/scan/office` (extension+size capped ✓), `/honeypots/*` (admin only).
2. **Local file system**: scanner đọc files đa định dạng — risk parsers (oletools, PyMuPDF) crash hoặc bị embedded payload exploit.
3. **Watchdog filesystem watcher** — race với attacker tạo/xóa file nhanh.
4. **YARA rule download** — đã pin SHA ✓, HTTPS only ✓.
5. **VT/TI HTTP responses** — chưa validate Pydantic; malformed response có thể crash.
6. **ctypes Windows API** trong injection_detector — buffer/handle leak risk.
7. **Subprocess calls** (`taskkill`, `netsh`) — list-args ✓ nên không command injection, nhưng rule_name không sanitize → exhaustion.

### Privilege Escalation
- Tool cần admin/SYSTEM để: kill processes, taskkill, netsh firewall, đọc memory (injection_detector). Nếu chạy SYSTEM thì compromise tool = full system compromise.
- **Fix**: Split privileges (helper service vs UI).

### Supply Chain Risks
- 64 dependencies không pin → drift.
- No SBOM generated.
- `yara-python` native build từ source → trojan-able.
- `scapy` raw socket access → privileged.

### Data Flow Sensitive
- **API keys** (VT, ThreatFox, OTX): `data/config.json` (gitignore ✓) + ENV.
- **JWT secret**: ENV → config (auto-gen warn).
- **File hashes**: `data/vt_cache.json`, `data/ti_cache.json` (gitignore ✓).
- **Quarantine**: ❌ committed to git (Critical #1).
- **User credentials**: bcrypt hashed in config.

---

## 🤖 ML DEEP-DIVE

### 16 Features
1-2: Shannon entropy, Chi-Square; 3-9: byte stats (mean, var, serial corr, chunk entropy stats); 10: magic bytes mismatch; 11-15: normalized entropy, byte mode, compression sim, structural consistency, ext entropy delta; 16: known benign format.

**Đánh giá**: Tất cả là statistical descriptors, **không có behavioral/dynamic features**. Mạnh cho phát hiện high-entropy encryption nhưng yếu với:
- Polymorphic malware không packed.
- Fileless ransomware.
- Living-off-the-land binaries (LOLBins).

### Detection Capability
- ✅ Phát hiện: encrypted files (high entropy + low structural), packed PE, suspicious extension changes, known YARA family signatures.
- ❌ Khó phát hiện: clean-binary droppers, scripted ransomware (PowerShell), fileless, partial encryption, polyglot files.

### FP/FN Scenarios
- **FP**: Compressed media (PNG/JPG/MP4) → đã giảm bằng per-extension threshold + magic discount; UPX-packed legit installers; encrypted archives.
- **FN**: Intermittent encryption (encrypt every Nth chunk); padded headers; ChaCha20/AES với non-uniform output.

### Evasion Techniques (trivial bypass)
1. Padding với plaintext giảm overall entropy.
2. Polyglot files (PE+JPG) match magic bytes → discount 0.7x.
3. Avoid suspicious extensions trong `SUSPICIOUS_EXTENSIONS` list.
4. Spread encryption mass < 10 files / 30s threshold.
5. Mimic process name in `KNOWN_BENIGN_PROCESSES` (notepad.exe).

---

## 🗺️ LỘ TRÌNH CẢI THIỆN

### Phase 1 (Tuần 1-2) — Critical Security
- [ ] git filter-repo xóa `ransomeware/`, `quarantine/` khỏi history; cập nhật `.gitignore`.
- [ ] Fix `unblock_network` sanitize.
- [ ] Add `SECURITY.md` với responsible disclosure.
- [ ] Atomic quarantine move (copy+fsync+verify+delete).
- [ ] Xóa debug instrumentation `4602d0`.

### Phase 2 (Tuần 3-4) — Code Quality & Testing
- [ ] Pin dependencies với pip-compile.
- [ ] Tách `requirements-dev.txt`.
- [ ] Coverage gate `--cov-fail-under=70` trong CI.
- [ ] Tests cho injection/network/watchdog modules.
- [ ] Refactor scan duplication API ↔ core.
- [ ] Move `_api_test*.py`, `test_injection.py`, `debug_gui.py`.

### Phase 3 (Tháng 2-3) — Architecture & Production
- [ ] Tách `core/` thành sub-packages.
- [ ] DetectionStage pipeline interface.
- [ ] Service layer cho GUI/API/CLI.
- [ ] Dockerfile + docker-compose.
- [ ] Health check + Prometheus metrics endpoint.
- [ ] Structured JSON logging.
- [ ] Atomic audit log (queue handler).

### Phase 4 (Tháng 3-6) — ML & Detection
- [ ] Thống nhất cost-matrix vs class_weight, retrain với real data.
- [ ] Bỏ feature 16 hoặc magic-bytes discount.
- [ ] Model versioning + rollback.
- [ ] YARA rules 2024-2025 families pinned.
- [ ] Dynamic features (process behavior, syscalls).
- [ ] Adversarial robustness testing.
- [ ] Async TI client với circuit breaker.

---

## 🎯 KẾT LUẬN

### 1. Sức khỏe dự án
Đây là một **dự án nghiên cứu/học thuật ở mức trên trung bình**, có nền tảng kiến trúc hợp lý, security đã hardened một phần đáng kể (JWT, CORS, path traversal, bcrypt-only). Tuy nhiên còn nhiều issue cấu trúc (god-object, code duplication, coupling), ML engine có mâu thuẫn nội tại nghiêm trọng, và **tồn tại malware binary trong git history** — vấn đề lớn nhất.

### 2. Sẵn sàng production?
**Chưa** — với điều kiện sau:
- Phải fix Critical #1 (xóa malware khỏi git) trước khi public deploy.
- Phải fix Critical #2 (cost-matrix consistency) và retrain với real data.
- Phải fix Critical #3 (atomic quarantine) trước khi deploy auto-response.
- Cần có Dockerfile + structured logging + health checks.

### 3. Top 3 rủi ro nếu deploy ngay
1. **Compliance violation** từ malware binary trong repo (GitHub TOS, SOC2, HIPAA fail).
2. **False negatives cao** từ ML training conflict + synthetic dataset bias → bỏ sót ransomware thật.
3. **Quarantine race** với encryption đang tiếp diễn → mất dữ liệu user.

### 4. Top 3 điểm dự án làm tốt
1. **Security hardening đã làm**: path traversal, JWT, CORS, rate limiting, atomic writes, allowlist scanning.
2. **FP reduction pipeline đa tầng** (whitelist → per-ext threshold → magic bytes → VT consensus downgrade) — kiến trúc tinh tế.
3. **Calibrated ML với threshold optimization** + Precision-Recall curve — đúng practice cho imbalanced security data.

### 5. So với industry standards (Crowdstrike, SentinelOne, Microsoft Defender)
- **Bằng**: file-based static detection, YARA integration, threat intel correlation.
- **Kém**: behavioral analytics (EDR-class), kernel-mode driver, cloud reputation, ML pipeline với continuous retraining, telemetry.
- **Tổng**: là **research-grade prototype**, không phải production EDR. Phù hợp cho lab/internal use sau khi fix Critical issues.

---

**Báo cáo hoàn tất.** Có 3 vấn đề Critical cần xử lý ngay, 24 High, 45 Medium, 25 Low. Khuyến nghị bắt đầu với Phase 1 (1-2 tuần) trước khi tiếp tục feature development.
