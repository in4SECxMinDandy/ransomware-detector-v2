# Báo Cáo Audit Ransomware Detector v2.0

**Vai trò đánh giá:** Senior Software Architect & Security Auditor  
**Phạm vi:** Kiến trúc, bảo mật, ML, detection engines, threat intelligence, hiệu suất, testing, dependency, DevOps, tài liệu và production readiness.  
**Môi trường kiểm tra:** `C:\Users\haqua\Documents\GitHub\ransomware-detector-v2`  

## Tóm Tắt Điều Hành

Dự án có nền tảng tốt cho mục tiêu nghiên cứu và prototype: kiến trúc đa engine, có FastAPI, GUI, ML pipeline, YARA, PE/Office analysis, process monitoring, threat intelligence và test suite tương đối rộng. Tuy nhiên, trạng thái hiện tại **chưa sẵn sàng production**, đặc biệt nếu bật auto-response trên endpoint thật.

Các rủi ro lớn nhất nằm ở ML evaluation leakage, model loading bằng `joblib`, quarantine/restore safety, một số bug detection nghiêm trọng, dependency chưa khóa version, coverage thấp ở các module critical và artifact nhạy cảm vẫn đang được git track.

Lưu ý quan trọng: một số vấn đề trong mô tả ban đầu đã được code hiện tại khắc phục. `api/auth.py` không còn hardcoded default users, không còn fallback lưu password plaintext khi bcrypt fail, và `api/main.py` không còn cấu hình CORS wildcard trực tiếp.

## Kết Quả Lệnh Kiểm Tra

```text
pytest tests --cov=core --cov-report=term-missing -q
Result: 253 passed, 1 failed
Core coverage: 45%
Failure: tests/test_honeypot_manager.py::test_remove_all_honeypots
```

```text
python -m pyright core
Result: No module named pyright
```

```text
python -m pip_audit -r requirements.txt
Result: No module named pip_audit
```

```text
radon cc core -a -nc
Result: radon not installed / not recognized
```

```text
python -m pip check
Result: dependency conflicts detected
- google-ai-generativelanguage requires protobuf <6, installed protobuf 6.33.6
- grpcio-status requires protobuf <6, installed protobuf 6.33.6
- mlflow requires protobuf <5 and pyarrow <16, installed protobuf 6.33.6 and pyarrow 23.0.1
- opencv-python/opencv-python-headless require numpy >=2, installed numpy 1.26.4
- poetry requires packaging >=24.0, installed packaging 23.2
- prometheus-fastapi-instrumentator requires starlette >=0.30.0,<1.0.0, installed starlette 1.0.0
```

## Bảng Tổng Hợp Đánh Giá

| # | Hạng mục | Điểm | Mức rủi ro | Critical | High | Medium | Low |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| 1 | Kiến trúc & Cấu trúc | 5/10 | High | 0 | 4 | 3 | 2 |
| 2 | Chất lượng Code | 5/10 | High | 0 | 5 | 6 | 3 |
| 3 | Bảo mật | 6/10 | High | 2 | 7 | 5 | 3 |
| 4 | Machine Learning Engine | 4/10 | High | 1 | 6 | 4 | 2 |
| 5 | Detection Engines | 5/10 | High | 1 | 7 | 6 | 3 |
| 6 | Threat Intelligence | 6/10 | Med-High | 0 | 3 | 4 | 2 |
| 7 | Hiệu suất | 5/10 | High | 0 | 5 | 4 | 2 |
| 8 | Testing | 4/10 | High | 0 | 5 | 3 | 1 |
| 9 | Dependency Management | 3/10 | High | 0 | 5 | 3 | 2 |
| 10 | DevOps & CI/CD | 5/10 | Med-High | 0 | 3 | 4 | 2 |
| 11 | Tài liệu | 5/10 | Medium | 0 | 2 | 4 | 2 |
| 12 | Production Readiness | 3/10 | Critical | 1 | 7 | 4 | 2 |
|  | **Tổng** | **56/120** | **High** | **5** | **59** | **50** | **26** |

## Top 15 Vấn Đề Nghiêm Trọng Nhất

| # | Severity | Hạng mục | Vấn đề | File | Fix đề xuất | Effort |
|---|---|---|---|---|---|---|
| 1 | Critical | ML | SMOTE chạy trước train/validation/test split, gây data leakage và metric ảo | `core/ml_engine.py:251-269` | Split dataset trước, chỉ áp dụng SMOTE trên train set | Medium |
| 2 | Critical | Security/ML | `joblib.load()` model không kiểm integrity, có rủi ro pickle RCE nếu file model bị thay | `core/ml_engine.py:180-184` | Ký model bằng SHA256/signature, chỉ load từ trusted readonly path | Medium |
| 3 | Critical | Production | Quarantine move/restore chưa đủ an toàn trước symlink, manifest tamper, collision | `core/auto_responder.py:119-223` | Copy+fsync+hash verify, signed manifest, path validation khi restore | High |
| 4 | Critical | Repo Hygiene | `Malware/` và `quarantine/` có file đang được git track | `.gitignore`, `git ls-files` | Xóa khỏi Git history hoặc chuyển sang Git LFS/private artifact store | High |
| 5 | Critical | Detection | DGA detection gần như không hoạt động vì entropy đã normalize nhưng threshold là `3.5` | `core/network_monitor.py:43`, `core/network_monitor.py:173-183` | Dùng raw entropy hoặc threshold normalized phù hợp | Low |
| 6 | High | API Security | Report download chưa sanitize `report_id` và `format`, có path traversal/arbitrary file probing risk | `api/routers/reports.py:104-129` | Regex report ID, enum format, `resolve_safe_path()` | Low |
| 7 | High | Injection Detection | Windows API memory scanner dùng protection mask sai và chỉ scan 32-bit range | `core/injection_detector.py:337-401` | Khai báo `argtypes/restype`, dùng PAGE constants, hỗ trợ 64-bit address space | High |
| 8 | High | API Performance | FastAPI endpoint là async nhưng chạy scan sync, có thể block event loop | `api/routers/scan.py:171-278` | Chạy scan qua background job/threadpool/service queue | Medium |
| 9 | High | Monitoring | Watchdog queue full thì drop event im lặng | `core/watchdog_monitor.py:148-164` | Thêm metric/log/backpressure và fail-safe alert | Medium |
| 10 | High | API Security | API keys lưu plaintext trong config | `api/main.py:236-244`, `api/auth.py:203-215` | Lưu hash/HMAC, thêm metadata, revoke và rotation | Medium |
| 11 | High | Rule Supply Chain | Rule updater cho validate pass khi thiếu `yara-python` | `core/rule_updater.py:147-164` | Disable update nếu không compile/validate được YARA | Low |
| 12 | High | Process Monitoring | Whitelist process theo tên rộng như `cmd.exe`, `powershell.exe`, `python.exe` | `core/process_monitor.py:56-76` | Whitelist theo signer, path, hash và context hành vi | Medium |
| 13 | High | Testing | Coverage core chỉ 45%, nhiều module critical 0% | pytest coverage output | Coverage gate >80% cho module security-critical | High |
| 14 | High | Dependencies | Requirements dùng `>=`, không lockfile, dev/prod deps trộn chung, `pip check` conflict | `requirements.txt:5-64` | Dùng lockfile, tách requirements, audit blocking | Medium |
| 15 | High | Performance | Hash file lớn bằng `f.read()` toàn bộ trong VT/Office analyzer | `core/virustotal_client.py:602-609`, `core/office_doc_analyzer.py:756-765` | Dùng streaming `compute_sha256()` | Low |

## 1. Kiến Trúc & Cấu Trúc — Điểm: 5/10

### Điểm mạnh

- Dự án đã tách tương đối rõ `core/`, `api/`, `gui/`, `tests/`.
- Có utility dùng chung cho security như `compute_sha256`, `atomic_write_json`, `resolve_safe_path` tại `core/security_utils.py:34-154`.
- Config tập trung trong `core/config_manager.py:34-286`, giúp giảm hardcode cấu hình ở nhiều nơi.

### Vấn đề phát hiện

#### High

- **`main.py` vi phạm Single Responsibility**
  - File: `main.py:41-498`
  - Impact: entrypoint vừa launch GUI, CLI scan, synthetic training, training source workflow và parsing command thủ công. Dễ phát sinh bug khi thêm command mới.
  - Fix đề xuất: tách `cli.py`, `gui_launcher.py`, `training_cli.py`; dùng argparse subcommands hoặc Typer.
  - Effort: Medium

- **`core/scanner.py` coupling quá chặt**
  - File: `core/scanner.py:602-780`
  - Impact: scan pipeline gom whitelist, feature extraction, ML, PE, heuristic, FP reducer, YARA, VT, TI vào một method lớn. Khó test, khó thay đổi scoring.
  - Fix đề xuất: tách `ScanPipeline`, `ScoringService`, `ThreatIntelEnricher`, `StaticAnalyzer`.
  - Effort: High

- **Artifact test/debug ở root**
  - File: `_api_test.py`, `_api_test2.py`, `test_injection.py`, `debug_gui.py`, `_check_config.py`, `_run_pytest.py`
  - Impact: repo khó maintain, có thể bị pytest/tooling nhận nhầm.
  - Fix đề xuất: chuyển vào `tests/`, `scripts/` hoặc xóa nếu obsolete.
  - Effort: Low

- **Malware/quarantine artifacts vẫn được git track**
  - File: `Malware/`, `quarantine/`
  - Impact: rủi ro pháp lý, operational và supply-chain. `.gitignore` chỉ ngăn file mới, không xóa file đã track.
  - Fix đề xuất: `git rm --cached`, rewrite history nếu cần, dùng private artifact storage.
  - Effort: High

#### Medium

- **`core/` có 32 module nhưng chưa có sub-package theo domain**
  - Impact: namespace phẳng làm tăng coupling.
  - Fix đề xuất: `core/detection`, `core/monitoring`, `core/training`, `core/integrations`, `core/response`.
  - Effort: Medium

- **GUI gọi trực tiếp core logic**
  - Impact: khó test headless, khó reuse logic cho API/CLI.
  - Fix đề xuất: thêm application service layer.
  - Effort: Medium

## 2. Chất Lượng Code — Điểm: 5/10

### Điểm mạnh

- Có nhiều dataclass/type hints và logging.
- Một số logic safety đã được đóng gói, ví dụ `atomic_write_json()` tại `core/security_utils.py:58-99`.
- ML engine có metadata, threshold optimizer và feature importance report tại `core/ml_engine.py:394-453`.

### Vấn đề phát hiện

#### High

- **Class/module quá lớn**
  - File: `core/ml_engine.py`, `core/scanner.py`, `core/process_monitor.py`, `gui/main_window.py`
  - Impact: khó review, khó test, dễ regression.
  - Fix đề xuất: split theo responsibility.
  - Effort: High

- **Broad exception/fail-open ở nhiều engine**
  - File: `core/yara_engine.py:637-658`, `core/feature_extractor.py:409-412`, `core/smote_trainer.py:133-157`
  - Impact: lỗi detection có thể bị che, kết quả trả benign hoặc empty.
  - Fix đề xuất: log structured, phân loại recoverable/unrecoverable, fail-safe với severity unknown.
  - Effort: Medium

- **Ghi JSON cache/config chưa atomic**
  - File: `core/config_manager.py:333-342`, `core/virustotal_client.py:594-595`, `core/threat_intel_client.py:537-563`
  - Impact: crash/race có thể corrupt config/cache.
  - Fix đề xuất: dùng `atomic_write_json()`.
  - Effort: Low

#### Medium

- **`# type: ignore[import]` che vấn đề packaging/import**
  - File: `core/scanner.py:31-38`
  - Impact: type checker không bắt lỗi import thật.
  - Fix đề xuất: chuẩn hóa package, thêm `py.typed`, chạy pyright CI.
  - Effort: Medium

- **Magic numbers cho threshold**
  - File: `core/process_monitor.py:90-94`, `core/network_monitor.py:43-45`, `core/watchdog_monitor.py:53-78`
  - Impact: khó calibrate theo môi trường.
  - Fix đề xuất: chuyển toàn bộ sang config có provenance.
  - Effort: Medium

## 3. Bảo Mật — Điểm: 6/10

### Điểm mạnh

- Không còn hardcoded default users: `api/auth.py:119-124`.
- bcrypt fail thì raise error, không fallback lưu plaintext: `api/auth.py:36-58`.
- JWT secret có load/generate mechanism: `api/auth.py:96-116`.
- CORS từ chối wildcard và fallback localhost: `api/main.py:110-132`.
- Scan path dùng `resolve_safe_path()`: `api/routers/scan.py:70-107`.
- API key generation dùng `secrets.token_urlsafe(32)`: `api/auth.py:185-187`.

### Vấn đề phát hiện

#### Critical

- **Unsafe model deserialization bằng joblib**
  - File: `core/ml_engine.py:180-184`
  - Code vi phạm:

```python
data = joblib.load(self.model_path)
```

  - Impact: `joblib`/pickle có thể thực thi code nếu model file bị thay thế.
  - Fix đề xuất:

```python
expected_sha256 = load_expected_model_hash()
actual_sha256 = compute_sha256(self.model_path)
if actual_sha256 != expected_sha256:
    raise RuntimeError("Model integrity check failed")
data = joblib.load(self.model_path)
```

  - Effort: Medium

#### High

- **Legacy plaintext password sentinel vẫn được chấp nhận**
  - File: `api/auth.py:73-79`
  - Impact: nếu config cũ còn `PLAIN:`, user vẫn login được bằng legacy plaintext.
  - Fix đề xuất: migration command bắt buộc hash lại, từ chối `PLAIN:` trong production.
  - Effort: Low

- **API key lưu plaintext**
  - File: `api/main.py:236-244`, `api/auth.py:203-215`
  - Impact: lộ config là lộ toàn bộ API key.
  - Fix đề xuất: chỉ lưu hash/HMAC của API key, hiển thị raw key một lần khi tạo.
  - Effort: Medium

- **Report download path chưa validate**
  - File: `api/routers/reports.py:104-129`
  - Code vi phạm:

```python
filename = f"{report_id}.{format}"
file_path = os.path.join(_REPORT_DIR, filename)
```

  - Impact: path traversal hoặc arbitrary file probing nếu format/report_id bị craft.
  - Fix đề xuất:

```python
safe_path = resolve_safe_path(_REPORT_DIR, f"{report_id}.{format}")
```

  - Effort: Low

- **Upload Office chỉ validate extension và size**
  - File: `api/routers/scan.py:410-445`
  - Impact: file polyglot, zip bomb hoặc spoofed extension có thể đi vào parser.
  - Fix đề xuất: magic validation, zip bomb guard, per-format parser sandbox.
  - Effort: Medium

## 4. Machine Learning Engine — Điểm: 4/10

### Điểm mạnh

- Có danh sách 16 feature rõ ràng tại `core/feature_extractor.py:415-434`.
- Có Random Forest 300 estimators và calibration isotonic tại `core/ml_engine.py:282-299`.
- Có threshold optimization tại `core/ml_engine.py:464-519`.
- Có feature importance extraction tại `core/ml_engine.py:394-420`.

### Vấn đề phát hiện

#### Critical

- **SMOTE trước split gây data leakage**
  - File: `core/ml_engine.py:251-269`
  - Code vi phạm:

```python
X_bal, y_bal = apply_smote_tomek(X, y, random_state=random_state)
X_train_full, X_test, y_train_full, y_test = train_test_split(X_bal, y_bal, ...)
```

  - Impact: synthetic samples từ toàn bộ dataset có thể leak vào validation/test, làm metric quá lạc quan.
  - Fix đề xuất:

```python
X_train_full, X_test, y_train_full, y_test = train_test_split(X, y, stratify=y, ...)
X_train, X_val, y_train, y_val = train_test_split(X_train_full, y_train_full, stratify=y_train_full, ...)
X_train_bal, y_train_bal = apply_smote_tomek(X_train, y_train, random_state=random_state)
```

  - Effort: Medium

#### High

- **Synthetic dataset không đại diện real-world ransomware**
  - File: `core/dataset_generator.py:253-340`
  - Impact: model có thể học artifact của generator, không học hành vi malware thật.
  - Fix đề xuất: thêm real benign corpus, malware feature corpus đã sanitize, time-based split.
  - Effort: High

- **Predict fail-open khi model chưa load**
  - File: `core/ml_engine.py:521-530`
  - Impact: engine chưa load model có thể trả benign confidence 0.
  - Fix đề xuất: trả trạng thái `model_unavailable` và không cho scan production tiếp tục.
  - Effort: Low

- **Sampling file không deterministic**
  - File: `core/feature_extractor.py:255-288`
  - Impact: cùng một file có thể cho prediction khác nhau giữa các lần scan.
  - Fix đề xuất: dùng fixed offsets hoặc seed theo file hash/size.
  - Effort: Low

## 5. Detection Engines — Điểm: 5/10

### Điểm mạnh

- Có nhiều lớp detection: YARA, PE, Office, process, injection, network, watchdog, honeypot.
- PE parser có kiểm tra malformed headers và short files tại `core/pe_analyzer.py:215-389`.
- YARA compile khi init engine, không compile lại mỗi file: `core/yara_engine.py:607-612`.

### Vấn đề phát hiện

#### Critical

- **DGA detection threshold sai**
  - File: `core/network_monitor.py:43-45`, `core/network_monitor.py:173-183`
  - Impact: entropy đã chia 8 nên gần như không bao giờ vượt threshold 3.5.
  - Fix đề xuất: bỏ normalize hoặc đổi threshold normalized.
  - Effort: Low

#### High

- **Injection detector memory scan sai constants và 32-bit only**
  - File: `core/injection_detector.py:337-401`
  - Impact: bỏ sót injected memory trên process 64-bit, RWX detection sai.
  - Fix đề xuất: dùng `ctypes` signatures chuẩn, `MEMORY_BASIC_INFORMATION64`, PAGE constants.
  - Effort: High

- **PE import fallback gần như vô dụng**
  - File: `core/pe_analyzer.py:466-489`
  - Impact: nếu thiếu `pefile`, dangerous API detection không hoạt động.
  - Fix đề xuất: bắt buộc `pefile` cho PE analysis hoặc hoàn thiện parser.
  - Effort: Medium

- **YARA/fallback rules dễ false positive**
  - File: `core/yara_engine.py:382-562`
  - Impact: nhiều family rule match chỉ cần 1 string/extension.
  - Fix đề xuất: yêu cầu kết hợp string + structural indicator + entropy/context.
  - Effort: Medium

- **Office analyzer xử lý `.xls` chưa đúng macro risk**
  - File: `core/office_doc_analyzer.py:376-377`
  - Impact: `.xls` có thể chứa VBA macro nhưng bị đánh dấu không macro-enabled.
  - Fix đề xuất: với OLE legacy formats, luôn chạy oletools macro detection.
  - Effort: Low

## 6. Threat Intelligence Integration — Điểm: 6/10

### Điểm mạnh

- VirusTotal rate limiter mặc định 4 rpm tại `core/virustotal_client.py:37-55`.
- Có persistent cache VT tại `core/virustotal_client.py:517-598`.
- Threat Intel client có rate limiter riêng mỗi source tại `core/threat_intel_client.py:47-62`.

### Vấn đề phát hiện

#### High

- **VT upload có privacy risk**
  - File: `core/virustotal_client.py:233-305`
  - Impact: file nội bộ có thể bị upload ra third-party service.
  - Fix đề xuất: mặc định hash-only, upload phải opt-in và có warning rõ.
  - Effort: Medium

- **Cache TI/VT ghi non-atomic**
  - File: `core/virustotal_client.py:594-595`, `core/threat_intel_client.py:537-563`
  - Impact: cache có thể corrupt khi crash hoặc concurrent writes.
  - Fix đề xuất: dùng `atomic_write_json()`.
  - Effort: Low

#### Medium

- **Threat Intel lookup chạy tuần tự**
  - File: `core/threat_intel_client.py:265-278`
  - Impact: latency cao, timeout một source ảnh hưởng UX.
  - Fix đề xuất: async/parallel query với deadline chung.
  - Effort: Medium

- **SHA256 chỉ validate length, chưa validate hex**
  - File: `core/threat_intel_client.py:203-227`
  - Impact: input malformed vẫn có thể đi vào request path.
  - Fix đề xuất: regex `^[a-fA-F0-9]{64}$`.
  - Effort: Low

## 7. Hiệu Suất — Điểm: 5/10

### Điểm mạnh

- Feature extractor có sampling strategy cho file lớn tại `core/feature_extractor.py:101-104`.
- Scanner dùng `ThreadPoolExecutor` tại `core/scanner.py:869-894`.
- Một số hash đã dùng streaming tại `core/security_utils.py:34-53`.

### Vấn đề phát hiện

#### High

- **API scan block event loop**
  - File: `api/routers/scan.py:171-278`
  - Impact: request scan lớn có thể làm API server không phản hồi.
  - Fix đề xuất: job queue/background worker.
  - Effort: Medium

- **Watchdog drop event khi queue full**
  - File: `core/watchdog_monitor.py:148-164`
  - Impact: ransomware burst có thể làm mất event quan trọng.
  - Fix đề xuất: drop policy có metric, bounded priority queue, escalation khi overflow.
  - Effort: Medium

- **Hash full-file bằng RAM**
  - File: `core/virustotal_client.py:602-609`, `core/office_doc_analyzer.py:756-765`
  - Impact: file lớn gây memory spike.
  - Fix đề xuất: dùng streaming hash.
  - Effort: Low

#### Medium

- **Incremental cache có race condition**
  - File: `core/scanner.py:46-75`
  - Impact: nhiều scan đồng thời có thể ghi đè cache.
  - Fix đề xuất: lock cache hoặc SQLite.
  - Effort: Medium

## 8. Testing — Điểm: 4/10

### Điểm mạnh

- Test suite có số lượng đáng kể: 253 test pass.
- Có test cho nhiều module như auth, config, scanner, yara, VT, honeypot.

### Vấn đề phát hiện

#### High

- **Coverage core chỉ 45%**
  - Evidence: pytest coverage output.
  - Impact: nhiều logic critical chưa được bảo vệ regression.
  - Fix đề xuất: coverage gate theo module, không chỉ global.
  - Effort: High

- **Một test honeypot đang fail**
  - File: `tests/test_honeypot_manager.py::test_remove_all_honeypots`
  - Impact: test chạm default honeypot location trong user home, isolation chưa tốt.
  - Fix đề xuất: inject temp config/registry path cho test.
  - Effort: Low

- **Nhiều module critical 0%**
  - File: `core/injection_detector.py`, `core/network_monitor.py`, `core/forensic_exporter.py`, `core/report_generator.py`
  - Impact: bug detection nghiêm trọng không bị test bắt.
  - Fix đề xuất: unit test với mock Windows API, process list, DNS/HTTP.
  - Effort: High

## 9. Dependency Management — Điểm: 3/10

### Điểm mạnh

- Requirements liệt kê đầy đủ nhóm chức năng chính.
- `yara-python` được comment optional, cho thấy có ý thức graceful degradation.

### Vấn đề phát hiện

#### High

- **Không pin version**
  - File: `requirements.txt:5-64`
  - Impact: build không reproducible, dependency mới có thể phá app.
  - Fix đề xuất: dùng `pip-compile` để tạo lockfile.
  - Effort: Medium

- **Dev/prod/optional dependencies trộn chung**
  - File: `requirements.txt:62-64`
  - Impact: production install kéo pytest/dev packages, attack surface tăng.
  - Fix đề xuất: tách `requirements.txt`, `requirements-dev.txt`, `requirements-optional.txt`.
  - Effort: Low

- **`pip check` conflict**
  - Evidence: command output.
  - Impact: môi trường hiện tại không đáng tin để release.
  - Fix đề xuất: clean venv và lock dependency set.
  - Effort: Medium

## 10. DevOps & CI/CD — Điểm: 5/10

### Điểm mạnh

- Có GitHub Actions trên Windows với Python 3.10/3.11/3.12 tại `.github/workflows/ci.yml:1-17`.
- CI chạy ruff, pytest và pip-audit.

### Vấn đề phát hiện

#### High

- **pip-audit không blocking**
  - File: `.github/workflows/ci.yml:39-40`
  - Impact: known vulnerabilities có thể không chặn merge.
  - Fix đề xuất: bỏ `continue-on-error: true` sau khi baseline sạch.
  - Effort: Low

- **Không chạy pyright dù có config**
  - File: `pyproject.toml:1-6`
  - Impact: type regressions không bị bắt.
  - Fix đề xuất: install pyright và chạy trong CI.
  - Effort: Low

#### Medium

- **Không có release pipeline/signing**
  - Impact: security tool phân phối không ký artifact sẽ tăng supply-chain risk.
  - Fix đề xuất: signed Windows build, SBOM, checksum release.
  - Effort: High

## 11. Tài Liệu — Điểm: 5/10

### Điểm mạnh

- README có hướng dẫn cài đặt, cấu hình và test tại `README.md:61-134`.
- Có tài liệu training workflow trong `docs/`.

### Vấn đề phát hiện

#### High

- **Thiếu production security guide**
  - Impact: user có thể chạy API/auto-response sai cách.
  - Fix đề xuất: thêm `docs/production-hardening.md`.
  - Effort: Medium

- **Thiếu model card và threat model**
  - Impact: không rõ limitation, false positive/negative, evasion risk.
  - Fix đề xuất: thêm `docs/model-card.md`, `docs/threat-model.md`.
  - Effort: Medium

#### Medium

- **Thiếu CONTRIBUTING và CHANGELOG**
  - Impact: khó onboarding và tracking thay đổi.
  - Fix đề xuất: thêm `CONTRIBUTING.md`, `CHANGELOG.md`.
  - Effort: Low

## 12. Production Readiness & Auto-Response — Điểm: 3/10

### Điểm mạnh

- Có response policy theo severity tại `core/auto_responder.py:53-58`.
- Có countdown/abort callback tại `core/auto_responder.py:81-117`.
- Có denylist system process tại `core/auto_responder.py:46-51`.
- Honeypot mặc định dùng prefix `_DECOY_` và thư mục riêng tại `core/honeypot_manager.py:42-63`.

### Vấn đề phát hiện

#### Critical

- **Auto-quarantine/restore chưa đủ an toàn cho production**
  - File: `core/auto_responder.py:119-223`
  - Impact: mất file, restore sai path, manifest tamper, symlink/hardlink attack.
  - Fix đề xuất: copy+verify+fsync+delete, signed manifest, restore path validation, undo audit.
  - Effort: High

#### High

- **Firewall block có thể tạo rule quá rộng**
  - File: `core/auto_responder.py:366-374`
  - Impact: nếu thiếu process path, rule theo remote port `*` có thể ảnh hưởng traffic hợp pháp.
  - Fix đề xuất: không tạo broad rule nếu thiếu executable path; yêu cầu confirmation.
  - Effort: Medium

- **Honeypot cleanup chưa robust**
  - File: `core/honeypot_manager.py:324-344`
  - Impact: stale registry, test fail, uninstall không sạch.
  - Fix đề xuất: stale cleanup mode, retry, registry reconciliation.
  - Effort: Medium

- **Không có resource/quarantine quota**
  - Impact: quarantine hoặc logs có thể chiếm disk.
  - Fix đề xuất: quota, retention policy, disk space guard.
  - Effort: Medium

## Security Deep-Dive

### Attack Surface Analysis

- FastAPI auth/token, scan, upload, report endpoints.
- File path input cho scan, report download và quarantine restore.
- Office/PDF/PE parser nhận file attacker-controlled.
- YARA custom rules và rule updater.
- `joblib` model file loading.
- Threat intelligence HTTP responses từ VirusTotal, MalwareBazaar, ThreatFox, OTX.
- Auto-response actions: kill process, move file, firewall rule.
- GUI action gọi core logic trực tiếp.

### Privilege Escalation Paths

- Nếu tool chạy với quyền admin, bug trong quarantine/restore có thể bị dùng để move/overwrite file nhạy cảm.
- Nếu model path bị attacker thay, `joblib.load()` có thể thành code execution.
- Nếu report path không sanitize, API có thể bị dùng để probing hoặc đọc file trong phạm vi process có quyền.
- Nếu rule updater tải rule không pin hash và thiếu compile validation, attacker có thể ảnh hưởng detection logic.

### Supply Chain Risks

- Dependencies parsing file phức tạp: `oletools`, `PyMuPDF`, `pefile`, `yara-python`.
- Networking/security libs: `python-jose`, `passlib`, `bcrypt`, `httpx`, `requests`.
- ML serialization: `joblib`, `scikit-learn`.
- Không có lockfile làm tăng rủi ro dependency drift.
- CI audit chưa blocking nên vulnerability có thể lọt qua.

### Data Flow Nhạy Cảm

- API keys/JWT secret nằm trong config.
- Scan path, hash, risk score, VT/TI result đi vào reports/cache/logs.
- VT upload có thể gửi file thật ra third-party service.
- Debug trace trong scanner có thể ghi path và feature metadata nếu bật `RANSOMWARE_DEBUG_TRACE`: `core/scanner.py:686-722`.

## ML Model Deep-Dive

### Feature Importance

Code có cơ chế xuất feature importance từ calibrated Random Forest tại `core/ml_engine.py:394-420`. Tuy nhiên ranking hiện tại chưa nên dùng làm quyết định production vì training pipeline có leakage do SMOTE trước split.

### Detection Capability Matrix

| Nhóm ransomware/kịch bản | Khả năng hiện tại | Ghi chú |
|---|---|---|
| File mã hóa high entropy | Khá | Phụ thuộc entropy/chi-square/extension |
| Ransomware đổi extension phổ biến | Khá | Dựa vào suspicious extensions và YARA |
| PE packed/suspicious imports | Trung bình | Fallback import parser yếu nếu thiếu `pefile` |
| Office macro malware | Trung bình | Có oletools nhưng còn gap với `.xls`, obfuscation, DDE |
| PDF exploit/JS | Trung bình-thấp | Parser hiện tại dễ miss object-level JS |
| LOLBin-based ransomware | Trung bình-thấp | Process whitelist quá rộng |
| Low-and-slow encryption | Thấp | Dễ né threshold burst |
| Adversarial padding/header manipulation | Thấp | Chưa có adversarial robustness |

### False Positive / False Negative

- False positive có thể xảy ra với archive nén, media, VM image, backup database, game assets, bulk rename tools.
- False negative có thể xảy ra với partial encryption, selective encryption, entropy padding, giữ extension bình thường, mã hóa chậm dưới threshold.

### Evasion Techniques

- Padding entropy để giống benign.
- Giữ magic bytes/header hợp lệ.
- Dùng extension bình thường.
- Mã hóa theo batch nhỏ dưới threshold process/watchdog.
- Dùng signed LOLBins như PowerShell, WMI, mshta, certutil.
- Tránh YARA string literal hoặc obfuscate macro/PDF JS.

## Lộ Trình Cải Thiện

### Phase 1 — Tuần 1-2: Critical Security Fixes

- [ ] Sửa SMOTE leakage trong `core/ml_engine.py`.
- [ ] Thêm integrity check/signature cho model trước `joblib.load()`.
- [ ] Sửa report path traversal trong `api/routers/reports.py`.
- [ ] Sửa DGA entropy threshold trong `core/network_monitor.py`.
- [ ] Sửa injection detector Windows API constants và 64-bit scan.
- [ ] Harden quarantine move/restore và manifest.
- [ ] Xóa `Malware/` và `quarantine/` khỏi Git tracking/history.

### Phase 2 — Tuần 3-4: Code Quality & Testing

- [ ] Refactor scanner thành pipeline service nhỏ.
- [ ] Tách ML training, prediction, calibration, model registry.
- [ ] Tăng coverage core critical lên trên 80%.
- [ ] Fix failing honeypot test bằng temp registry/config.
- [ ] Thêm pyright vào CI.
- [ ] Chuẩn hóa atomic writes cho config/cache.

### Phase 3 — Tháng 2-3: Architecture & Production

- [ ] Tạo dependency lockfile và tách prod/dev/optional requirements.
- [ ] Bật pip-audit blocking trong CI.
- [ ] Thêm SBOM, checksum và signed Windows release.
- [ ] Thêm health check, metrics, structured logs.
- [ ] Viết production hardening guide.

### Phase 4 — Tháng 3-6: ML & Detection Enhancement

- [ ] Xây real-world benign/malware feature corpus.
- [ ] Thêm model card và adversarial evaluation.
- [ ] Nâng cấp YARA rule quality pipeline.
- [ ] Bổ sung DNS tunneling, beaconing robust, LOLBin coverage.
- [ ] Calibrate threshold bằng telemetry thực tế và false positive review loop.

## Kết Luận

Ransomware Detector v2.0 là một dự án security research có scope rộng và nhiều thành phần đáng giá: ML, YARA, PE/Office analysis, process/network monitoring, honeypot, threat intelligence, API và GUI. Codebase đã có dấu hiệu hardening đáng kể ở auth, CORS và path validation so với mô tả ban đầu.

Tuy nhiên, dự án **chưa sẵn sàng production**. Các điểm cần sửa trước khi triển khai thật là ML leakage, unsafe model deserialization, quarantine safety, detection bugs, dependency reproducibility, coverage thấp ở module critical và artifact nhạy cảm trong Git.

Top 3 rủi ro nếu deploy ngay:

- Auto-response có thể gây mất dữ liệu hoặc block nhầm hệ thống.
- ML metric có thể ảo do data leakage nên quyết định detection không đáng tin.
- Attack surface của chính tool còn tồn tại ở model loading, path handling, quarantine manifest và dependency supply chain.

Top 3 điểm dự án làm tốt:

- Thiết kế detection đa lớp, không phụ thuộc một engine duy nhất.
- Auth/CORS/path scanning đã được cải thiện rõ so với baseline ban đầu.
- Có test suite và CI nền tảng, đủ để phát triển thành quality gate nghiêm túc.

So với industry standards cho endpoint security tools, dự án hiện phù hợp mức **research/lab prototype**. Để đạt mức production, cần thêm hardening, telemetry, signed artifacts, reproducible builds, model governance, incident-safe auto-response và kiểm thử adversarial/large-scale nghiêm ngặt.
