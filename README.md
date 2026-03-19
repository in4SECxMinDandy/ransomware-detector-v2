# Ransomware Entropy Detector v2.5

> Cong cu phat hien ransomware manh me voi Machine Learning + YARA Rules + Process Behavior Monitoring + Real-time Protection + Network Analysis

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Platform: Windows](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
[![Tests](https://img.shields.io/badge/Tests-116%20passed-brightgreen.svg)](#testing)
[![Coverage](https://img.shields.io/badge/Coverage-80%25%2B-yellowgreen.svg)](#testing)

---

## Muc luc

1. [Tong quan](#tong-quan)
2. [Tinh nang chinh](#tinh-nang-chinh)
3. [Kien truc](#kien-truc)
4. [Cai dat](#cai-dat)
5. [Huong dan su dung](#huong-dan-su-dung)
6. [ML Engine](#ml-engine)
7. [FP Reduction Pipeline](#fp-reduction-pipeline)
8. [YARA Signatures](#yara-signatures)
9. [Process Behavior Detection](#process-behavior-detection)
10. [Real-time Protection](#real-time-protection)
11. [Windows Notifications](#windows-notifications)
12. [GUI](#gui)
13. [Performance](#performance)
14. [Testing](#testing)
15. [Roadmap](#roadmap)
16. [License](#license)

---

## Tong quan

**Ransomware Entropy Detector** la cong cu phong thu ransomware da lop (multi-layer) voi kha nang:

- ✅ **ML-based Detection**: Su dung RandomForest voi 16 features de phan tich entropy va patterns
- ✅ **YARA Rules**: Tich hop 20+ YARA signatures cho cac ransomware families pho bien
- ✅ **Process Behavior Monitoring**: Phat hien hanh vi bat thuong cua process (mass encryption, rapid file ops)
- ✅ **Real-time Protection**: Giam sat filesystem theo thoi gian thuc voi Windows notifications
- ✅ **FP Reduction**: Giam thieu False Positives voi per-extension thresholds va whitelist
- ✅ **Incremental Scan**: Chi quet file moi hoac da sua doi tu lan quet truoc
- ✅ **Network Traffic Analysis**: Phat hien C2 indicators, DGA domains, beaconing patterns

> ⚠️ **Luu y**: Day la cong cu nghien cuu & phong thu. Khong thay the hoan toan EDR thuong mai.

---

## Tinh nang chinh

### 1. ML Engine (16 Features)

- **CalibratedClassifierCV** voi threshold tuning tu dong
- **Class weights** chong False Positive (uu tien precision ≥95%)
- **SMOTE** de xu ly class imbalance
- 16 features phan biet compressed vs encrypted files:
  - Shannon Entropy
  - Chi-Square
  - Byte Distribution
  - Compression Ratio
  - Structural Consistency
  - Magic Bytes Validation
  - Va 10 features khac...

### 2. FP Reduction Pipeline (3 tang)

| Tang | Chuc nang |
| --- | --- |
| **Whitelist** | Bo qua system files, fonts, logs, known benign |
| **Per-extension Threshold** | PNG/ZIP/EXE dung threshold cao hon |
| **Magic Bytes Validation** | File hop le → giam probability ×0.70 |

### 3. YARA + Heuristic Fusion

- **20+ built-in YARA rules**: WannaCry, LockBit, BlackCat, Ryuk, REvil, Conti, Cl0p, Play, Rhysida, Akira, BianLian, Medusa, Qilin...
- **Fallback Python signatures** neu khong co `yara-python`
- **Heuristic boost** khi phat hien entropy bat thuong

### 4. Process Behavior Detection

Phat hien ransomware dang hoat dong qua hanh vi process:

| Pattern | Mo ta | Severity |
| --- | --- | --- |
| `ENCRYPTION_BURST` | >10 files bi ma hoa trong 30s | 🔴 Critical |
| `EXTENSION_CHANGE` | Doi extension sang `.locked`, `.encrypted` | 🔴 Critical |
| `RAPID_OPS` | >5 files/second duoc tao/sua | 🟠 High |
| `SUSPICIOUS_PROCESS` | Process chay tu temp/downloads | 🟠 High |

### 5. Real-time Protection

- **File System Watcher**: Su dung `watchdog` library
- **Multi-threaded scanning**: Xu ly song song voi ThreadPoolExecutor
- **Debouncing**: 2s cooldown tranh spam
- **Auto-alert**: Kich hoat callback khi phat hien threat

### 6. Windows Notifications

- Toast notifications khi phat hien ransomware
- Sound alerts theo muc do nghiem trong
- Ho tro: win10toast, plyer, hoac PowerShell fallback

### 7. Incremental Scan (v2.5 NEW)

- Chi quet file moi hoac da sua doi tu lan quet truoc
- Su dung `data/scan_cache.json` de luu trang thai
- Tang toc do quet len 3-5 lan cho cac he thong co nhieu file

### 8. Premium GUI

- **Dark mode** voi CustomTkinter
- **Threshold slider** dieu chinh 0.30 → 0.95
- **Real-time stats**: Files analyzed, threats detected
- **Alert Windows**: Chi tiet ve tung threat
- **Export**: CSV, PNG, PDF reports

---

## Kien truc

```
ransomware_detector_v2/
├── core/
│   ├── feature_extractor.py    # 16 features extraction
│   ├── ml_engine.py            # ML model + threshold optimizer
│   ├── fp_reducer.py           # 3-tang FP reduction
│   ├── yara_engine.py          # YARA rules + fallback
│   ├── scanner.py              # ML + YARA + Heuristic fusion
│   ├── process_monitor.py      # Process behavior detection
│   ├── network_monitor.py       # Network C2 detection
│   ├── notifications.py        # Windows notifications
│   ├── watchdog_monitor.py    # Real-time protection
│   ├── config_manager.py       # Centralized configuration
│   ├── logger_setup.py         # Structured logging
│   └── ...
├── gui/
│   ├── main_window.py          # Premium GUI
│   └── tray_manager.py         # System tray
├── tests/
│   ├── conftest.py              # Shared pytest fixtures
│   ├── test_feature_extractor.py
│   ├── test_fp_reducer.py
│   ├── test_ml_engine.py
│   ├── test_yara_engine.py
│   └── test_dynamic_signals.py
├── models/
│   └── rf_ransomware_detector.joblib  # Trained model
├── data/
│   ├── whitelist.json           # File whitelist
│   ├── scan_cache.json          # Incremental scan cache
│   └── config.json              # Runtime configuration
├── train_model.py               # Model training script
├── main.py                      # Entry point
└── requirements.txt             # Dependencies
```

---

## Cai dat

### Yeu cau

- **Python 3.8+**
- **Windows 10/11** (notifications va process monitoring toi uu cho Windows)

### Buoc 1: Clone va cai dat dependencies

```bash
# Clone repository
git clone https://github.com/yourusername/ransomware_detector_v2.git
cd ransomware_detector_v2

# Tao virtual environment (khuyen nghi)
python -m venv venv
venv\Scripts\activate  # Windows

# Cai dat dependencies
pip install -r requirements.txt
```

### Buoc 2: Train model (lan dau)

```bash
python train_model.py
```

### Buoc 3: Chay ung dung

```bash
python main.py
```

### Optional: YARA native (toc do cao hon)

```bash
pip install yara-python
```

---

## Huong dan su dung

### Mode 1: Manual Scan

1. Click **"Select Folder"** de chon thu muc can quet
2. Chon **Scan Mode**: Full Scan (de quy), Quick Scan, hoac Incremental Scan
3. Dieu chinh **Threshold** neu can (mac dinh: 0.65)
4. Click **"Start Scan"**
5. Xem ket qua trong bang ben duoi

### Mode 2: Real-time Protection

1. Click **"Select Folder"** de chon thu muc giam sat
2. Click **"Start Protection"**
3. Tool se giam sat va:
   - Gui **Windows notification** khi phat hien threat
   - Hien thi **Behavior Alert window** voi chi tiet process
   - Ghi log vao console

### Adjusting Sensitivity

| Profile | Threshold Delta | Use Case |
| --- | --- | --- |
| **Balanced** | +0.00 | Can bang FN/FP |
| **High Sensitivity** | -0.05 | Uu tien bat ransomware |
| **Paranoid** | -0.10 | Giam sat nghiem nhat |

### Export Reports

- **CSV**: Click "Export CSV"
- **PNG**: Click "Export PNG"
- **PDF**: Click "Export PDF"

---

## ML Engine

### Features (16)

| # | Feature | Mo ta |
| --- | --- | --- |
| 1 | Shannon Entropy | Entropy trung binh |
| 2 | Chi-Square (log) | Byte distribution uniformity |
| 3 | Mean Byte | Gia tri trung binh byte |
| 4 | Byte Variance | Phuong sai byte |
| 5 | Serial Correlation | Tuong quan byte lien tiep |
| 6 | Chunk Entropy StdDev | Do lech entropy |
| 7 | Chunk Entropy Max | Entropy cao nhat |
| 8 | Chunk Entropy Min | Entropy thap nhat |
| 9 | High Entropy Ratio | Ty le chunk entropy cao |
| 10 | Magic Bytes Mismatch | Magic bytes khong khop |
| 11 | Normalized Entropy | Entropy chuan hoa |
| 12 | Byte Distribution Mode | Mode phan bo byte |
| 13 | Compression Ratio Sim | An tinh nen |
| 14 | Structural Consistency | Nhat quan cau truc |
| 15 | Extension Entropy Delta | Chenh lech entropy vs extension |
| 16 | Is Known Benign Format | Format known benign |

### Model

- **Algorithm**: RandomForestClassifier
- **Calibration**: CalibratedClassifierCV
- **Threshold**: Auto-tuned cho Precision ≥95%

---

## FP Reduction Pipeline

### Tang 1: Whitelist

Bo qua cac file he thong:

```python
WHITELIST_PATHS = [
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
]
```

### Tang 2: Per-extension Threshold

| Extension | Threshold | Ly do |
| --- | --- | --- |
| `.png`, `.jpg` | 0.85 | Entropy cao tu nhien |
| `.zip`, `.7z` | 0.80 | Compressed files |
| `.exe`, `.dll` | 0.75 | PE files |
| `.txt`, `.doc` | 0.65 | Normal documents |

### Tang 3: Magic Bytes Validation

```python
MAGIC_BYTES = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff",
    "zip": b"PK\x03\x04",
    "pdf": b"%PDF",
}
```

Neu magic bytes hop le → `probability *= 0.70`

---

## YARA Signatures

### Built-in Rules

| Family | Aliases |
| --- | --- |
| WannaCry | wncry, wannacry |
| LockBit | lockbit, lockbit2, lockbit3 |
| BlackCat | blackcat, alphv |
| Ryuk | ryuk |
| REvil | revil, sodinokibi |
| Conti | conti |
| Cl0p | cl0p, clop |
| Play | play |
| Rhysida | rhysida |
| Akira | akira |
| BianLian | bianlian |
| Medusa | medusa |
| Qilin | qilin |

---

## Process Behavior Detection

### Cach hoat dong

```
File Event → Get PID → Get Process Info → Check Patterns → Alert
```

### Patterns

1. **ENCRYPTION_BURST**
   - Phat hien: >10 files bi modify trong 30s
   - Kem: entropy >7.0 (encrypted)
   - Action: Critical alert

2. **EXTENSION_CHANGE**
   - Phat hien: Doi extension sang suspicious
   - Examples: `.doc` → `.locked`, `.pdf` → `.encrypted`
   - Action: Critical alert

3. **RAPID_OPS**
   - Phat hien: >5 files/second
   - Action: High alert

4. **SUSPICIOUS_PROCESS**
   - Phat hien: Process chay tu temp/downloads
   - Kem: Ghi file entropy cao
   - Action: High alert

---

## Network Traffic Analysis (v2.4)

### C2 Detection Features

- **DGA Domain Detection**: Tinh toan Shannon entropy cua domain de phat hien Domain Generation Algorithms
- **Beaconing Detection**: Phat hien request den known malicious IPs (Feodo Tracker C2)
- **Connection Rate Limiting**: Canh bao neu qua nhieu connections trong thoi gian ngan
- **DNS Tunneling Indicators**: Phat hien DNS queries bat thuong

---

## Windows Notifications

### Requirements

```bash
pip install win10toast plyer
```

### Notification Levels

| Level | Sound | Use Case |
| --- | --- | --- |
| LOW | None | Info messages |
| MEDIUM | SystemAsterisk | Warnings |
| HIGH | SystemExclamation | Threats |
| CRITICAL | SystemHand | Critical alerts |

---

## GUI

### Layout

```
┌─────────────────────────────────────────────────────────────┐
│  HEADER: Logo + Title + Version + Status badge              │
├──────────────┬──────────────────────────────────────────────┤
│  LEFT PANEL  │  RIGHT: Results Table                        │
│  - Directory │                                              │
│  - Scan mode │  - Status | File | Path | Risk | Prob | H   │
│  - Threshold │                                              │
│    Slider    │                                              │
│  - Start btn │                                              │
│  - Stats     │                                              │
│  - Watchdog  │                                              │
│  - FP Info   │                                              │
│  - Export    │                                              │
│  - ML Engine │                                              │
├──────────────┴──────────────────────────────────────────────┤
│  BOTTOM: Log console (real-time events)                     │
└─────────────────────────────────────────────────────────────┘
```

---

## Performance

| Metric | Target |
| --- | --- |
| Precision | ≥ 95% |
| False Positive Rate | < 5% |
| Recall | ≥ 90% |
| Scan Speed | ~100 files/second |
| Memory Usage | < 200MB |

---

## Testing

### Unit Tests

116 unit tests voi coverage 80%+ cho tat ca core modules.

```bash
# Chay tat ca tests
pytest tests/ -v

# Voi coverage report
pytest tests/ --cov=core --cov-report=term-missing
```

### Test Modules

| File | Mo ta |
| --- | --- |
| `test_feature_extractor.py` | 49 tests cho 16 features extraction |
| `test_fp_reducer.py` | 24 tests cho FP reduction pipeline |
| `test_ml_engine.py` | 15 tests cho ML engine |
| `test_yara_engine.py` | 18 tests cho YARA signatures |
| `test_dynamic_signals.py` | 16 tests cho process behavior |

### Test Fixtures

Shared fixtures trong `conftest.py`: `sample_safe_file`, `sample_random_file`, `sample_png_header`, `sample_pdf_header`, `sample_zip_header`, `temp_dir`, `mock_engine`.

---

## Roadmap

### v2.5 (Current)

- [x] **Unit test suite** voi 116 tests va 80%+ coverage ✅
- [x] **Incremental scan** — chi scan file moi/da sua ✅
- [x] **Config manager** — centralized configuration ✅
- [x] **Logger setup** — structured logging ✅
- [x] **Bug fixes**: entropy formula, file handle leak, exception handling ✅

- [x] ~~Retrain tren malware dataset thuc te (VirusTotal, MalwareBazaar)~~
- [x] **Dynamic behavior signals** (file rename bursts, mass IO) (v2.2) ✅
- [x] **Rule pack updater** (auto update YARA rules) (v2.3) ✅
- [x] **Export forensic bundle** (hashes + IOC report) (v2.3) ✅
- [x] **System Tray integration** (v2.3) ✅
- [x] **Auto-response actions** (quarantine, kill process) (v2.3) ✅
- [x] **Network traffic analysis** (C2 detection, DGA, beacon) (v2.4) ✅

---

## License

MIT License - Xem [LICENSE](LICENSE) de biet them chi tiet.

---

## Author

- **Name**: Hà Quang Minh
- **Email**: minhhq.in4sec@gmail.com
- **GitHub**: https://github.com/in4SECxMinDandy

---

## Acknowledgments

- [scikit-learn](https://scikit-learn.org/) - ML framework
- [YARA](https://virustotal.github.io/yara/) - Pattern matching
- [watchdog](https://pythonhosted.org/watchdog/) - File system monitoring
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) - Modern GUI
- [psutil](https://psutil.readthedocs.io/) - Process monitoring

---

**⭐ Nếu thấy hưu ích, hãy cho tôi 1 ⭐ để ủng hộ!**
