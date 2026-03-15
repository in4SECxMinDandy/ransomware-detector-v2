# 🛡️ Ransomware Entropy Detector v2.2

> Công cụ phát hiện ransomware mạnh mẽ với Machine Learning + YARA Rules + Process Behavior Monitoring + Real-time Protection

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](#)

---

## 📋 Mục lục

1. [Tổng quan](#tổng-quan)
2. [Tính năng chính](#tính-năng-chính)
3. [Kiến trúc](#kiến-trúc)
4. [Cài đặt](#cài-đặt)
5. [Hướng dẫn sử dụng](#hướng-dẫn-sử-dụng)
6. [ML Engine](#ml-engine)
7. [FP Reduction Pipeline](#fp-reduction-pipeline)
8. [YARA Signatures](#yara-signatures)
9. [Process Behavior Detection](#process-behavior-detection)
10. [Real-time Protection](#real-time-protection)
11. [Windows Notifications](#windows-notifications)
12. [GUI](#gui)
13. [Performance](#performance)
14. [Roadmap](#roadmap)
15. [License](#license)

---

## 🎯 Tổng quan

**Ransomware Entropy Detector** là công cụ phòng thủ ransomware đa lớp (multi-layer) với khả năng:

- ✅ **ML-based Detection**: Sử dụng RandomForest với 16 features để phân tích entropy và patterns
- ✅ **YARA Rules**: Tích hợp 20+ YARA signatures cho các ransomware families phổ biến
- ✅ **Process Behavior Monitoring**: Phát hiện hành vi bất thường của process (mass encryption, rapid file ops)
- ✅ **Real-time Protection**: Giám sát filesystem theo thời gian thực với Windows notifications
- ✅ **FP Reduction**: Giảm thiểu False Positives với per-extension thresholds và whitelist

> ⚠️ **Lưu ý**: Đây là công cụ nghiên cứu & phòng thủ. Không thay thế hoàn toàn EDR thương mại.

---

## 🚀 Tính năng chính

### 1. ML Engine (16 Features)

- **CalibratedClassifierCV** với threshold tuning tự động
- **Class weights** chống False Positive (ưu tiên precision ≥95%)
- **SMOTE** để xử lý class imbalance
- 16 features phân biệt compressed vs encrypted files:
  - Shannon Entropy
  - Chi-Square
  - Byte Distribution
  - Compression Ratio
  - Structural Consistency
  - Magic Bytes Validation
  - Và 10 features khác...

### 2. FP Reduction Pipeline (3 tầng)

| Tầng | Chức năng |
|------|-----------|
| **Whitelist** | Bỏ qua system files, fonts, logs, known benign |
| **Per-extension Threshold** | PNG/ZIP/EXE dùng threshold cao hơn |
| **Magic Bytes Validation** | File hợp lệ → giảm probability ×0.70 |

### 3. YARA + Heuristic Fusion

- **20+ built-in YARA rules**: WannaCry, LockBit, BlackCat, Ryuk, REvil, Conti, Cl0p, Play, Rhysida, Akira, BianLian, Medusa, Qilin, Haque...
- **Fallback Python signatures** nếu không có `yara-python`
- **Heuristic boost** khi phát hiện entropy bất thường

### 4. Process Behavior Detection (v2.2 NEW)

Phát hiện ransomware đang hoạt động qua hành vi process:

| Pattern | Mô tả | Severity |
|---------|-------|----------|
| `ENCRYPTION_BURST` | >10 files bị mã hóa trong 30s | 🔴 Critical |
| `EXTENSION_CHANGE` | Đổi extension sang `.locked`, `.encrypted` | 🔴 Critical |
| `RAPID_OPS` | >5 files/second được tạo/sửa | 🟠 High |
| `SUSPICIOUS_PROCESS` | Process chạy từ temp/downloads | 🟠 High |

### 5. Real-time Protection

- **File System Watcher**: Sử dụng `watchdog` library
- **Multi-threaded scanning**: Xử lý song song với ThreadPoolExecutor
- **Debouncing**: 2s cooldown tránh spam
- **Auto-alert**: Kích hoạt callback khi phát hiện threat

### 6. Windows Notifications (v2.2 NEW)

- Toast notifications khi phát hiện ransomware
- Sound alerts theo mức độ nghiêm trọng
- Hỗ trợ: win10toast, plyer, hoặc PowerShell fallback

### 7. Premium GUI

- **Dark mode** với CustomTkinter
- **Threshold slider** điều chỉnh 0.30 → 0.95
- **Real-time stats**: Files analyzed, threats detected
- **Alert Windows**: Chi tiết về từng threat
- **Export**: CSV, PNG, PDF reports

---

## 🏗️ Kiến trúc

```
ransomware_detector_v2/
├── core/
│   ├── feature_extractor.py    # 16 features extraction
│   ├── ml_engine.py            # ML model + threshold optimizer
│   ├── fp_reducer.py           # 3-tầng FP reduction
│   ├── yara_engine.py          # YARA rules + fallback
│   ├── scanner.py              # ML + YARA + Heuristic fusion
│   ├── process_monitor.py      # v2.2: Process behavior detection
│   ├── notifications.py        # v2.2: Windows notifications
│   ├── watchdog_monitor.py    # v2.2: Real-time protection
│   ├── report_generator.py    # CSV/PNG export
│   ├── pdf_reporter.py        # PDF export
│   └── smote_trainer.py       # SMOTE oversampling
├── gui/
│   ├── main_window.py          # Premium GUI
│   └── whitelist_editor.py     # Whitelist management
├── models/
│   └── rf_ransomware_detector.joblib  # Trained model
├── data/
│   └── whitelist.json          # File whitelist
├── train_model.py              # Model training script
├── main.py                     # Entry point
└── requirements.txt            # Dependencies
```

---

## 💾 Cài đặt

### Yêu cầu

- **Python 3.8+**
- **Windows 10/11** (notifications và process monitoring tối ưu cho Windows)

### Bước 1: Clone và cài đặt dependencies

```bash
# Clone repository
git clone https://github.com/yourusername/ransomware_detector_v2.git
cd ransomware_detector_v2

# Tạo virtual environment (khuyến nghị)
python -m venv venv
venv\Scripts\activate  # Windows

# Cài đặt dependencies
pip install -r requirements.txt
```

### Bước 2: Train model (lần đầu)

```bash
python train_model.py
```

### Bước 3: Chạy ứng dụng

```bash
python main.py
```

### Optional: YARA native (tốc độ cao hơn)

```bash
pip install yara-python
```

---

## 📖 Hướng dẫn sử dụng

### Mode 1: Manual Scan

1. Click **"Select Folder"** để chọn thư mục cần quét
2. Chọn **Scan Mode**: Full Scan (đệ quy) hoặc Quick Scan
3. Điều chỉnh **Threshold** nếu cần (mặc định: 0.65)
4. Click **"Start Scan"**
5. Xem kết quả trong bảng bên dưới

### Mode 2: Real-time Protection

1. Click **"Select Folder"** để chọn thư mục giám sát
2. Click **"Start Protection"**
3. Tool sẽ giám sát và:
   - Gửi **Windows notification** khi phát hiện threat
   - Hiển thị **Behavior Alert window** với chi tiết process
   - Ghi log vào console

### Adjusting Sensitivity

| Profile | Threshold Delta | Use Case |
|---------|----------------|----------|
| **Balanced** | +0.00 | Cân bằng FN/FP |
| **High Sensitivity** | -0.05 | Ưu tiên bắt ransomware |
| **Paranoid** | -0.10 | Giám sát nghiêm ngặt |

### Export Reports

- **CSV**: Click "Export CSV"
- **PNG**: Click "Export PNG"  
- **PDF**: Click "Export PDF"

---

## 🤖 ML Engine

### Features (16)

| # | Feature | Mô tả |
|---|---------|-------|
| 1 | Shannon Entropy | Entropy trung bình |
| 2 | Chi-Square (log) | Byte distribution uniformity |
| 3 | Mean Byte | Giá trị trung bình byte |
| 4 | Byte Variance | Phương sai byte |
| 5 | Serial Correlation | Tương quan byte liên tiếp |
| 6 | Chunk Entropy StdDev | Độ lệch entropy |
| 7 | Chunk Entropy Max | Entropy cao nhất |
| 8 | Chunk Entropy Min | Entropy thấp nhất |
| 9 | High Entropy Ratio | Tỷ lệ chunk entropy cao |
| 10 | Magic Bytes Mismatch | Magic bytes không khớp |
| 11 | Normalized Entropy | Entropy chuẩn hóa |
| 12 | Byte Distribution Mode | Mode phân bố byte |
| 13 | Compression Ratio Sim | Ẩn tính nén |
| 14 | Structural Consistency | Nhất quán cấu trúc |
| 15 | Extension Entropy Delta | Chênh lệch entropy vs extension |
| 16 | Is Known Benign Format | Format known benign |

### Model

- **Algorithm**: RandomForestClassifier
- **Calibration**: CalibratedClassifierCV
- **Threshold**: Auto-tuned cho Precision ≥95%

---

## 🔍 FP Reduction Pipeline

### Tầng 1: Whitelist

Bỏ qua các file hệ thống:

```python
WHITELIST_PATHS = [
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
]
```

### Tầng 2: Per-extension Threshold

| Extension | Threshold | Lý do |
|-----------|-----------|-------|
| `.png`, `.jpg` | 0.85 | Entropy cao tự nhiên |
| `.zip`, `.7z` | 0.80 | Compressed files |
| `.exe`, `.dll` | 0.75 | PE files |
| `.txt`, `.doc` | 0.65 | Normal documents |

### Tầng 3: Magic Bytes Validation

```python
MAGIC_BYTES = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff",
    "zip": b"PK\x03\x04",
    "pdf": b"%PDF",
}
```

Nếu magic bytes hợp lệ → `probability *= 0.70`

---

## 🎯 YARA Signatures

### Built-in Rules

| Family | Aliases |
|--------|---------|
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
| Haque | haque |

### Custom Rules

Thêm rules vào `core/yara_engine.py`:

```python
BUILTIN_YARA_RULES_SOURCE = """
rule custom_ransomware {
    strings:
        $s1 = "YOUR_CUSTOM_STRING" nocase
    condition:
        any of them
}
"""
```

---

## ⚙️ Process Behavior Detection

### Cách hoạt động

```
File Event → Get PID → Get Process Info → Check Patterns → Alert
```

### Patterns

1. **ENCRYPTION_BURST**
   - Phát hiện: >10 files bị modify trong 30s
   - Kèm: entropy >7.0 (encrypted)
   - Action: Critical alert

2. **EXTENSION_CHANGE**
   - Phát hiện: Đổi extension sang suspicious
   - Examples: `.doc` → `.locked`, `.pdf` → `.encrypted`
   - Action: Critical alert

3. **RAPID_OPS**
   - Phát hiện: >5 files/second
   - Action: High alert

4. **SUSPICIOUS_PROCESS**
   - Phát hiện: Process chạy từ temp/downloads
   - Kèm: Ghi file entropy cao
   - Action: High alert

### Known Benign Processes

```python
KNOWN_BENIGN_PROCESSES = [
    "notepad.exe", "code.exe", "chrome.exe",
    "firefox.exe", "explorer.exe", "cmd.exe",
    "powershell.exe", "python.exe", ...
]
```

---

## 🔔 Windows Notifications

### Requirements

```bash
pip install win10toast plyer
```

### Notification Levels

| Level | Sound | Use Case |
|-------|-------|----------|
| LOW | None | Info messages |
| MEDIUM | SystemAsterisk | Warnings |
| HIGH | SystemExclamation | Threats |
| CRITICAL | SystemHand | Critical alerts |

### Usage

```python
from core.notifications import get_notifier

notifier = get_notifier()
notifier.notify(
    title="Ransomware Detected!",
    message="Mass encryption detected",
    severity="critical"
)
```

---

## 🖥️ GUI

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

### Screenshots

(Thêm screenshots vào đây sau khi chụp)

---

## ⚡ Performance

| Metric | Target |
|--------|--------|
| Precision | ≥ 95% |
| False Positive Rate | < 5% |
| Recall | ≥ 90% |
| Scan Speed | ~100 files/second |
| Memory Usage | < 200MB |

### Optimization Tips

1. **GPU**: Không cần GPU cho inference
2. **Multi-threading**: Tự động với 8 threads
3. **Incremental Scan**: Chỉ scan file mới (sắp có)

---

## 🗺️ Roadmap

- [ ] Retrain trên malware dataset thực tế (VirusTotal, MalwareBazaar)
- [ ] Thêm dynamic behavior signals (file rename bursts, mass IO)
- [ ] Rule pack updater (auto update YARA rules)
- [ ] Export forensic bundle (hashes + IOC report)
- [ ] **System Tray integration** (v2.3)
- [ ] **Auto-response actions** (quarantine, kill process) (v2.3)
- [   **Network traffic analysis** (v2.4)

---

## 📄 License

MIT License - Xem [LICENSE](LICENSE) để biết thêm chi tiết.

---

## 👤 Author

- **Name**: Your Name
- **Email**: your.email@example.com
- **GitHub**: [yourusername](https://github.com/yourusername)

---

## 🙏 Acknowledgments

- [scikit-learn](https://scikit-learn.org/) - ML framework
- [YARA](https://virustotal.github.io/yara/) - Pattern matching
- [watchdog](https://pythonhosted.org/watchdog/) - File system monitoring
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) - Modern GUI
- [psutil](https://psutil.readthedocs.io/) - Process monitoring

---

**⭐ Nếu dự án hữu ích, hãy star để ủng hộ!**
