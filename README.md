# Ransomware Entropy Detector v2.5

> Công cụ phát hiện ransomware mạnh mẽ với Machine Learning kết hợp YARA Rules, giám sát hành vi Process, bảo vệ thời gian thực và phân tích mạng.

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Platform: Windows](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
[![Tests](https://img.shields.io/badge/Tests-116%20passed-brightgreen.svg)](#kiểm-tra---testing)
[![Coverage](https://img.shields.io/badge/Coverage-80%25%2B-yellowgreen.svg)](#kiểm-tra---testing)

---

## Mục lục

1. [Tổng quan](#t%E1%BB%95ng-quan)
2. [Tính năng chính](#t%C3%ADnh-n%C4%83ng-ch%C3%ADnh)
3. [Kiến trúc](#ki%E1%BA%BFn-tr%C3%BAc)
4. [Cài đặt](#cài-đặt)
5. [Hướng dẫn sử dụng](#h%C6%B0%E1%BB%9Bng-d%E1%BA%ABn-s%E1%BB%AD-d%E1%BB%A5ng)
6. [Máy học - ML Engine](#m%C3%A1y-h%E1%BB%8Dc---ml-engine)
7. [Giảm thiểu False Positive - FP Reduction](#gi%E1%BA%A3m-thi%E1%BB%83u-false-positive---fp-reduction)
8. [Quy tắc YARA](#quy-t%E1%BA%AFc-yara)
9. [Phát hiện hành vi Process](#ph%C3%A1t-hi%E1%BB%87n-h%C3%A0nh-vi-process)
10. [Phân tích mạng - Network Analysis](#ph%C3%A2n-t%C3%ADch-m%E1%BA%A1ng---network-analysis)
11. [Bảo vệ thời gian thực - Real-time Protection](#b%E1%BA%A3o-v%E1%BB%87-th%E1%BB%9Di-gian-th%E1%BB%B1c---real-time-protection)
12. [Tự động phản ứng - Auto-Response](#t%E1%BB%B1-%C4%91%E1%BB%99ng-ph%E1%BA%A3n-%E1%BB%A9ng---auto-response)
13. [Thông báo Windows](#th%C3%B4ng-b%C3%A1o-windows)
14. [Giao diện đồ họa - GUI](#giao-di%E1%BB%87n-%C4%91%E1%BB%93-h%E1%BB%8Da---gui)
15. [Hiệu năng](#hi%E1%BB%87u-n%C4%83ng)
16. [Kiểm tra - Testing](#ki%E1%BB%83m-tra---testing)
17. [Lộ trình phát triển - Roadmap](#l%E1%BB%99-tr%C3%ACnh-ph%C3%A1t-tri%E1%BB%83n---roadmap)
18. [Giấy phép - License](#gi%E1%BA%A5y-ph%C3%A9p---license)

---

## Tổng quan

**Ransomware Entropy Detector** là công cụ phòng chống ransomware đa lớp (multi-layer) với khả năng:

- **Phát hiện dựa trên Máy học (ML)**: Sử dụng RandomForest với 16 đặc trưng để phân tích entropy và patterns của file
- **Quy tắc YARA**: Tích hợp 20+ chữ ký YARA cho các nhóm ransomware phổ biến
- **Giám sát hành vi Process**: Phát hiện hành vi bất thường của process như mã hóa hàng loạt, thao tác file nhanh
- **Bảo vệ thời gian thực**: Giám sát filesystem liên tục kèm thông báo Windows
- **Giảm thiểu False Positive**: Sử dụng ngưỡng riêng cho từng loại file và danh sách whitelist
- **Quét tăng dần (Incremental Scan)**: Chỉ quét file mới hoặc đã sửa đổi từ lần quét trước
- **Phân tích mạng**: Phát hiện C2 indicators, DGA domains, beaconing patterns
- **Tự động phản ứng**: Cách ly file, kết thúc process độc hại, chặn mạng

> **Lưu ý quan trọng**: Đây là công cụ nghiên cứu và phòng thủ. Không thay thế hoàn toàn các giải pháp EDR thương mại.

---

## Tính năng chính

### 1. Máy học - ML Engine (16 đặc trưng)

- **CalibratedClassifierCV** với ngưỡng tự điều chỉnh
- **Class weights** chống False Positive (ưu tiên precision ≥95%)
- **SMOTE** để xử lý mất cân bằng dữ liệu
- 16 đặc trưng phân biệt file nén vs file mã hóa:
  - Shannon Entropy (Entropy thông tin)
  - Chi-Square (Phân bố byte)
  - Byte Distribution (Phân bố byte)
  - Compression Ratio (Tỷ lệ nén)
  - Structural Consistency (Tính nhất quán cấu trúc)
  - Magic Bytes Validation (Xác thực magic bytes)
  - Và 10 đặc trưng khác...

### 2. Giảm thiểu False Positive - FP Reduction (3 lớp)

| Lớp | Chức năng | Mô tả |
| --- | --- | --- |
| **Whitelist** | Bỏ qua file hệ thống | System files, fonts, logs, known benign |
| **Per-extension Threshold** | Ngưỡng theo đuôi file | PNG/ZIP/EXE dùng ngưỡng cao hơn |
| **Magic Bytes Validation** | Xác thực file hợp lệ | File hop le → giảm probability ×0.70 |

### 3. Tích hợp YARA + Heuristic

- **20+ quy tắc YARA tích hợp sẵn**: WannaCry, LockBit, BlackCat, Ryuk, REvil, Conti, Cl0p, Play, Rhysida, Akira, BianLian, Medusa, Qilin...
- **Signature Python thay thế** nếu không có `yara-python`
- **Heuristic boost** khi phát hiện entropy bất thường

### 4. Phát hiện hành vi Process

Phát hiện ransomware đang hoạt động qua hành vi của process:

| Pattern | Mô tả | Mức độ nghiêm trọng |
| --- | --- | --- |
| `ENCRYPTION_BURST` | >10 files bị mã hóa trong 30 giây | 🔴 Nghiêm trọng |
| `EXTENSION_CHANGE` | Đổi extension sang `.locked`, `.encrypted` | 🔴 Nghiêm trọng |
| `RAPID_OPS` | >5 files/giây được tạo/sửa | 🟠 Cao |
| `SUSPICIOUS_PROCESS` | Process chạy từ temp/downloads | 🟠 Cao |

### 5. Phân tích mạng - Network Analysis

- **DGA Domain Detection**: Tính toán Shannon entropy của domain để phát hiện Domain Generation Algorithms
- **Beaconing Detection**: Phát hiện request đến known malicious IPs (Feodo Tracker C2)
- **Connection Rate Limiting**: Cảnh báo nếu quá nhiều kết nối trong thời gian ngắn
- **DNS Tunneling Indicators**: Phát hiện DNS queries bất thường

### 6. Bảo vệ thời gian thực - Real-time Protection

- **File System Watcher**: Sử dụng thư viện `watchdog`
- **Đa luồng xử lý**: Xử lý song song với ThreadPoolExecutor
- **Debouncing**: 2 giây cooldown tránh spam
- **Tự động cảnh báo**: Kích hoạt callback khi phát hiện mối đe dọa

### 7. Tự động phản ứng - Auto-Response

- **Cách ly file (Quarantine)**: Di chuyển file độc hại vào thư mục cách ly
- **Kết thúc Process**: Dừng process độc hại một cách an toàn
- **Chặn mạng**: Sử dụng Windows Firewall để ngăn chặn kết nối C2
- **Khôi phục file**: Hoàn tác cách ly khi cần thiết

### 8. Quét tăng dần - Incremental Scan

- Chỉ quét file mới hoặc đã sửa đổi từ lần quét trước
- Sử dụng `data/scan_cache.json` để lưu trạng thái
- Tăng tốc độ quét lên 3-5 lần cho các hệ thống có nhiều file

### 9. Phân tích PE (Portable Executable)

- Kiểm tra entropy của các section trong file PE
- Phát hiện packer và obfuscation
- Phân tích import table bất thường

### 10. Phát hiện Injection

- Phát hiện DLL Injection và Process Injection
- Kiểm tra code integrity
- Giám sát remote thread creation

### 11. Xuất báo cáo pháp y

- **CSV**: Danh sách chi tiết các mối đe dọa
- **PNG**: Ảnh chụp giao diện kết quả
- **PDF**: Báo cáo tổng hợp chuyên nghiệp
- **Bundle**: Hashes + IOC report cho forensic analysis

### 12. Giao diện đồ họa - Premium GUI

- **Dark mode** với CustomTkinter
- **Threshold slider** điều chỉnh 0.30 → 0.95
- **Thống kê thời gian thực**: Files analyzed, threats detected
- **Cửa sổ cảnh báo**: Chi tiết về từng mối đe dọa
- **Xuất báo cáo**: CSV, PNG, PDF reports
- **11 tab GUI**: Dashboard, Scan, Alerts, Settings, Quarantine, Reports, Logs, Office Scanner, Entropy Watch, Honeypot, ML Training

### 13. Phân tích tài liệu Office

- Quét file `.doc/.docx/.docm/.xls/.xlsx/.xlsm/.ppt/.pptx/.pdf/.rtf`
- Phát hiện **Auto-Execution triggers**: `AutoOpen`, `Workbook_Open`, `Document_Open`
- Phân tích **VBA macro** bằng `oletools` (mraptor, olevba)
- Phát hiện **JavaScript nhúng** và `/OpenAction`, `/AA` trong PDF
- Phát hiện **shellcode** trong RTF bằng `rtfobj`
- Tích hợp **YARA rules** chuyên dụng cho Office files
- Mã màu threat level: CLEAN 🟢 | SUSPICIOUS 🟡 | MALICIOUS 🔴

### 14. Giám sát Entropy thời gian thực

- Tính **Shannon Entropy** `H = -Σ p_i log₂ p_i` sau mỗi sự kiện file modification
- Ngưỡng cảnh báo: entropy > **7.5** trên **5 file liên tiếp** trong vòng **30 giây**
- Biểu đồ line chart real-time (cập nhật mỗi 2 giây)
- **Danger Level** indicator (0-10) với màu gradient xanh → đỏ
- Popup cảnh báo khi phát hiện burst encryption
- Ghi log chi tiết vào `logs/entropy_alerts.log`

### 15. Tích hợp VirusTotal API

- Cross-check SHA256 với **VirusTotal API v3**
- Cache kết quả vào `data/vt_cache.json` (TTL 24h)
- Rate limiting: **4 request/phút** (free tier)
- Hiển thị badge: `VT: 12/72 engines detected`
- Hyperlink trực tiếp đến trang phân tích VirusTotal.com

### 16. Honeypot File Monitoring

- **Tự động tạo file mồi nhử** với tên hấp dẫn: `passwords.xlsx`, `backup.docx`, `financial_report_2025.pdf`, `company_secrets.txt`
- Đặt tại Desktop, Documents, Downloads của user
- Giám sát mọi sự kiện `READ`, `WRITE`, `DELETE`
- Khi phát hiện truy cập → trigger `auto_responder` ngay lập tức
- Badge đếm số lần trigger trong 24h
- Bảng timeline lịch sử truy cập (process, PID, timestamp)

### 17. REST API (FastAPI)

- Xác thực **dual-layer**: API Key (`X-API-Key`) + **JWT Bearer Token**
- RBAC: role `admin` (full access), `reader` (GET only)
- Endpoints: `POST /scan/file`, `POST /scan/hash`, `GET /status`, `GET /alerts`, `GET/POST /honeypots`, `GET /reports/{id}`
- Auto-generated docs tại `/docs` (Swagger UI)
- Toggle bật/tắt trực tiếp từ GUI Settings

### 18. ML Incremental Learning (Feedback Loop)

- Người dùng đánh dấu kết quả: **Correct / Incorrect** (False Positive / False Negative)
- Mẫu feedback lưu vào `data/feedback_samples.csv`
- **Auto-retrain** khi đạt ngưỡng 50 mẫu (tùy chọn)
- Model versioning: `models/ml_model_YYYYMMDD.pkl`
- Biểu đồ accuracy history, rollback và xóa phiên bản cũ

### 19. Claude AI Analysis (Anthropic Integration)

- Tích hợp **Claude Sonnet 4.6** qua proxy `taphoaapi.info.vn` để phân tích mối đe dọa ransomware
- Model có sẵn:
  - `claude-sonnet-4-6` — Cân bằng (mặc định, khuyến nghị)
  - `claude-opus-4-6` — Mạnh nhất, phân tích chuyên sâu
  - `claude-haiku-4-5` — Nhanh nhất, phản hồi tức thời
- Phân tích chi tiết dữ liệu mối đe dọa, đưa ra khuyến nghị ứng phó
- Cấu hình API key trực tiếp từ **GUI Settings → Claude AI Analysis**
- Nút **"Test Connection"** để xác minh kết nối trước khi sử dụng
- Toggle bật/tắt phân tích AI từ GUI
- API key và cấu hình được lưu vào `data/config.json`

---

## Kiến trúc

```text
ransomware_detector_v2/
├── core/
│   ├── feature_extractor.py    # Trích xuất 16 đặc trưng
│   ├── ml_engine.py            # ML model + feedback loop
│   ├── fp_reducer.py           # 3-lớp giảm FP
│   ├── yara_engine.py          # Quy tắc YARA + fallback
│   ├── scanner.py              # Tích hợp ML + YARA + Heuristic
│   ├── process_monitor.py      # Phát hiện hành vi process
│   ├── network_monitor.py      # Phát hiện C2
│   ├── notifications.py         # Thông báo Windows
│   ├── watchdog_monitor.py     # Bảo vệ thời gian thực + Entropy
│   ├── auto_responder.py       # Tự động phản ứng
│   ├── pe_analyzer.py          # Phân tích PE
│   ├── injection_detector.py   # Phát hiện injection
│   ├── forensic_exporter.py    # Xuất báo cáo pháp y
│   ├── report_generator.py     # Tạo báo cáo CSV/PNG/PDF
│   ├── pdf_reporter.py         # Xuất báo cáo PDF
│   ├── rule_updater.py         # Cập nhật quy tắc
│   ├── honeypot_manager.py      # Honeypot file deployment
│   ├── office_doc_analyzer.py  # Phân tích tài liệu Office
│   ├── virustotal_client.py    # Tích hợp VirusTotal API
│   ├── ai_analyzer.py          # Claude AI threat analysis
│   └── config_manager.py       # Quản lý cấu hình tập trung
├── api/
│   ├── main.py                # FastAPI application
│   ├── auth.py                # JWT + API Key authentication
│   ├── schemas.py             # Pydantic models
│   └── routers/
│       ├── scan.py            # /scan/file, /scan/hash
│       ├── status.py          # /status, /alerts
│       ├── honeypots.py       # /honeypots
│       └── reports.py         # /reports/{id}
├── gui/
│   ├── main_window.py         # CustomTkinter main window (11 tabs)
│   ├── tray_manager.py        # System tray
│   ├── whitelist_editor.py      # Whitelist editor dialog
│   ├── tab_office_scanner.py   # Office document scanner tab
│   ├── tab_entropy_watch.py    # Real-time entropy monitor tab
│   ├── tab_honeypot.py         # Honeypot management tab
│   ├── tab_ml_training.py       # ML feedback loop tab
│   └── components/
│       └── plot_frame.py      # Matplotlib in CTk
├── data/
│   ├── vt_cache.json          # VirusTotal hash cache
│   ├── feedback_samples.csv    # ML feedback data
│   └── honeypot_registry.json # Honeypot file registry
└── tests/
    └── test_*.py              # 16+ unit test modules
│   ├── dataset_generator.py     # Tạo dữ liệu training
│   ├── smote_trainer.py        # Training với SMOTE
│   ├── config_manager.py        # Quản lý cấu hình
│   └── logger_setup.py         # Structured logging
├── gui/
│   ├── main_window.py          # Giao diện chính
│   ├── tray_manager.py         # System tray
│   └── whitelist_editor.py      # Trình chỉnh sửa whitelist
├── tests/
│   ├── conftest.py              # Shared pytest fixtures
│   ├── test_feature_extractor.py
│   ├── test_fp_reducer.py
│   ├── test_ml_engine.py
│   ├── test_yara_engine.py
│   └── test_dynamic_signals.py
├── data/
│   ├── whitelist.json           # Danh sách whitelist
│   ├── scan_cache.json          # Cache quét tăng dần
│   ├── config.json              # Cấu hình runtime
│   └── threat_intel/
│       └── feodo_ips.json       # Threat intelligence
├── models/
│   └── rf_ransomware_detector.joblib  # Model đã train
├── quarantine/                   # Thư mục cách ly
├── logs/                        # Log files
├── train_model.py               # Script train model
├── main.py                      # Entry point
└── requirements.txt             # Dependencies
```

---

## Cài đặt

### Yêu cầu

- **Python 3.8 trở lên**
- **Windows 10/11** (notifications và process monitoring được tối ưu cho Windows)

### Bước 1: Clone và cài đặt dependencies

```bash
# Clone repository
git clone https://github.com/in4SECxMinDandy/ransomware_detector_v2.git
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

Hoặc sử dụng:

```bash
python main.py --train
```

### Bước 3: Chạy ứng dụng

```bash
python main.py
```

### Tùy chọn: YARA native (hiệu năng cao hơn)

```bash
pip install yara-python
```

---

## Hướng dẫn sử dụng

### Chế độ 1: Quét thủ công (Manual Scan)

1. Click **"Chọn thư mục"** để chọn thư mục cần quét
2. Chọn **Chế độ quét**:
   - **Quét toàn bộ (Full Scan)**: Đệ quy tất cả thư mục con
   - **Quét nhanh (Quick Scan)**: Chỉ quét thư mục gốc
   - **Quét tăng dần (Incremental Scan)**: Chỉ quét file mới/sửa đổi
3. Điều chỉnh **Ngưỡng (Threshold)** nếu cần (mặc định: 0.65)
4. Click **"Bắt đầu quét"**
5. Xem kết quả trong bảng bên dưới

### Chế độ 2: Bảo vệ thời gian thực (Real-time Protection)

1. Click **"Chọn thư mục"** để chọn thư mục giám sát
2. Click **"Bắt đầu bảo vệ"**
3. Công cụ sẽ giám sát và:
   - Gửi **thông báo Windows** khi phát hiện mối đe dọa
   - Hiển thị **cửa sổ cảnh báo** với chi tiết process
   - Ghi log vào console

### Chế độ 3: Dòng lệnh (CLI)

```bash
# Quét thư mục
python main.py --scan "C:\Path\To\Folder"

# Chỉ train model
python main.py --train
```

### Điều chỉnh độ nhạy

| Chế độ | Điều chỉnh ngưỡng | Trường hợp sử dụng |
| --- | --- | --- |
| **Cân bằng** | +0.00 | Cân bằng giữa bỏ sót và cảnh báo sai |
| **Độ nhạy cao** | -0.05 | Ưu tiên phát hiện ransomware |
| **Paranoid** | -0.10 | Giám sát nghiêm ngặt nhất |

### Xuất báo cáo

- **CSV**: Click "Xuất CSV"
- **PNG**: Click "Xuất PNG"
- **PDF**: Click "Xuất PDF"

---

## Máy học - ML Engine

### 16 Đặc trưng (Features)

| # | Đặc trưng | Mô tả |
| --- | --- | --- |
| 1 | Shannon Entropy | Entropy trung bình của file |
| 2 | Chi-Square (log) | Độ đồng đều phân bố byte |
| 3 | Mean Byte | Giá trị trung bình byte |
| 4 | Byte Variance | Phương sai byte |
| 5 | Serial Correlation | Tương quan byte liên tiếp |
| 6 | Chunk Entropy StdDev | Độ lệch chuẩn entropy |
| 7 | Chunk Entropy Max | Entropy cao nhất |
| 8 | Chunk Entropy Min | Entropy thấp nhất |
| 9 | High Entropy Ratio | Tỷ lệ chunk có entropy cao |
| 10 | Magic Bytes Mismatch | Magic bytes không khớp |
| 11 | Normalized Entropy | Entropy chuẩn hóa |
| 12 | Byte Distribution Mode | Mode phân bố byte |
| 13 | Compression Ratio Sim | Ước tính tỷ lệ nén |
| 14 | Structural Consistency | Tính nhất quán cấu trúc |
| 15 | Extension Entropy Delta | Chênh lệch entropy vs extension |
| 16 | Is Known Benign Format | Kiểm tra format known benign |

### Mô hình

- **Thuật toán**: RandomForestClassifier
- **Calibration**: CalibratedClassifierCV
- **Ngưỡng**: Tự điều chỉnh cho Precision ≥95%

---

## Giảm thiểu False Positive - FP Reduction

### Lớp 1: Whitelist

Bỏ qua các file hệ thống:

```python
WHITELIST_PATHS = [
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
]
```

### Lớp 2: Ngưỡng theo đuôi file (Per-extension Threshold)

| Đuôi file | Ngưỡng | Lý do |
| --- | --- | --- |
| `.png`, `.jpg` | 0.85 | Entropy cao tự nhiên |
| `.zip`, `.7z` | 0.80 | File nén |
| `.exe`, `.dll` | 0.75 | PE files |
| `.txt`, `.doc` | 0.65 | Tài liệu thông thường |

### Lớp 3: Xác thực Magic Bytes

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

## Quy tắc YARA

### Các quy tắc tích hợp sẵn

| Nhóm ransomware | Aliases |
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

## Phát hiện hành vi Process

### Cách hoạt động

```text
File Event → Get PID → Get Process Info → Check Patterns → Alert
```

### Các pattern được phát hiện

1. **ENCRYPTION_BURST**
   - Phát hiện: >10 files bị sửa đổi trong 30 giây
   - Kèm: entropy >7.0 (mã hóa)
   - Hành động: Cảnh báo nghiêm trọng

2. **EXTENSION_CHANGE**
   - Phát hiện: Đổi extension sang đáng nghi ngờ
   - Ví dụ: `.doc` → `.locked`, `.pdf` → `.encrypted`
   - Hành động: Cảnh báo nghiêm trọng

3. **RAPID_OPS**
   - Phát hiện: >5 files/giây
   - Hành động: Cảnh báo cao

4. **SUSPICIOUS_PROCESS**
   - Phát hiện: Process chạy từ temp/downloads
   - Kèm: Ghi file có entropy cao
   - Hành động: Cảnh báo cao

---

## Phân tích mạng - Network Analysis

### Các tính năng phát hiện C2

- **DGA Domain Detection**: Tính toán Shannon entropy của domain để phát hiện Domain Generation Algorithms
- **Beaconing Detection**: Phát hiện request đến known malicious IPs (Feodo Tracker C2)
- **Connection Rate Limiting**: Cảnh báo nếu quá nhiều kết nối trong thời gian ngắn
- **DNS Tunneling Indicators**: Phát hiện DNS queries bất thường

---

## Bảo vệ thời gian thực - Real-time Protection

### Yêu cầu

```bash
pip install watchdog
```

### Tính năng

- **File System Watcher**: Giám sát thay đổi file theo thời gian thực
- **Đa luồng xử lý**: Xử lý song song với ThreadPoolExecutor
- **Debouncing**: 2 giây cooldown tránh spam thông báo
- **Tự động cảnh báo**: Kích hoạt callback khi phát hiện mối đe dọa

---

## Tự động phản ứng - Auto-Response

### Các hành động tự động

| Mức độ | Hành động | Mô tả |
| --- | --- | --- |
| **CRITICAL** | auto_quarantine | Tự động cách ly, không hỏi |
| **HIGH** | ask_user | Hiển thị hộp thoại với countdown |
| **MEDIUM** | notify_only | Chỉ thông báo |
| **LOW** | log_only | Chỉ ghi log |

### Các chức năng chính

- **Cách ly file**: Di chuyển file độc hại vào thư mục `quarantine/`
- **Khôi phục file**: Hoàn tác cách ly khi cần
- **Kết thúc Process**: Dừng process độc hại một cách an toàn
- **Chặn mạng**: Sử dụng Windows Firewall để ngăn chặn kết nối C2

---

## Thông báo Windows

### Yêu cầu thư viện

```bash
pip install win10toast plyer
```

### Các mức thông báo

| Mức | Âm thanh | Trường hợp sử dụng |
| --- | --- | --- |
| LOW | Không | Thông tin |
| MEDIUM | SystemAsterisk | Cảnh báo |
| HIGH | SystemExclamation | Mối đe dọa |
| CRITICAL | SystemHand | Cảnh báo nghiêm trọng |

---

## Giao diện đồ họa - GUI

### Bố cục

```text
┌─────────────────────────────────────────────────────────────┐
│  HEADER: Logo + Tiêu đề + Phiên bản + Trạng thái            │
├──────────────┬──────────────────────────────────────────────┤
│  PANEL TRÁI │  PHẢI: Bảng kết quả                          │
│  - Thư mục  │                                              │
│  - Chế độ   │  - Trạng thái | File | Đường dẫn | Nguy cơ  │
│  - Ngưỡng   │                                              │
│  - Bắt đầu │                                              │
│  - Thống kê│                                              │
│  - Bảo vệ  │                                              │
│  - FP Info  │                                              │
│  - Xuất    │                                              │
│  - ML Engine│                                             │
├──────────────┴──────────────────────────────────────────────┤
│  DƯỚI: Console log (sự kiện thời gian thực)                │
└─────────────────────────────────────────────────────────────┘
```

---

## Hiệu năng

| Chỉ số | Mục tiêu |
| --- | --- |
| Precision | ≥ 95% |
| False Positive Rate | < 5% |
| Recall | ≥ 90% |
| Tốc độ quét | ~100 files/giây |
| Bộ nhớ sử dụng | < 200MB |

---

## Kiểm tra - Testing

### Unit Tests

**140+ unit tests** với coverage 85%+ cho tất cả core modules.

```bash
# Chạy tất cả tests
pytest tests/ -v

# Với coverage report
pytest tests/ --cov=core --cov-report=term-missing
```

### Các module test

| File | Mô tả |
| --- | --- |
| `test_feature_extractor.py` | 49 tests cho 16 features extraction |
| `test_fp_reducer.py` | 24 tests cho FP reduction pipeline |
| `test_ml_engine.py` | 15 tests cho ML engine |
| `test_yara_engine.py` | 18 tests cho YARA signatures |
| `test_dynamic_signals.py` | 16 tests cho process behavior |
| `test_office_analyzer.py` | Tests cho Office document scanning |
| `test_virustotal_client.py` | Tests cho VT API integration |
| `test_honeypot_manager.py` | Tests cho honeypot deployment |
| `test_entropy_monitor.py` | Tests cho entropy burst detection |
| `test_ml_feedback.py` | Tests cho ML feedback loop |
| `test_api_auth.py` | Tests cho JWT + API Key auth |
| `test_api_routes.py` | Tests cho FastAPI endpoints |

---

## Lộ trình phát triển - Roadmap

### v2.5 (Hiện tại)

- [x] **Bộ test unit** với 140+ tests và 85%+ coverage ✅
- [x] **Quét tăng dần** — chỉ scan file mới/đã sửa ✅
- [x] **Config manager** — centralized configuration ✅
- [x] **Logger setup** — structured logging ✅
- [x] **Bug fixes**: entropy formula, file handle leak, exception handling ✅
- [x] **Dynamic behavior signals** (file rename bursts, mass IO) ✅
- [x] **Rule pack updater** (auto update YARA rules) ✅
- [x] **Export forensic bundle** (hashes + IOC report) ✅
- [x] **System Tray integration** ✅
- [x] **Auto-response actions** (quarantine, kill process) ✅
- [x] **Network traffic analysis** (C2 detection, DGA, beacon) ✅
- [x] **Office Document Scanner** — VBA macro, PDF action detection ✅
- [x] **Real-time Entropy Watch** — Shannon entropy monitoring ✅
- [x] **VirusTotal Integration** — VT API v3 + cache ✅
- [x] **Honeypot File Monitoring** — decoy file deployment ✅
- [x] **REST API (FastAPI)** — JWT + API Key auth ✅
- [x] **ML Incremental Learning** — feedback loop + retrain ✅

---

## Cấu hình nâng cao

### Environment Variables

| Variable | Mô tả | Mặc định |
| --- | --- | --- |
| `VT_API_KEY` | VirusTotal API key | - |
| `ML_THRESHOLD` | Detection threshold | 0.65 |
| `ENTROPY_THRESHOLD` | Entropy alert threshold | 7.5 |
| `API_PORT` | FastAPI server port | 8000 |
| `HONEYPOT_AUTO_DEPLOY` | Auto-deploy honeypots on startup | false |
| `CLAUDE_API_KEY` | Anthropic Claude API key (proxy: taphoaapi.info.vn) | - |
| `CLAUDE_MODEL` | Claude model: `claude-sonnet-4-6`, `claude-opus-4-6`, `claude-haiku-4-5` | `claude-sonnet-4-6` |

### Config Files

Cấu hình được quản lý qua `core/config_manager.py` và lưu trong `data/config.json`.

---

## Giấy phép - License

MIT License - Xem [LICENSE](LICENSE) để biết thêm chi tiết.

---

## Tác giả

- **Họ tên**: Hà Quang Minh
- **Email**: <minhhq.in4sec@gmail.com>
- **GitHub**: <https://github.com/in4SECxMinDandy>

---

## Acknowledgments - Cảm ơn

- [scikit-learn](https://scikit-learn.org/) - Khung máy học
- [YARA](https://virustotal.github.io/yara/) - Pattern matching
- [watchdog](https://pythonhosted.org/watchdog/) - Giám sát file system
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) - Giao diện hiện đại
- [psutil](https://psutil.readthedocs.io/) - Giám sát process
- [Anthropic](https://www.anthropic.com/) - Claude AI cho phân tích mối đe dọa

---

**⭐ Nếu thấy hữu ích, hãy cho tôi 1 ⭐ để ủng hộ!**
