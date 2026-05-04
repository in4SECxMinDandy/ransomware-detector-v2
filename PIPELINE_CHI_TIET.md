# Ransomware Detector v2 — Pipeline Tải 5GB & Training ML Chi Tiết

> **Dự án:** PTIT Security Research Lab — Hệ thống phát hiện ransomware đa lớp  
> **Ngày cập nhật:** 02/05/2026  
> **Phiên bản ML:** v2.4 (SMOTE + Anti-FP + Cost-Aware)

---

## Mục Lục

1. [Tổng Quan Kiến Trúc](#1-tổng-quan-kiến-trúc)
2. [Pipeline Tự Động Tải 5GB Malware](#2-pipeline-tự-động-tải-5gb-malware)
3. [Trích Xuất Đặc Trưng (16 Features)](#3-trích-xuất-đặc-trưng-16-features)
4. [Pipeline Training ML](#4-pipeline-training-ml)
5. [Kiến Trúc Model Random Forest](#5-kiến-trúc-model-random-forest)
6. [Các Cách Chạy Pipeline](#6-các-cách-chạy-pipeline)
7. [Cấu Trúc Thư Mục Dữ Liệu](#7-cấu-trúc-thư-mục-dữ-liệu)

---

## 1. Tổng Quan Kiến Trúc

```
┌─────────────────────────────────────────────────────────────────────┐
│                    RANSOMWARE DETECTOR v2                           │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  8 Lớp Phòng │    │  ML Engine   │    │  Auto Download       │  │
│  │  Thủ Theo    │◄───│  (RF+SMOTE)  │◄───│  Pipeline (5GB)      │  │
│  │  Thời Gian   │    │              │    │                      │  │
│  │  Thực        │    │  16 Features │    │  MalwareBazaar API   │  │
│  └──────────────┘    └──────────────┘    └──────────────────────┘  │
│                                                                     │
│  Giao diện: GUI (CustomTkinter) | API (FastAPI) | CLI (main.py)   │
└─────────────────────────────────────────────────────────────────────┘
```

**8 Lớp phòng thủ:**

| Lớp | Cơ chế | Mô tả |
|------|--------|-------|
| 1 | **ML Engine** | Random Forest + 16 features, phân loại SAFE vs ENCRYPTED |
| 2 | **Watchdog** | Giám sát filesystem real-time, phát hiện burst mã hóa |
| 3 | **Process Monitor** | Theo dõi burst IO, đổi extension, rename nhanh |
| 4 | **PE Analysis** | Phân tích cấu trúc executable, packer detection |
| 5 | **Threat Intel** | Lookup hash trên VirusTotal, MalwareBazaar, AlienVault |
| 6 | **YARA Engine** | Signature-based detection (WannaCry, LockBit, BlackCat...) |
| 7 | **Honeypot** | Triển khai file mồi để phát hiện ransomware |
| 8 | **Auto-Response** | Cách ly file, kill process, block firewall tự động |

---

## 2. Pipeline Tự Động Tải 5GB Malware

### 2.1 File Chính

| File | Vai trò |
|------|---------|
| `scripts/pipeline_download_and_train.py` | Pipeline chính: tải CSV → lọc hash → download → train (416 dòng) |
| `scripts/download_malwarebazaar.py` | Advanced downloader với nhiều phương thức khám phá (612 dòng) |

### 2.2 Luồng Hoạt Động (4 Bước)

```
┌──────────────────────────────────────────────────────────────────┐
│  STEP 1: Tải Daily CSV Dumps (~90 ngày, ~500MB)                  │
│  ─────────────────────────────────────────                        │
│  URL: https://datalake.abuse.ch/malware-bazaar/daily/{date}.csv  │
│  Lưu vào: datasets/sources/encrypted/malwarebazaar/_daily_csvs/  │
│                                                                   │
│  STEP 2: Lọc Hash Ransomware Từ CSVs                             │
│  ─────────────────────────────────────                             │
│  Tiêu chí lọc:                                                    │
│    • PE (70%):  tags/signature chứa keyword ransomware           │
│                + file_type = exe/dll/sys/msi                     │
│                + mime = x-msdownload, x-dosexec                   │
│    • Office (30%): tags/signature chứa keyword malware           │
│                    + file_type = doc/docx/xls/xlsx/ppt/pptx       │
│                                                                   │
│  STEP 3: Download Samples Qua MalwareBazaar API                  │
│  ─────────────────────────────────────────────                     │
│  API: POST https://bazaar.abuse.ch/api/                          │
│  Body: {"query": "get_file", "sha256_hash": "<hash>"}            │
│  Download: ZIP được mã hóa base64 (password: "infected")         │
│  Giới hạn: rate-limit 0.6s/request, tự động resume               │
│  Dừng khi: đạt 5GB tổng (PE=3.5GB, Office=1.5GB)                │
│                                                                   │
│  STEP 4: Prepare Features + Training Model                       │
│  ───────────────────────────────────────                           │
│  → Trích xuất 16 features từ mỗi file PE đã tải                  │
│  → Kết hợp với dữ liệu synthetic SAFE (5000 samples)             │
│  → Training Random Forest + SMOTE                                │
└──────────────────────────────────────────────────────────────────┘
```

### 2.3 Keyword Lọc Ransomware

**PE Keywords** (48 từ khóa):
```
ransomware, ransom, lockbit, blackcat, alphv, conti, revil,
sodinokibi, cuba, blackbasta, hive, vice, royal, bianlian,
play, medusa, ransomhub, akira, crylock, dharma, phobos,
stop, makop, maze, ryuk, wannacry, crypt, babuk, ragnar,
mount, avos, hello, trigona, clop, darkside, blackmatter
```

**Office Keywords** (24 từ khóa):
```
ransomware, lockbit, emotet, trickbot, dridex, ursnif,
agenttesla, formbook, loki, azorult, remcos, njrat, asyncrat,
nanocore, quakbot, icedid, bumblebee, qbot, ransom, malware,
trojan, loader, dropper, downloader
```

### 2.4 Cơ Chế Resume (Tiếp Tục Khi Bị Ngắt)

Pipeline lưu tiến trình vào file `_pipeline_progress.json`:

```json
{
  "pe_bytes_done": 2147483648,
  "of_bytes_done": 536870912,
  "downloaded_hashes": ["abc123...", "def456..."],
  "failed_hashes": ["bad111..."],
  "csv_dates_done": ["2026-04-01", "2026-04-02"],
  "updated_at": "2026-05-02T10:30:00+00:00"
}
```

Khi chạy lại, pipeline sẽ:
- Bỏ qua các hash đã download/failed
- Bỏ qua các CSV đã xử lý
- Tiếp tục download cho đến khi đạt đủ 5GB

### 2.5 Cấu Trúc File Malware Tải Về

```
datasets/sources/encrypted/malwarebazaar/
├── pe/                          # File PE (.exe, .dll, .sys, .msi)
│   ├── <sha256>.exe
│   ├── <sha256>.dll
│   └── ...
├── office/                      # File Office (.doc, .docx, .xls...)
│   ├── <sha256>.docx
│   └── ...
├── _daily_csvs/                 # CSV dumps hàng ngày
│   ├── 2026-04-01.csv
│   ├── 2026-04-02.csv
│   └── ...
└── _pipeline_progress.json      # File lưu tiến trình
```

### 2.6 Encoding & Extraction ZIP

Tất cả samples từ MalwareBazaar được đóng gói:
- **Format:** ZIP nén chứa malware sample
- **Encoding:** Base64 (trong response JSON)
- **Password ZIP:** `infected`
- **Quy trình giải nén:**
  1. Gọi API lấy JSON response
  2. Giải mã base64 field `data`
  3. Mở ZIP với password `infected`
  4. Đọc file bên trong, tính SHA256 thực tế
  5. Lưu với tên `<sha256>.<extension>` để tránh trùng lặp

---

## 3. Trích Xuất Đặc Trưng (16 Features)

### 3.1 File Chính

| File | Vai trò |
|------|---------|
| `core/feature_extractor.py` | Trích xuất 16 features từ file nhị phân (434 dòng) |

### 3.2 Chi Tiết 16 Features

Vector đầu ra: `np.ndarray shape=(16,)`, dtype `float32`.

#### Nhóm 1: Thống Kê Toàn File (5 features)

| # | Feature | Công thức/Mô tả | Ý nghĩa |
|---|---------|----------------|---------|
| 0 | **Shannon Entropy** | `H = -Σ p(x) * log2(p(x))` | Độ ngẫu nhiên tổng thể (bits/byte). Encrypted ~7.9-8.0, text ~4.0-5.0 |
| 1 | **Chi-Square (log)** | `log1p(Σ (O-E)²/E)` | Độ đồng đều phân bố byte. Encrypted → phân bố đều → χ² thấp |
| 2 | **Mean Byte** | `μ = Σ bytes / n` | Giá trị byte trung bình. Random → gần 127.5 |
| 3 | **Byte Variance** | `σ² = E[(X-μ)²]` | Độ phân tán byte. Encrypted → variance thấp hơn do đều |
| 4 | **Serial Correlation** | `corr(byte[i], byte[i+1])` | Tương quan byte liên tiếp. File bình thường → có pattern; encrypted → gần 0 |

#### Nhóm 2: Phân Tích Theo Chunk (4 features)

| # | Feature | Mô tả | Ý nghĩa |
|---|---------|-------|---------|
| 5 | **Chunk Entropy StdDev** | `std(entropy của từng chunk 4KB)` | Phát hiện mã hóa từng phần (partial encryption) |
| 6 | **Chunk Entropy Max** | `max(entropy của từng chunk)` | Chunk có entropy cao nhất |
| 7 | **Chunk Entropy Min** | `min(entropy của từng chunk)` | Chunk có entropy thấp nhất |
| 8 | **High Entropy Ratio** | `tỉ lệ chunk có entropy > ngưỡng` | Ngưỡng adaptive: 7.5 (file nén) hoặc 7.2 (file thường) |

#### Nhóm 3: Anti False-Positive (7 features)

| # | Feature | Mô tả | Ý nghĩa |
|---|---------|-------|---------|
| 9 | **Magic Bytes Mismatch** | `0 = khớp, 1 = không khớp` | File header có khớp extension không? |
| 10 | **Ext Entropy Z-Score** | `(H - μ_ext) / σ_ext, clamp [-3,3]` | Độ lệch entropy so với baseline của loại file. **KEY anti-FP!** |
| 11 | **Byte Mode Frequency** | `max(freq) / len(data)` | Tần suất mode byte. Encrypted → rất thấp (~0.004); structured → cao hơn |
| 12 | **Compression Estimate** | `1 - (byte[i] != byte[i+1]) / n` | Ước lượng khả năng nén. Encrypted → gần 0; structured → cao hơn |
| 13 | **Structural Consistency** | `1 - min(1, std(H_chunks)/mean(H_chunks))` | Tính nhất quán cấu trúc. File nén hợp lệ → cao; encrypted → không nhất quán |
| 14 | **Ext Entropy Raw Delta** | `(H - μ_ext) / σ_ext` (không clamp) | Giữ giá trị thô không clamp để bảo toàn extreme values |
| 15 | **Is Known Benign Format** | `0.0 hoặc 1.0` | Magic bytes hợp lệ cho extension? Ví dụ: PNG có `\x89PNG` → 1.0 |

### 3.3 Magic Bytes DB (Định Dạng Nhận Diện)

```
PDF  → %PDF          ZIP → PK\x03\x04      PNG → \x89PNG
JPEG → \xff\xd8\xff  RAR → Rar!             EXE → MZ
GIF  → GIF8          7Z  → 7z\xbc\xaf       ELF → \x7fELF
MP4  → ftyp          MP3 → ID3              DOCX→ PK\x03\x04
```

### 3.4 Entropy Baseline Theo Loại File

Đây là **KEY** giải quyết False Positive — file nén có entropy cao TỰ NHIÊN:

| Extension | Mean Entropy | Std | Giải thích |
|-----------|-------------|-----|------------|
| **png** | 7.60 | 0.35 | Nén lossless → entropy cao tự nhiên |
| **jpg** | 7.50 | 0.40 | Lossy compressed |
| **zip** | 7.80 | 0.15 | Compressed archive |
| **gz/7z** | 7.85 | 0.10 | High-compression archive |
| **docx/xlsx** | 7.75 | 0.20 | Office = ZIP inside |
| **mp4** | 7.70 | 0.25 | Video compressed |
| **exe/dll** | 5.50 | 1.80 | Executable → varies widely |
| **txt** | 4.00 | 0.80 | Plain text |

**Nguyên lý:** PNG có entropy ~7.6 là **BÌNH THƯỜNG**. Nhưng file `.txt` có entropy ~7.6 → **BẤT THƯỜNG** → nghi ngờ ransomware.

### 3.5 Cơ Chế Đọc File (Smart Sampling)

| Kích thước file | Cách đọc |
|----------------|----------|
| ≤ 1 MB | Đọc toàn bộ |
| 1 MB - 100 MB | Đọc header (4KB) + footer (4KB) + 16 chunks ngẫu nhiên (4KB) |
| > 100 MB | Đọc header + 64 chunks cách đều (step = filesize/64 × 4KB) |

---

## 4. Pipeline Training ML

### 4.1 File Chính

| File | Vai trò |
|------|---------|
| `core/ml_engine.py` | `CalibratedMalwareDetector` — training, predict, threshold optimization (1230+ dòng) |
| `core/dataset_generator.py` | Sinh dữ liệu synthetic (7 SAFE + 5 ENCRYPTED types) |
| `core/smote_trainer.py` | SMOTE oversampling (6 chiến lược) |
| `core/external_dataset_builder.py` | Build CSV từ PE files thực tế |
| `train_model.py` | Entry point standalone training |

### 4.2 Luồng Training Chi Tiết (12 Bước)

```
┌─────────────────────────────────────────────────────────────────────┐
│ BƯỚC 1: Chuẩn bị dữ liệu                                           │
│  • Nếu train từ pipeline download: PE thật + synthetic SAFE         │
│  • Nếu train synthetic: generate_synthetic_dataset()                │
│  • Dữ liệu: X.shape = (N, 16), y ∈ {0=SAFE, 1=ENCRYPTED}          │
├─────────────────────────────────────────────────────────────────────┤
│ BƯỚC 2: Train/Val/Test Split (TRƯỚC SMOTE → tránh data leakage)   │
│  • Stratified split với random_state=42                             │
│  • 60% Train → dùng để fit model + SMOTE                            │
│  • 20% Validation → tìm optimal threshold                           │
│  • 20% Test → đánh giá cuối cùng (HELD OUT)                         │
├─────────────────────────────────────────────────────────────────────┤
│ BƯỚC 3: SMOTE Oversampling (CHỈ trên training fold)                │
│  • Chỉ áp dụng khi imbalance ratio < 0.9                            │
│  • 6 chiến lược: smote, smote_tomek, smote_enn, adasyn,            │
│    borderline, none                                                 │
│  • Default: smote_tomek (SMOTE + TomekLinks undersampling)          │
│  • ⚠️ KHÔNG áp dụng lên val/test → tránh leak synthetic samples    │
├─────────────────────────────────────────────────────────────────────┤
│ BƯỚC 4: StandardScaler                                              │
│  • Fit ONLY trên training fold (post-SMOTE)                         │
│  • Transform val/test dùng scaler đã fit                            │
├─────────────────────────────────────────────────────────────────────┤
│ BƯỚC 5: Random Forest Training                                     │
│  • n_estimators = 300                                               │
│  • min_samples_split = 4 (tăng từ 2 để tránh overfit)               │
│  • min_samples_leaf = 2 (tăng từ 1)                                 │
│  • max_features = "sqrt"                                            │
│  • class_weight = {0: 3.0, 1: 10.0} (COST-FP, COST-FN)             │
│    → 0=SAFE (FP cost=3), 1=ENCRYPTED (FN cost=10)                  │
│    → FN nặng hơn FP → model ưu tiên bắt ransomware                  │
├─────────────────────────────────────────────────────────────────────┤
│ BƯỚC 6: Calibration (Isotonic Regression)                          │
│  • CalibratedClassifierCV(method="isotonic", cv=3)                  │
│  • Đảm bảo probability output phản ánh true likelihood              │
├─────────────────────────────────────────────────────────────────────┤
│ BƯỚC 7: Threshold Optimization trên Validation Set                 │
│  • Duyệt Precision-Recall curve                                     │
│  • Tìm threshold tối thiểu mà Precision ≥ 95%                       │
│  • Fallback: threshold cho F1 max, không thấp hơn 0.65              │
├─────────────────────────────────────────────────────────────────────┤
│ BƯỚC 8: Refit trên Train+Val (hiệu quả dữ liệu tối đa)            │
│  • Gộp train + val → trainval                                       │
│  • Áp dụng SMOTE lại trên trainval (nếu imbalance)                  │
│  • Fit StandardScaler + CalibratedRF trên toàn bộ trainval          │
├─────────────────────────────────────────────────────────────────────┤
│ BƯỚC 9: Đánh Giá trên Test Set (HELD OUT)                          │
│  • Accuracy, Precision, Recall, F1, AUC-ROC                         │
│  • Confusion Matrix: TN, FP, FN, TP                                 │
│  • False Positive Rate (target: < 5%)                               │
│  • Classification Report                                            │
├─────────────────────────────────────────────────────────────────────┤
│ BƯỚC 10: 5-Fold Cross-Validation (trên dữ liệu GỐC)                │
│  • Dùng X_orig, y_orig (CHƯA SMOTE)                                 │
│  • RF riêng với 200 trees, class_weight tương tự                     │
│  • StratifiedKFold(5, shuffle=True)                                 │
│  • Metric: F1-score                                                 │
├─────────────────────────────────────────────────────────────────────┤
│ BƯỚC 11: Lưu Model + SHA256 Integrity Pin                           │
│  • Model: models/rf_ransomware_detector.joblib                      │
│  • SHA256: models/rf_ransomware_detector.joblib.sha256             │
│  • Metadata: models/model_metadata.json                             │
│  • Trước khi load sẽ verify SHA256 → chống tampering                │
├─────────────────────────────────────────────────────────────────────┤
│ BƯỚC 12: Lưu Metadata (model_metadata.json)                        │
│  • version, n_features                                              │
│  • accuracy, precision, recall, f1, auc_roc                         │
│  • false_positive_rate                                              │
│  • cv_mean, cv_std (5-fold)                                         │
│  • confusion_matrix                                                 │
│  • optimal_threshold                                                │
│  • class_weight, cost_fp, cost_fn                                   │
│  • feature_importances                                              │
│  • threshold_report                                                 │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.3 Chiến Lược Cost-Aware (Chống False Positive)

```
┌─────────────────────────────────────────────────────────────────────┐
│ TRIẾT LÝ THIẾT KẾ:                                                 │
│                                                                     │
│  COST_FP = 3.0    — Chi phí khi báo động giả (làm phiền user)     │
│  COST_FN = 10.0   — Chi phí khi bỏ sót ransomware (NGUY HIỂM!)   │
│                                                                     │
│  class_weight = {0=SAFE: 3.0, 1=ENCRYPTED: 10.0}                  │
│                                                                     │
│  → Model được dạy: bắt ransomware QUAN TRỌNG HƠN tránh báo động   │
│    (FN nặng gấp 3.3× FP)                                           │
│                                                                     │
│  SAU KHI TRAINING:                                                  │
│  → Threshold optimizer chọn ngưỡng Precision ≥ 95%                 │
│    (chỉ 5% FP chấp nhận được)                                      │
│  → FP Reducer: whitelist + per-extension threshold adjustment      │
│  → Feedback loop: user có thể mark FP/FN để retrain                │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.4 Synthetic Dataset Generation

File `core/dataset_generator.py` sinh dữ liệu mô phỏng:

**7 Loại File SAFE:**
| Loại | Mô tả | Magic Bytes |
|------|-------|-------------|
| Text | Văn bản thuần | Không |
| PE Valid | EXE hợp lệ | MZ |
| PNG Valid | PNG hợp lệ | \x89PNG |
| ZIP Valid | ZIP hợp lệ | PK\x03\x04 |
| Media | MP3/MP4 | ID3 / ftyp |
| Office | DOCX/XLSX | PK\x03\x04 |
| Binary Structured | Binary có pattern | Không |

**5 Loại File ENCRYPTED:**
| Loại | Mô tả |
|------|-------|
| Full AES | Toàn bộ mã hóa AES (entropy rất cao) |
| Intermittent | Mã hóa xen kẽ (một phần cao, một phần thấp) |
| Header Only | Chỉ mã hóa header |
| Disguised PNG | Mã hóa nhưng giả mạo header PNG |
| Disguised ZIP | Mã hóa nhưng giả mạo header ZIP |

### 4.5 SMOTE Strategies

| Strategy | Mô tả |
|----------|-------|
| `smote` | SMOTE cơ bản — tạo synthetic samples cho minority class |
| `smote_tomek` | SMOTE + Tomek Links — xóa mẫu nhiễu sau khi oversample **(DEFAULT)** |
| `smote_enn` | SMOTE + Edited Nearest Neighbors — lọc mạnh hơn |
| `adasyn` | Adaptive Synthetic — tập trung vào vùng khó phân loại |
| `borderline` | Borderline-SMOTE — chỉ oversample samples ở biên |
| `none` | Không dùng SMOTE |

---

## 5. Kiến Trúc Model Random Forest

### 5.1 Cấu Trúc Pipeline

```python
Pipeline([
    ("scaler", StandardScaler()),           # Chuẩn hóa features
    ("clf", CalibratedClassifierCV(          # Random Forest + Calibration
        RandomForestClassifier(
            n_estimators=300,
            max_depth=None,                  # Không giới hạn độ sâu
            min_samples_split=4,
            min_samples_leaf=2,
            max_features="sqrt",
            class_weight={0: 3.0, 1: 10.0},
            random_state=42,
            n_jobs=1  # Windows-safe
        ),
        method="isotonic",                   # Isotonic regression calibration
        cv=3
    ))
])
```

### 5.2 Dự Đoán (Predict)

```python
def predict(features: np.ndarray) -> Tuple[int, float]:
    """
    Input:  features shape (16,)  — vector 16 đặc trưng
    Output: (label, probability)
      label = 0 (SAFE) hoặc 1 (ENCRYPTED)
      probability = xác suất là ENCRYPTED (0.0 ~ 1.0)
    
    Phân loại dựa trên optimal_threshold:
      prob >= threshold → ENCRYPTED
      prob <  threshold → SAFE
    """
```

### 5.3 Mức Độ Rủi Ro

| Ngưỡng | Risk Level | Màu |
|--------|-----------|-----|
| ≥ threshold + 0.15 (hoặc ≥ 85%) | `CRITICAL` | #FF2D2D |
| ≥ threshold + 0.05 (hoặc ≥ 70%) | `HIGH` | #FF8C00 |
| ≥ threshold | `MEDIUM` | #FFD700 |
| ≥ threshold × 0.6 | `LOW` | #00BFFF |
| < threshold × 0.6 | `SAFE` | #00FF88 |

### 5.4 Model Integrity (Chống Tampering)

```
KHI LOAD MODEL:
  1. Compute SHA256 của file .joblib
  2. So sánh với SHA256 đã pin:
     a. Biến môi trường: RANSOMWARE_MODEL_SHA256
     b. Sidecar file: rf_ransomware_detector.joblib.sha256
  3. Nếu KHÔNG khớp → từ chối load (ModelIntegrityError)
  4. Nếu không có pin → TOFU mode (Trust On First Use) + WARNING
  5. Strict mode: RANSOMWARE_REQUIRE_MODEL_INTEGRITY=1 → bắt buộc có pin

KHI TRAIN MODEL:
  → Tự động tạo file .sha256 sidecar
  → Backup model cũ theo timestamp (rf_ransomware_detector_20260502_103000.joblib)
  → Lưu metadata kèm model_metadata_<timestamp>.json
```

---

## 6. Các Cách Chạy Pipeline

### 6.1 Pipeline Tự Động Tải 5GB + Train

```bash
# Cách 1: Pipeline đầy đủ (CSV + download + train)
python scripts/pipeline_download_and_train.py --total-size-gb 5 --pe-ratio 0.7 --csv-days 90

# Cách 2: Chỉ download (bỏ qua CSV cũ, bắt đầu download ngay)
python scripts/pipeline_download_and_train.py --skip-csv --total-size-gb 5

# Cách 3: Chỉ train từ file đã tải
python scripts/pipeline_download_and_train.py --skip-download

# Cách 4: Tùy chỉnh đầy đủ
python scripts/pipeline_download_and_train.py \
  --total-size-gb 5 \      # Tổng dung lượng mục tiêu (GB)
  --pe-ratio 0.7 \          # Tỷ lệ PE (0.0-1.0), còn lại là Office
  --csv-days 90 \           # Số ngày CSV dumps cần tải
  --rate-limit 0.6 \        # Giới hạn API request (giây/request)
  --output datasets/sources/encrypted/malwarebazaar
```

### 6.2 Advanced Downloader (download_malwarebazaar.py)

```bash
# Download với nhiều phương thức phát hiện
python scripts/download_malwarebazaar.py \
  --output datasets/sources/encrypted/malwarebazaar \
  --max-size-gb 5 \
  --pe-ratio 0.7 \
  --csv-days 90
```

### 6.3 Training Từ Synthetic Data

```bash
# Training cơ bản (2500 SAFE + 2500 ENCRYPTED)
python train_model.py

# Training với số lượng tùy chỉnh
python train_model.py --samples 5000 --smote smote_tomek

# Training qua main.py
python main.py --train
```

### 6.4 Training Từ File PE Thực Tế

```bash
# Chuẩn bị PE files từ corpus
python main.py --prepare-external-pe \
  --input-dir C:\raw_corpus \
  --output-dir datasets\prepared\external_pe\safe

# Train từ thư mục SAFE/ENCRYPTED có sẵn
python main.py --train-external \
  --safe-dir datasets\prepared\external_pe\safe \
  --encrypted-dir datasets\prepared\external_pe\encrypted
```

### 6.5 Curated Training Source Pipeline

```bash
# 1. Tìm kiếm nguồn dữ liệu có sẵn
python main.py --search-training-sources --query "malware"

# 2. Lập kế hoạch training
python main.py --plan-training-source --scale pilot

# 3. Tạo manifest + thư mục (user tự tải file thủ công)
python main.py --download-training-source --source-id sorel20m-github --kind encrypted

# 4. Chuẩn bị (lọc PE files)
python main.py --prepare-training-source --source-id sorel20m-github --kind encrypted

# 5. Train từ kế hoạch
python main.py --train-from-source-plan --scale pilot

# 6. Kiểm tra tiến độ
python main.py --training-progress --scale pilot
```

**Các Scale Presets:**
| Scale | Samples/Lớp | Dung lượng ước tính |
|-------|------------|-------------------|
| `smoke` | 100 | Dùng để test pipeline |
| `pilot` | 1,000 | ~500 MB - 1 GB |
| `production` | 5,000 | ~2.5 - 5 GB |

### 6.6 Feedback Loop (Retrain Từ Phản Hồi)

```python
# Khi user đánh dấu FP/FN trong GUI, hệ thống tự lưu vào feedback_samples.csv
# Retrain với feedback:
engine = get_engine()
result = engine.retrain_with_feedback()
# result chứa: new_accuracy, new_precision, new_recall, samples_used, etc.
```

---

## 7. Cấu Trúc Thư Mục Dữ Liệu

```
ransomware-detector-v2/
│
├── datasets/                           # Dữ liệu training
│   ├── sources/                        # Nguồn dữ liệu thô
│   │   ├── safe/                       # File SAFE (từ curated sources)
│   │   │   ├── napierone/
│   │   │   ├── govdocs1/
│   │   │   └── trusted-vendors/
│   │   └── encrypted/                  # File ENCRYPTED (từ curated sources)
│   │       ├── sorel20m-github/
│   │       ├── sorel20m-aws/
│   │       └── malwarebazaar/          # ← Pipeline 5GB lưu ở đây
│   │           ├── pe/                 # PE malware samples
│   │           ├── office/             # Office malware samples
│   │           ├── _daily_csvs/        # CSV dumps từ abuse.ch
│   │           └── _pipeline_progress.json
│   │
│   ├── prepared/                       # File PE đã lọc (chỉ .exe/.dll/.sys/.msi)
│   │   ├── safe/
│   │   └── encrypted/
│   │
│   ├── datasets/                       # CSV datasets đã build
│   │   └── external_dataset.csv
│   │
│   ├── manifests/                      # Manifest files (danh sách hash)
│   │
│   └── logs/                           # Training logs
│
├── models/                             # Model đã train
│   ├── rf_ransomware_detector.joblib          # Model active
│   ├── rf_ransomware_detector.joblib.sha256   # Integrity pin
│   ├── model_metadata.json                    # Metrics & hyperparameters
│   ├── rf_ransomware_detector_20260502.joblib # Backup models
│   └── model_metadata_20260502.json           # Backup metadata
│
├── data/                               # Runtime data
│   ├── config.json                     # Cấu hình chính (API keys, thresholds...)
│   ├── config.json.template            # Template (không chứa secrets)
│   ├── synthetic_dataset_v2.csv        # Dataset synthetic đã generate
│   ├── feedback_samples.csv            # User feedback (FP/FN đánh dấu)
│   ├── whitelist.json                  # Whitelist (file/folder không quét)
│   └── threat_intel/                   # Cache threat intelligence
│
└── core/                               # Source code ML pipeline
    ├── ml_engine.py                    # CalibratedMalwareDetector (train/predict)
    ├── feature_extractor.py            # 16-feature extraction
    ├── dataset_generator.py            # Synthetic data generation
    ├── smote_trainer.py                # SMOTE oversampling
    ├── training_source_registry.py     # Curated source catalog
    ├── training_source_planner.py      # Pipeline orchestrator
    ├── external_dataset_builder.py     # CSV dataset builder từ PE files
    ├── pe_corpus_preparer.py           # PE file filter/copy
    ├── training_progress.py            # Progress tracking
    └── feedback_csv.py                 # Feedback storage
```

---

## Phụ Lục A: Các Lệnh Thường Dùng

```bash
# === CÀI ĐẶT ===
git clone https://github.com/haquan/ransomware-detector-v2.git
cd ransomware-detector-v2
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
copy data\config.json.template data\config.json

# === PIPELINE TỰ ĐỘNG 5GB ===
python scripts/pipeline_download_and_train.py --total-size-gb 5 --pe-ratio 0.7 --csv-days 90

# === TRAINING ===
python train_model.py --samples 5000 --smote smote_tomek
python main.py --train

# === SCAN ===
python main.py --scan C:\Users\Public

# === GUI ===
python main.py

# === API SERVER ===
python -m scripts.init_admin --user admin --password 'Strong!Pa$$w0rd'
uvicorn api.main:app --reload --host 127.0.0.1 --port 8000

# === DOCKER ===
set RANSOMWARE_JWT_SECRET=<your-secret>
docker compose up --build

# === TEST ===
pytest tests/ --cov=core
```

---

## Phụ Lục B: Sơ Đồ Tổng Thể Pipeline

```
                            ┌─────────────────────┐
                            │   abuse.ch API       │
                            │ datalake.abuse.ch    │
                            └────────┬────────────┘
                                     │
                              ┌──────▼──────┐
                              │  STEP 1     │
                              │  Tải 90     │
                              │  Daily CSVs │ (~500 MB)
                              └──────┬──────┘
                                     │
                              ┌──────▼──────┐
                              │  STEP 2     │
                              │  Lọc hash   │
                              │  ransomware │ (~30K PE + 15K Office)
                              │  từ CSVs    │
                              └──────┬──────┘
                                     │
                              ┌──────▼──────┐
                              │  STEP 3     │
                              │  Download   │
                              │  samples    │
                              │  qua API    │
                              │             │
                              │  ZIP (b64)  │ ~5GB PE + Office
                              │  pwd:infected│
                              │  RESUME     │ ← _pipeline_progress.json
                              └──────┬──────┘
                                     │
                          ┌──────────┴──────────┐
                          │                     │
                   ┌──────▼──────┐      ┌──────▼──────┐
                   │  PE Files   │      │ Office Files│
                   │ .exe/.dll/  │      │ .docx/.xlsx │
                   │ .sys/.msi   │      │ .pptx...    │
                   └──────┬──────┘      └─────────────┘
                          │                    (sẽ xử lý sau)
                          │
                   ┌──────▼──────┐
                   │  STEP 4     │
                   │  Trích xuất │
                   │  16 Features│
                   │  từ mỗi PE  │
                   └──────┬──────┘
                          │
                   ┌──────▼──────┐      ┌──────────────┐
                   │  X_enc (PE) │  +   │ X_safe       │
                   │  y = 1      │      │ (synthetic)  │
                   │  5000+ cols │      │ y = 0        │
                   └──────┬──────┘      └──────┬───────┘
                          │                    │
                          └─────────┬──────────┘
                                    │
                          ┌─────────▼─────────┐
                          │  TRAINING         │
                          │  ─────────        │
                          │  1. Split 60/20/20│
                          │  2. SMOTE on train│
                          │  3. StandardScaler│
                          │  4. Random Forest │
                          │     (300 trees)   │
                          │  5. Isotonic Calib│
                          │  6. Threshold Opt │
                          │     (Prec >= 95%) │
                          │  7. Test Eval     │
                          │  8. 5-Fold CV     │
                          │  9. Save + SHA256 │
                          └─────────┬─────────┘
                                    │
                          ┌─────────▼─────────┐
                          │  MODEL OUTPUT     │
                          │  ─────────────    │
                          │  .joblib (model)  │
                          │  .joblib.sha256   │
                          │  model_metadata   │
                          └───────────────────┘
```

---

*Tài liệu được tạo tự động từ codebase ransomware-detector-v2 — ngày 02/05/2026*
