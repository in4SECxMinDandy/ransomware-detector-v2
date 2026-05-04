# TỔNG QUAN: TẢI 5GB DỮ LIỆU MALWARE & TRAINING ML MODEL
## Ransomware Detector v2.1

> **Dự án**: Ransomware Detector v2.1 — Phát hiện & ngăn chặn ransomware đa lớp  
> **Lab**: PTIT Security Research Lab  
> **Ngôn ngữ**: Python 3.10+ (Windows 10/11)  
> **License**: MIT

---

## MỤC LỤC

1. [Tổng quan hệ thống](#1-tổng-quan-hệ-thống)
2. [Kiến trúc thư mục dữ liệu](#2-kiến-trúc-thư-mục-dữ-liệu)
3. [Pipeline tải 5GB dữ liệu](#3-pipeline-tải-5gb-dữ-liệu-tự-động)
4. [16 đặc trưng (features) trích xuất từ file](#4-16-đặc-trưng-features-trích-xuất)
5. [Sinh dữ liệu tổng hợp (Synthetic Dataset)](#5-sinh-dữ-liệu-tổng-hợp-synthetic-dataset)
6. [Training ML Model](#6-training-ml-model)
7. [SMOTE Oversampling](#7-smote-oversampling)
8. [Đánh giá & metrics](#8-đánh-giá--metrics)
9. [Các lệnh thực thi](#9-các-lệnh-thực-thi)

---

## 1. TỔNG QUAN HỆ THỐNG

Hệ thống phát hiện ransomware gồm **8 lớp phòng thủ**:

| Lớp | Thành phần | Mô tả |
|-----|-----------|-------|
| 1 | **ML Engine** | Random Forest classifier phân tích 16 features để phát hiện file mã hóa/ransomware |
| 2 | **Watchdog Monitor** | Giám sát filesystem real-time, phát hiện burst mã hóa hàng loạt |
| 3 | **Process Monitor** | Theo dõi hành vi tiến trình (burst I/O, đổi extension, rename nhanh) |
| 4 | **PE Analysis** | Phân tích cấu trúc file PE, phát hiện packer (UPX, VMProtect) và API đáng ngờ |
| 5 | **Threat Intelligence** | Tra cứu hash trên VirusTotal, MalwareBazaar, ThreatFox, AlienVault OTX |
| 6 | **YARA Engine** | 18 built-in rule cho các họ ransomware đã biết |
| 7 | **Honeypot/Decoy** | Triển khai file mồi ("passwords.xlsx", "wallet_keys.txt"...) để bẫy ransomware |
| 8 | **Auto-Responder** | Tự động quarantine file, kill process, chặn firewall |

**Giao diện**:
- **GUI**: CustomTkinter desktop app (Dashboard, Scan, Honeypot, ML Training tabs)
- **CLI**: `python main.py --scan PATH`
- **API**: FastAPI + JWT authentication
- **System Tray**: Tích hợp Windows system tray

---

## 2. KIẾN TRÚC THƯ MỤC DỮ LIỆU

```
ransomware-detector-v2/
├── datasets/                          ← THƯ MỤC DỮ LIỆU CHÍNH
│   ├── sources/                       ← Dữ liệu nguồn (raw)
│   │   ├── safe/                      ← File SAFE (lành tính) từ curated sources
│   │   └── encrypted/                 ← File ENCRYPTED/malware
│   │       └── malwarebazaar/         ← ↓ Dữ liệu tải từ MalwareBazaar (5GB)
│   │           ├── pe/                ←   File PE (.exe/.dll/.sys/.msi)
│   │           ├── office/            ←   File Office (.doc/.docx/.xls...)
│   │           └── _download_progress.json  ← Tiến trình download (resumable)
│   │
│   ├── prepared/                      ← Dữ liệu đã lọc PE-only
│   │   └── external_pe/
│   │       ├── safe/                  ← PE SAFE (lọc từ raw sources)
│   │       └── encrypted/             ← PE ENCRYPTED (lọc từ raw sources)
│   │
│   ├── manifests/                     ← JSON manifests theo dõi từng source
│   ├── datasets/                      ← CSV datasets đầu ra cho training
│   └── logs/                          ← Training logs
│
├── models/                            ← THƯ MỤC MODEL
│   ├── rf_ransomware_detector.joblib          ← Model chính (Random Forest)
│   ├── rf_ransomware_detector.joblib.sha256   ← Hash kiểm tra toàn vẹn
│   └── model_metadata.json                    ← Metrics metadata
│
├── data/                              ← DỮ LIỆU RUNTIME
│   ├── synthetic_dataset_v2.csv       ← Dataset tổng hợp có sẵn
│   ├── config.json                    ← Cấu hình toàn hệ thống
│   ├── whitelist.json                 ← Whitelist file/path
│   └── feedback_samples.csv           ← Phản hồi người dùng để retrain
│
└── core/                              ← ENGINE (logic nghiệp vụ)
    ├── ml_engine.py                   ← Model Random Forest
    ├── feature_extractor.py           ← Trích xuất 16 features
    ├── dataset_generator.py           ← Sinh dữ liệu tổng hợp
    ├── smote_trainer.py               ← SMOTE oversampling
    ├── external_dataset_builder.py    ← Build dataset từ external PE
    ├── pe_corpus_preparer.py          ← Lọc PE từ raw corpora
    ├── training_source_registry.py    ← Registry 6 source dữ liệu
    ├── training_source_planner.py     ← Orchestration: plan → manifest → train
    ├── training_progress.py           ← Báo cáo tiến trình training
    └── scanner.py                     ← Scanner đa luồng
```

---

## 3. PIPELINE TẢI 5GB DỮ LIỆU (TỰ ĐỘNG)

### 3.1. Tổng quan pipeline

File thực thi: **`scripts/pipeline_download_and_train.py`**

Pipeline gồm 4 bước:

```
┌───────────────────────────────────────────────────────────┐
│ Bước 1: Tải ~90 daily CSV từ abuse.ch                      │
│   URL: https://datalake.abuse.ch/malware-bazaar/daily/    │
│   Tổng: ~500MB CSV                                        │
└─────────────┬─────────────────────────────────────────────┘
              ▼
┌───────────────────────────────────────────────────────────┐
│ Bước 2: Quét CSVs, lọc hash ransomware                    │
│   - PE: .exe/.dll/.sys/.msi + keyword ransomware          │
│   - Office: .doc/.docx/.xls... + keyword malware           │
│   - Keywords: LockBit, BlackCat, Conti, REvil, WannaCry..│
│   → Output: danh sách SHA256 hash theo loại                │
└─────────────┬─────────────────────────────────────────────┘
              ▼
┌───────────────────────────────────────────────────────────┐
│ Bước 3: Tải sample qua MalwareBazaar API                   │
│   - API: https://bazaar.abuse.ch/api/                     │
│   - Mỗi sample: ZIP password "infected"                   │
│   - Giải nén, phân loại vào pe/ và office/                │
│   - Dừng khi đạt 5GB (70% PE, 30% Office)                 │
│   - Rate limit: 0.6 req/s                                 │
│   - Resumable: lưu _pipeline_progress.json                │
└─────────────┬─────────────────────────────────────────────┘
              ▼
┌───────────────────────────────────────────────────────────┐
│ Bước 4: Trích xuất features + Training Model               │
│   - Đọc từng file PE, trích 16 features                   │
│   - Kết hợp với synthetic SAFE data                        │
│   - Train Random Forest + SMOTE + Calibration              │
└─────────────────────────────────────────────────────────────┘
```

### 3.2. Download resume (tiếp tục khi bị ngắt)

Pipeline hỗ trợ **resumable download** — nếu bị ngắt (Ctrl+C, mất mạng), chạy lại sẽ tiếp tục từ nơi đã dừng:

```json
// _pipeline_progress.json
{
  "pe_bytes_done": 2450000000,       // Đã tải 2.45GB PE
  "of_bytes_done": 800000000,        // Đã tải 0.8GB Office
  "downloaded_hashes": ["abc123...", "def456..."],   // Hash đã tải
  "failed_hashes": ["xxx..."],       // Hash lỗi (bỏ qua khi chạy lại)
  "csv_dates_done": ["2026-04-01", "2026-04-02"],   // CSV dates đã xử lý
  "updated_at": "2026-05-02T10:30:00Z"
}
```

### 3.3. Cấu trúc class Pipeline

```python
class Pipeline:
    def __init__(self, args):
        self.total_bytes = 5GB          # Tổng dung lượng mục tiêu
        self.pe_bytes    = 3.5GB        # 70% PE
        self.of_bytes    = 1.5GB        # 30% Office
        self.rate        = 0.6          # Rate limit (giây/request)
        self.csv_days    = 90           # Số ngày CSV để quét
        self.data_dir    = datasets/sources/encrypted/malwarebazaar
```

**Các tham số dòng lệnh**:

| Tham số | Mặc định | Mô tả |
|---------|---------|-------|
| `--total-size-gb` | `5.0` | Tổng GB mục tiêu |
| `--pe-ratio` | `0.7` | Tỉ lệ PE (70% = 3.5GB) |
| `--csv-days` | `90` | Số ngày CSV quét ngược |
| `--rate-limit` | `0.6` | Số giây giữa các request |
| `--output` | `malwarebazaar` | Thư mục output |
| `--skip-csv` | `false` | Bỏ qua bước tải CSV |
| `--skip-download` | `false` | Bỏ qua tải, chỉ train |

### 3.4. Keyword dùng để lọc ransomware

**PE keywords** (đặc trưng cho ransomware):
```
ransomware, ransom, lockbit, blackcat, alphv, conti, revil,
sodinokibi, cuba, blackbasta, hive, vice, royal, bianlian,
play, medusa, ransomhub, akira, crylock, dharma, phobos,
stop, makop, maze, ryuk, wannacry, crypt, babuk, ragnar,
mount, avos, hello, trigona, clop, darkside, blackmatter
```

**Office keywords** (cả ransomware + malware khác):
```
ransomware, lockbit, emotet, trickbot, dridex, ursnif,
agenttesla, formbook, loki, azorult, remcos, njrat,
asyncrat, nanocore, quakbot, icedid, bumblebee, qbot,
ransom, malware, trojan, loader, dropper, downloader
```

### 3.5. Các curated training sources (6 nguồn)

Ngoài tải tự động từ MalwareBazaar, dự án còn có registry **6 nguồn dữ liệu**:

| Source ID | Tên | Loại | Kích thước | Cách lấy |
|-----------|-----|------|-----------|----------|
| `napierone` | NapierOne Mixed File | SAFE | ~10GB | AWS Registry |
| `govdocs1` | Govdocs1 | SAFE | ~5GB | HTML hướng dẫn |
| `filetypes1` | FILETYPES1 | SAFE | ~1GB | HTML hướng dẫn |
| `trusted-vendors` | Trusted Vendor Installers | SAFE | ~2GB | Thủ công |
| `sorel20m-github` | SOREL-20M GitHub | ENCRYPTED | ~8GB | HTML hướng dẫn |
| `sorel20m-aws` | SOREL-20M AWS | ENCRYPTED | **78GB** | AWS Registry |

Các source này phải tải thủ công (không tự động) vì kích thước lớn, vấn đề bản quyền và an toàn.

---

## 4. 16 ĐẶC TRƯNG (FEATURES) TRÍCH XUẤT

File: **`core/feature_extractor.py`**

Mỗi file được phân tích thành **16 đặc trưng**:

| # | Tên Feature | Mô tả |
|---|------------|-------|
| 0 | **Shannon Entropy** | Entropy toàn bộ file (byte-level) — ransomware có entropy cao do mã hóa |
| 1 | **Chi-Square (log)** | Độ đồng đều phân phối byte — file mã hóa có phân phối đều |
| 2 | **Mean Byte** | Giá trị byte trung bình |
| 3 | **Byte Variance** | Phương sai giá trị byte |
| 4 | **Serial Correlation** | Tương quan giữa các byte liên tiếp |
| 5 | **Chunk Entropy StdDev** | Độ lệch chuẩn entropy giữa các chunk — file bình thường không đồng nhất |
| 6 | **Chunk Entropy Max** | Entropy chunk cao nhất |
| 7 | **Chunk Entropy Min** | Entropy chunk thấp nhất |
| 8 | **High Entropy Ratio** | Tỉ lệ chunk có entropy cao (>7.5) |
| 9 | **Magic Bytes Mismatch** | Magic bytes có khớp với extension không? (ransomware thường giả mạo) |
| 10 | **Ext Entropy Z-Score** | Z-score của entropy so với baseline cùng extension |
| 11 | **Byte Mode Frequency** | Tần suất byte phổ biến nhất |
| 12 | **Compression Estimate** | Ước lượng khả năng nén (file mã hóa = không nén được) |
| 13 | **Structural Consistency** | Độ nhất quán entropy qua các chunk |
| 14 | **Ext Entropy Raw Delta** | Delta entropy thô (chưa clamp) so với baseline |
| 15 | **Is Known Benign Format** | Magic bytes có hợp lệ cho extension? |

**Cách đọc file thông minh**:
- File < 1MB → đọc toàn bộ
- File < 100MB → đọc đầu + đuôi + 16 chunk ngẫu nhiên
- File > 100MB → đọc 64 chunk cách đều, mỗi chunk 4KB

---

## 5. SINH DỮ LIỆU TỔNG HỢP (SYNTHETIC DATASET)

File: **`core/dataset_generator.py`**

Dữ liệu tổng hợp được dùng để:
1. Bổ sung SAFE samples khi không có đủ dữ liệu thật
2. Đảm bảo cân bằng class trong training
3. Mô phỏng nhiều loại file khác nhau

### 5.1. 7 loại file SAFE (lành tính)

| Loại | Tỉ lệ | Mô tả |
|------|-------|-------|
| `text_ascii` | 25% | File text ASCII thuần túy |
| `pe_valid` | 20% | File PE (Windows executable) hợp lệ |
| `compressed_png` | 15% | Ảnh PNG đã nén |
| `compressed_zip` | 15% | File ZIP đã nén |
| `media_mp4` | 10% | File media MP4 |
| `office_doc` | 10% | Tài liệu Office |
| `binary_struct` | 5% | File nhị phân có cấu trúc |

### 5.2. 5 loại file ENCRYPTED (mã hóa — giả lập ransomware)

| Loại | Tỉ lệ | Mô tả |
|------|-------|-------|
| `full_aes` | 35% | Mã hóa AES toàn bộ file |
| `intermittent` | 25% | Mã hóa từng phần (mô phỏng ransomware đang chạy) |
| `header_only` | 15% | Mã hóa phần header (mô phỏng kỹ thuật tránh phát hiện) |
| `disguised_png` | 15% | Ngụy trang thành PNG nhưng thực chất đã mã hóa |
| `disguised_zip` | 10% | Ngụy trang thành ZIP nhưng thực chất đã mã hóa |

Mỗi sample có kích thước 4KB-512KB, được ghi ra file tạm, trích xuất features, rồi xóa.

---

## 6. TRAINING ML MODEL

### 6.1. Kiến trúc model: `CalibratedMalwareDetector`

File: **`core/ml_engine.py`**

```python
Pipeline:
    StandardScaler → CalibratedClassifierCV(RandomForestClassifier)
```

**Random Forest Hyperparameters**:

| Tham số | Giá trị | Ý nghĩa |
|---------|---------|---------|
| `n_estimators` | **300** | Số cây trong rừng |
| `max_depth` | None | Không giới hạn độ sâu |
| `min_samples_split` | **4** | Số mẫu tối thiểu để split node (chống overfitting) |
| `min_samples_leaf` | **2** | Số mẫu tối thiểu ở leaf |
| `max_features` | `"sqrt"` | Số feature cho mỗi split |
| `class_weight` | `{0: 3.0, 1: 10.0}` | **Cost-aware**: phạt FN nặng gấp 3.3x FP |
| `n_jobs` | `1` (Windows), `-1` (Linux) | Số thread CPU |

**Calibration**: `CalibratedClassifierCV` với `method="isotonic"`, `cv=3` → chuyển output thành xác suất chính xác.

### 6.2. Quy trình training (4 bước)

```
┌─────────────────────────────────────────────────────────────┐
│ STEP 1: Sinh / chuẩn bị dataset                              │
│   - Sinh synthetic data (5000 SAFE + 5000 ENCRYPTED)        │
│   - HOẶC load dataset external PE (CSV)                      │
│   - HOẶC trích xuất features từ file PE thật                 │
└─────────────┬───────────────────────────────────────────────┘
              ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 2: Chia dữ liệu (stratified split)                      │
│   - 60% Train | 20% Validation | 20% Test                    │
│   - Stratified: giữ tỉ lệ class như nhau trong mỗi phần      │
│   - Thêm SMOTE trên training fold (không leak sang val/test)│
└─────────────┬───────────────────────────────────────────────┘
              ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 3: Train + Calibrate                                    │
│   - StandardScaler → RandomForest(300 trees, class_weight)  │
│   - Isotonic calibration (3-fold CV)                        │
│   - Threshold optimization: Precision ≥ 95%                 │
└─────────────┬───────────────────────────────────────────────┘
              ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 4: Đánh giá + Lưu model                                 │
│   - Metrics trên test set                                    │
│   - 5-fold CV F1 (trên original data, không SMOTE)          │
│   - Feature importances (top-10)                             │
│   - Lưu model.joblib + SHA256 sidecar + metadata.json       │
└─────────────────────────────────────────────────────────────┘
```

### 6.3. Threshold Optimization

Sau khi có xác suất từ model đã calibrate:

1. Duyệt qua các ngưỡng (threshold) từ 0.01 → 0.99
2. Với mỗi ngưỡng, tính Precision, Recall, FPR
3. Chọn ngưỡng **cao nhất** sao cho Precision ≥ 95%
4. Mục tiêu: giảm False Positive (không flag nhầm file lành)

### 6.4. Bảo vệ model (Integrity)

Model được bảo vệ chống giả mạo:
- **SHA256 hash** lưu trong file `.sha256` sidecar hoặc biến môi trường `RANSOMWARE_MODEL_SHA256`
- **Strict mode**: `RANSOMWARE_REQUIRE_MODEL_INTEGRITY=1` → từ chối load nếu hash không khớp
- **Versioned backups**: mỗi lần retrain tự động backup model cũ (timestamped `.joblib`)

### 6.5. Feedback loop (học từ phản hồi)

```
Người dùng flag file → feedback_samples.csv → retrain_with_feedback() → model mới
```

- Tự động retrain khi số feedback vượt ngưỡng (config: `ml_feedback.auto_retrain_threshold`)
- Hỗ trợ rollback nếu model mới kém hơn

---

## 7. SMOTE OVERSAMPLING

File: **`core/smote_trainer.py`**

SMOTE (**S**ynthetic **M**inority **O**versampling **TE**chnique) giải quyết vấn đề **class imbalance** — thực tế có ít mẫu ransomware hơn rất nhiều so với file lành.

### 5 chiến lược SMOTE:

| Strategy | Mô tả | Phù hợp |
|----------|-------|---------|
| **`smote_tomek`** *(khuyến nghị)* | SMOTE + Tomek Links — tạo minority samples rồi xóa noisy borderline | Đa số trường hợp |
| `smote` | SMOTE cơ bản — tạo synthetic từ k-nearest neighbors | Dataset sạch |
| `smote_enn` | SMOTE + Edited Nearest Neighbors — xóa ambiguous samples | Giảm noise |
| `adasyn` | Adaptive Synthetic — tập trung vào vùng khó phân loại | Ranh giới phức tạp |
| `borderline` | BorderlineSMOTE — chỉ tạo ở vùng biên | Ransomware variants |

**Nguyên tắc quan trọng**: SMOTE **chỉ áp dụng trên training fold**, không áp dụng trên validation/test để tránh data leakage.

```python
# Cách sử dụng
X_train_resampled, y_train_resampled = smote_trainer.resample(X_train, y_train)
# → Chỉ X_train thay đổi, X_val, X_test giữ nguyên
```

---

## 8. ĐÁNH GIÁ & METRICS

### 8.1. Metrics chính

| Metric | Mục tiêu | Công thức / Mô tả |
|--------|---------|-------------------|
| **Accuracy** | Càng cao càng tốt | (TP+TN) / Total |
| **Precision** | ≥ **95%** | TP / (TP+FP) — độ chính xác khi flag ransomware |
| **Recall** | Càng cao càng tốt | TP / (TP+FN) — tỉ lệ phát hiện ransomware thật |
| **F1-Score** | Cân bằng P và R | 2PR / (P+R) |
| **AUC-ROC** | Càng cao càng tốt | Diện tích dưới đường ROC |
| **FPR** | < **5%** | FP / (FP+TN) — tỉ lệ flag nhầm file lành |
| **CV F1 5-fold** | Ổn định (std thấp) | Cross-validation F1 trên original data |

### 8.2. Output khi train xong

```
==================================================
  TRAINING COMPLETE
  Accuracy:  97.34%
  Precision: 96.12%   (target >= 95%)
  Recall:    94.87%
  F1:        95.49%
  AUC-ROC:   99.21%
  False Pos. Rate: 1.23%   (target < 5%)
  CV 5-fold: 95.12% +/- 0.45%

  -- Threshold --
  Optimal threshold: 0.7234

  -- Feature Importances (top 10) --
    Shannon Entropy                      0.2845  ##############
    High Entropy Ratio                   0.1923  #########
    Compression Estimate                 0.1456  #######
    Chunk Entropy StdDev                 0.1234  ######
    ...
==================================================
```

### 8.3. Confusion Matrix

```
              Predicted SAFE  Predicted ENCRYPTED
Actual SAFE       TN (True Neg)     FP (False Pos)  ← File lành bị flag nhầm
Actual ENCRYPTED  FN (False Neg)    TP (True Pos)   ← Ransomware bị bỏ sót
```

Mục tiêu: FP thấp nhất có thể (class_weight={0:3.0, 1:10.0} phạt FN nặng hơn FP).

---

## 9. CÁC LỆNH THỰC THI

### 9.1. Tải 5GB + train tự động (1 lệnh)

```bash
# Pipeline đầy đủ: tải CSV → lọc hash → tải sample → train
python scripts/pipeline_download_and_train.py --total-size-gb 5 --pe-ratio 0.7

# Chỉ train model (bỏ qua download, dùng file đã có)
python scripts/pipeline_download_and_train.py --skip-download

# Bỏ qua CSV, dùng API trực tiếp
python scripts/pipeline_download_and_train.py --skip-csv
```

### 9.2. Train với synthetic data (nhanh, không cần internet)

```bash
# Train với SMOTE (khuyến nghị)
python train_model.py --smote smote_tomek --samples 5000

# Train không có SMOTE
python train_model.py --no-smote

# Train với BorderlineSMOTE (phù hợp ransomware variants)
python train_model.py --smote borderline
```

### 9.3. Train với external PE data

```bash
# Plan: lên kế hoạch lấy dữ liệu từ curated sources
python main.py --search-training-sources --query "malware"
python main.py --plan-training-source --scale pilot

# Prepare: lọc PE-only từ raw corpora
python main.py --prepare-external-pe

# Build dataset + train
python main.py --train-from-source-plan --scale pilot
```

### 9.4. Các lệnh khác

```bash
# Train nhanh với synthetic data (CLI)
python main.py --train

# Train từ external PE folders
python main.py --train-external

# Build auto-labeled dataset từ scan history + feedback
python main.py --build-auto-dataset --retrain

# Build dataset từ file PE
python build_auto_dataset.py
```

### 9.5. Windows .cmd shortcuts

```batch
download-training-source.cmd     ← Tải source hướng dẫn từ registry
plan-training-source.cmd         ← Lập kế hoạch acquisition
prepare-training-source.cmd      ← Chuẩn bị (lọc PE)
train-external.cmd               ← Train từ external PE
train-from-source-plan.cmd       ← Train từ source plan
prepare-external-pe.cmd          ← Lọc PE từ raw corpora
build-auto-dataset.cmd           ← Build auto-labeled dataset
training-progress.cmd            ← Xem tiến trình training
search-training-sources.cmd      ← Tìm kiếm trong source registry
```

---

## PHỤ LỤC: CÁC FILE QUAN TRỌNG

| File | Mục đích |
|------|---------|
| `scripts/pipeline_download_and_train.py` | **Pipeline tải 5GB + train** (1 lệnh chạy tất cả) |
| `scripts/download_malwarebazaar.py` | Downloader MalwareBazaar độc lập (10GB) |
| `train_model.py` | Standalone training script (SMOTE + YARA) |
| `core/ml_engine.py` | Model RF + calibration + threshold optimization |
| `core/feature_extractor.py` | Trích xuất 16 features từ file |
| `core/dataset_generator.py` | Sinh synthetic dataset (7 SAFE + 5 ENCRYPTED) |
| `core/smote_trainer.py` | SMOTE oversampling (5 strategies) |
| `core/external_dataset_builder.py` | Build CSV dataset từ file PE |
| `core/training_source_registry.py` | Registry 6 curated training sources |
| `core/training_source_planner.py` | Orchestration plan → manifest → train |
| `core/pe_corpus_preparer.py` | Lọc file PE từ thư mục raw |
| `data/config.json.template` | Template cấu hình toàn hệ thống |
| `requirements.txt` | Dependency runtime |
| `requirements-dev.txt` | Dependency phát triển (pytest, ruff...) |
