# Ransomware Entropy Detector — v2.0 Anti-FP Edition

> Công cụ phát hiện ransomware dựa trên phân tích entropy + Machine Learning.
> **v2.0** tập trung giải quyết vấn đề False Positive (FP) — PNG/ZIP/EXE không còn bị cảnh báo nhầm.

---

## Vấn đề v1.0 đã giải quyết trong v2.0

| Vấn đề v1.0 | Giải pháp v2.0 |
| --- | --- |
| PNG screenshots bị flagged CRITICAL | Per-extension threshold: PNG dùng 0.80 thay vì 0.59 |
| ZIP/MP4 có entropy cao bị nhầm | Magic bytes validator: file hợp lệ → prob giảm 30% |
| Python scripts bị cảnh báo | class_weight={0:3.0, 1:1.0}: phạt FP 3x nặng hơn |
| Threshold cứng 0.5 | Precision-Recall curve optimization → threshold 0.59 |
| 10 features không phân biệt compressed vs encrypted | 16 features: `is_known_benign_format`, `ext_entropy_delta`, v.v. |

---

## Kiến trúc v2.0

```text
ransomware_detector_v2/
├── core/
│   ├── feature_extractor.py    ← v2: 16 features (tăng từ 10)
│   ├── dataset_generator.py    ← v2: 7 SAFE + 5 ENCRYPTED types
│   ├── ml_engine.py            ← v2: CalibratedMalwareDetector
│   ├── fp_reducer.py           ← MỚI: 3-tầng FP reduction
│   ├── scanner.py              ← v2: tích hợp FP reducer
│   ├── watchdog_monitor.py
│   └── report_generator.py
├── gui/
│   └── main_window.py          ← v2: Threshold Slider + FP stats
├── models/
│   └── rf_ransomware_detector.joblib
├── train_model.py              ← v2: 5000 samples, N_FEATURES=16
└── requirements.txt
```

---

## Tính năng mới v2.0

### 1. 16 Features (tăng từ 10)

| Feature | Mô tả | Vai trò Anti-FP |
| --- | --- | --- |
| `normalized_entropy` | Entropy chuẩn hóa theo loại file | PNG entropy 7.8 = bình thường |
| `byte_distribution_mode` | Mode của phân phối byte | Media/PE có mode ổn định |
| `compression_ratio_sim` | Tỷ lệ nén ước lượng | File nén hợp lệ vs random bytes |
| `structural_consistency` | Độ nhất quán cấu trúc | File nén: cao; ransomware: thấp |
| `extension_entropy_delta` | Chênh lệch entropy vs baseline | Phát hiện PNG giả |
| `is_known_benign_format` | Magic bytes hợp lệ? | 1.0 = file cấu trúc đúng |

### 2. FP Reducer 3 tầng (`core/fp_reducer.py`)

- **Tầng 1 — Whitelist**: Fonts, icons, logs → skip hoàn toàn
- **Tầng 2 — Per-extension Threshold**: PNG/ZIP/EXE dùng threshold cao hơn
- **Tầng 3 — Magic Bytes Discount**: File có magic bytes hợp lệ → prob × 0.70

### 3. Calibrated ML Engine (`core/ml_engine.py`)

- `CalibratedClassifierCV` với isotonic regression
- `class_weight={0:3.0, 1:1.0}` — phạt FP gấp 3 lần
- Threshold optimizer tự động trên Precision-Recall curve
- `CalibratedMalwareDetector.set_threshold()` — điều chỉnh từ GUI

### 4. GUI Threshold Slider

- Slider 0.30 → 0.95 để điều chỉnh sensitivity
- Hiển thị Precision / Recall / FP Rate từ model metadata
- Cột "FP↓" trong bảng kết quả: đánh dấu file được điều chỉnh
- Filter "FP Adj." để xem các file được giảm threshold

---

## Cài đặt & Chạy

```bash
# 1. Cài dependencies
pip install -r requirements.txt

# 2. Train model (bắt buộc lần đầu)
python train_model.py

# 3. Khởi động GUI
python main.py
```

---

## Performance Metrics (v2.0)

| Metric | Giá trị | Mục tiêu |
| --- | --- | --- |
| Accuracy | 100.0% | ≥ 95% |
| Precision | 100.0% | ≥ 95% |
| Recall | 100.0% | ≥ 90% |
| F1-Score | 100.0% | ≥ 92% |
| AUC-ROC | 100.0% | ≥ 98% |
| False Positive Rate | 0.00% | < 5% |
| CV F1 5-fold | 99.96% ± 0.05% | — |

> **Lưu ý**: Trên dữ liệu synthetic. Performance trên dữ liệu thực tế sẽ thấp hơn.
> Khuyến nghị: retrain trên dataset thực tế của bạn.

---

## Feature Importances (Top 5)

| Feature | Importance |
| --- | --- |
| Mean Byte | 25.7% |
| Is Known Benign Format | 16.9% |
| Chunk Entropy StdDev | 11.0% |
| Structural Consistency | 9.3% |
| Chunk Entropy Max | 7.5% |

---

## Root Cause Analysis — False Positive PNG

### Vấn đề (v1.0)

```text
PNG entropy tự nhiên: 7.6–7.9 bits/byte (do zlib compression)
                          ↓
High Entropy Ratio feature = 1.0 (vì > threshold cứng 7.2)
                          ↓
Model không có training samples cho "compressed_png" benign
                          ↓
Default threshold = 0.5 → TẤT CẢ PNG → ENCRYPTED
```

### Giải pháp (v2.0)

```text
is_known_benign_format = 1.0 (PNG magic bytes \x89PNG hợp lệ)
ext_entropy_delta      = 0.1 (entropy ~ baseline, không đáng ngờ)
compressed_png samples = 375 mẫu trong training set
                          ↓
Model học: "PNG với magic bytes hợp lệ + entropy cao = SAFE"
                          ↓
Per-extension threshold: PNG = 0.80 (thay vì 0.59)
Magic bytes discount:    prob × 0.70 (giảm 30%)
                          ↓
Screenshot PNG → SAFE ✅
```

---

## Phát triển thêm

- [ ] Retrain trên real-world malware samples (VirusTotal, MalwareBazaar)
- [ ] Thêm SMOTE oversampling cho minority classes
- [ ] Tích hợp YARA rules cho signature-based detection
- [ ] Export model analysis report (PDF)
- [ ] Whitelist editor trong GUI
