# Ransomware Entropy Detector — v2.1 Premium Defense

> Công cụ phát hiện ransomware dựa trên phân tích entropy + Machine Learning + YARA + heuristic.
> **v2.1** nâng cấp UI premium, giảm False Positive và tăng khả năng phát hiện bằng multi-signal fusion.

---

## Tổng quan

**Ransomware Entropy Detector** phân tích file bằng 3 lớp chính:

1. **ML Entropy Engine (16 features)** — mô hình RandomForest calibrate xác suất, threshold auto-tuned.
2. **FP Reduction Pipeline** — per-extension threshold + magic bytes discount + whitelist.
3. **YARA Signature + Heuristic Boost** — tăng điểm xác suất khi match rule hoặc dấu hiệu bất thường.

---

## Kiến trúc v2.1

```text
ransomware_detector_v2/
├── core/
│   ├── feature_extractor.py    ← 16 features (anti-FP)
│   ├── ml_engine.py            ← CalibratedMalwareDetector + threshold optimizer
│   ├── fp_reducer.py           ← 3-tầng FP reduction
│   ├── yara_engine.py          ← YARA rules + fallback signatures
│   ├── scanner.py              ← ML + YARA + Heuristic fusion
│   ├── watchdog_monitor.py     ← real-time protection
│   ├── report_generator.py     ← CSV/PNG report
│   └── pdf_reporter.py         ← PDF report
├── gui/
│   ├── main_window.py          ← Premium UI + Threat Intelligence
│   └── whitelist_editor.py     ← GUI quản lý whitelist
├── models/
│   └── rf_ransomware_detector.joblib
├── data/
│   └── whitelist.json
├── train_model.py
└── requirements.txt
```

---

## Tính năng chính v2.1

### 1. ML Engine (16 Features)
- **CalibratedClassifierCV + threshold tuning**
- **class_weight** chống FP
- **Precision-Recall optimization** để chọn threshold tối ưu
- **16 features** phân biệt compressed vs encrypted

### 2. FP Reduction Pipeline
- **Whitelist**: bỏ qua file hệ thống/fonts/logs
- **Per-extension threshold**: PNG/ZIP/EXE dùng ngưỡng cao hơn
- **Magic bytes validation**: file hợp lệ → giảm xác suất (prob × 0.70)

### 3. YARA + Heuristic Fusion
- **Built-in YARA rules** (WannaCry, LockBit, BlackCat, Ryuk, REvil, Conti, Cl0p, Play, Rhysida, Akira, BianLian, Medusa, Qilin...)
- **Fallback Python signatures** nếu không có `yara-python`
- **Heuristic boost** khi phát hiện dấu hiệu entropy bất thường

### 4. Premium GUI
- **Threat Intelligence panel** hiển thị YARA engine + heuristic state
- **Threshold slider** điều chỉnh độ nhạy 0.30 → 0.95
- **FP Adjusted indicator** trong bảng kết quả
- **Whitelist Editor** + Export CSV/PNG/PDF

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

> Nếu muốn dùng YARA hiệu năng cao:
>
> ```bash
> pip install yara-python
> ```

---

## Chế độ độ nhạy (Sensitivity Profiles)

- **Balanced**: cân bằng FN/FP
- **High Sensitivity**: ưu tiên bắt ransomware (FP cao hơn)
- **Paranoid**: tối đa nhạy (chỉ dùng cho giám sát nghiêm ngặt)

Cấu hình trong `core/scanner.py` (profile mặc định hiện tại: **High Sensitivity**).

---

## Performance Metrics (tham khảo)

> Metrics phụ thuộc dataset và mô hình hiện tại. Tham số hiển thị trong GUI có thể khác.

| Metric | Mục tiêu |
| --- | --- |
| Precision | ≥ 95% |
| FP Rate | < 5% |
| Recall | ≥ 90% |

---

## Hướng dẫn mở rộng YARA

- Thêm rules vào `core/yara_engine.py` (BUILTIN_YARA_RULES_SOURCE)
- Hoặc import file `.yar/.yara` (nếu có `yara-python`)

---

## Roadmap

- [ ] Retrain trên malware dataset thực tế (VirusTotal, MalwareBazaar)
- [ ] Thêm dynamic behavior signals (file rename bursts, mass IO)
- [ ] Rule pack updater (auto update YARA rules)
- [ ] Export forensic bundle (hashes + IOC report)

---

## Ghi chú

- Đây là công cụ nghiên cứu & phòng thủ. Không thay thế hoàn toàn EDR thương mại.
- Hãy retrain model nếu bạn triển khai cho môi trường production.
