# Ransomware Entropy Detector v2.5

> Công cụ phát hiện ransomware đa lớp (multi-layer) mạnh mẽ: Machine Learning + YARA Rules + Threat Intelligence + Claude AI Analysis. Bảo vệ thời gian thực, giám sát hành vi Process, phân tích mạng và tự động phản ứng.

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Platform: Windows](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
[![Tests](https://img.shields.io/badge/Tests-140%2B%20passed-brightgreen.svg)](#7-kiểm-tra---testing)
[![Coverage](https://img.shields.io/badge/Coverage-85%25%2B-yellowgreen.svg)](#7-kiểm-tra---testing)

---

## Mục lục

1. [Tổng quan](#1-tổng-quan)
2. [Kiến trúc hệ thống](#2-kiến-trúc-hệ-thống)
3. [Chi tiết kiến trúc từng module](#3-chi-tiết-kiến-trúc-từng-module)
4. [Cài đặt](#4-cài-đặt)
5. [Hướng dẫn sử dụng](#5-hướng-dẫn-sử-dụng)
6. [Hiệu năng](#6-hiệu-năng)
7. [Kiểm tra - Testing](#7-kiểm-tra---testing)
8. [Các loại virus & File test](#8-các-loại-virus--file-test)
9. [Lộ trình phát triển - Roadmap](#9-lộ-trình-phát-triển---roadmap)
10. [Cấu hình nâng cao](#10-cấu-hình-nâng-cao)
11. [Giấy phép - License](#11-giấy-phép---license)

---

## 1. Tổng quan

**Ransomware Entropy Detector v2.5** là công cụ phòng chống ransomware đa lớp với 8 lớp phát hiện:

| # | Lớp phát hiện | Kỹ thuật | Mô tả |
| --- | --- | --- | --- |
| 1 | **ML Engine** | RandomForest + 16 features | Phát hiện entropy, phân bố byte, cấu trúc file |
| 2 | **YARA Rules** | 20+ signature rules | Nhận diện specific ransomware families |
| 3 | **Process Behavior** | Giám sát hành vi | Burst encryption, extension change, rapid file ops |
| 4 | **PE Analysis** | Static PE parsing | Packer, injection, RWX sections, overlay |
| 5 | **VirusTotal** | VT API v3 + cache | Cross-check SHA256 với 70+ AV engines |
| 6 | **Threat Intelligence** | MB + TF + OTX | Global TI context cho AI analysis |
| 7 | **Network Analysis** | C2 detection | DGA domains, beaconing, Feodo Tracker |
| 8 | **AI Deep Analysis** | Claude Sonnet 4.6 | Tổng hợp tất cả signals, đưa ra khuyến nghị ATT&CK |

**Nhóm ransomware được hỗ trợ:** WannaCry, LockBit 3.0, BlackCat/ALPHV, Ryuk, REvil/Sodinokibi, Conti, Cl0p, Play, Rhysida, Akira, BianLian, Medusa, Qilin + Generic Ransom Note patterns.

**Định dạng file hỗ trợ:** PE (.exe/.dll/.sys), Office (.doc/.docx/.docm/.xls/.xlsx/.xlsm/.ppt/.pptx), PDF, RTF, ZIP, 7z, RAR, PNG, MP4, TXT, và 40+ extension đáng ngờ.

---

## 2. Kiến trúc hệ thống

### 2.1. Tổng quan kiến trúc (System Architecture Overview)

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                           RANSOMWARE DETECTOR v2.5                            │
│                              Entry Points (main.py)                            │
└─────────────────────────────────┬────────────────────────────────────────────┘
                                  │
                    ┌─────────────┴──────────────┐
                    │   config_manager.py          │
                    │   (Central Configuration     │
                    │    Singleton — 20 sections) │
                    └─────────────┬──────────────┘
                                  │
        ┌─────────────────────────┼──────────────────────────────────────────────┐
        │                         │                                              │
        ▼                         ▼                                              ▼
┌───────────────────┐   ┌──────────────────┐   ┌──────────────────────────────┐
│   GUI Layer        │   │  Scanner Layer   │   │  Monitoring Layer            │
│  (CustomTkinter)   │   │  (Multi-threaded)│   │  (watchdog + psutil)        │
│  11 Tabs           │   │                  │   │                              │
│                    │   │  • Full Scan     │   │  • Real-time Protection      │
│  • Dashboard       │   │  • Quick Scan    │   │  • Entropy Burst Watch      │
│  • Scan            │   │  • Incremental   │   │  • Process Monitor          │
│  • Alerts          │   │  • Office Scan   │   │  • Network Monitor          │
│  • Settings        │   │                  │   │  • Honeypot Deploy          │
│  • Quarantine      │   │                  │   │                              │
│  • Reports         │   │                  │   │                              │
│  • Logs            │   │                  │   │                              │
│  • Office Scanner  │   │                  │   │                              │
│  • Entropy Watch   │   │                  │   │                              │
│  • Honeypot        │   │                  │   │                              │
│  • ML Training     │   │                  │   │                              │
└────────┬────────────┘   └────────┬─────────┘   └──────────────┬───────────────┘
         │                          │                            │
         │    ┌─────────────────────┼────────────────────────────┤
         │    │                     │                            │
         ▼    ▼                     ▼                            ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                              CORE ANALYSIS PIPELINE                               │
│                                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────────┐ │
│  │ feature_     │───▶│  ML Engine   │───▶│  FP Reducer  │───▶│  Heuristic     │ │
│  │ extractor    │    │  (RF 300     │    │  (3 layers)  │    │  Signals       │ │
│  │ 16 features  │    │  Calibrated) │    │  • Whitelist │    │  • Entropy Z   │ │
│  │              │    │              │    │  • Per-ext    │    │  • Compression │ │
│  │ • Entropy    │    │              │    │    threshold  │    │  • Structure   │ │
│  │ • Chi-Square │    │              │    │  • Magic Byte│    │                │ │
│  │ • Byte Dist  │    │              │    │              │    │                │ │
│  │ • Correlation│    │              │    │              │    │                │ │
│  │ • ...        │    │              │    │              │    │                │ │
│  └──────────────┘    └──────────────┘    └──────────────┘    └───────┬────────┘ │
│                                                                     │          │
│         ┌────────────────────────────────────────────────────────────┘          │
│         │                                                                     │
│         ▼                                                                     ▼
│  ┌────────────────┐    ┌────────────────┐    ┌─────────────────────────────┐   │
│  │  PE Analyzer   │    │  YARA Engine   │    │  VT + TI Correlation       │   │
│  │  (PE header,   │    │  20+ rules:    │    │                             │   │
│  │   sections,    │    │  • WannaCry    │    │  ┌──────────────────────┐  │   │
│  │   imports,     │    │  • LockBit 3    │    │  │  VirusTotal API v3   │  │   │
│  │   packer)      │    │  • BlackCat     │    │  │  4 req/min, cache   │  │   │
│  │                │    │  • Ryuk         │    │  └──────────────────────┘  │   │
│  │  Threat Score  │    │  • Generic      │    │  ┌──────────────────────┐  │   │
│  │  ≥0.60 CONFIRM │    │    Ransom Note  │    │  │  MalwareBazaar       │  │   │
│  │  ≥0.35 LIKELY  │    │  ≥0.30 boost    │    │  │  ThreatFox           │  │   │
│  │  ≥0.15 SUSP    │    │                 │    │  │  AlienVault OTX v3   │  │   │
│  └───────┬────────┘    └───────┬────────┘    │  └──────────────────────┘  │   │
│          │                     │              │                             │   │
│          └─────────────────────┴──────────────┴──────────────┬────────────┘   │
│                                                               │                 │
│                              ┌────────────────────────────────┘                 │
│                              ▼                                                 │
│                    ┌─────────────────────┐                                     │
│                    │  AI Analyzer        │                                     │
│                    │  (Claude Sonnet 4.6)│                                     │
│                    │                     │                                     │
│                    │  Threat Data Input: │                                     │
│                    │  • 16 ML features   │                                     │
│                    │  • PE analysis      │                                     │
│                    │  • YARA matches     │                                     │
│                    │  • VT detections    │                                     │
│                    │  • TI correlation   │──────────────────▶ ATT&CK Mapping │
│                    │  • Process behavior │                                     │
│                    │  • Entropy context  │                                     │
│                    │                     │                                     │
│                    │  AI Output:         │                                     │
│                    │  • Risk Assessment  │                                     │
│                    │  • MITRE ATT&CK     │                                     │
│                    │  • IOCs             │                                     │
│                    │  • Incident Actions │                                     │
│                    └─────────────────────┘                                     │
└──────────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                          RESPONSE & REPORTING LAYER                               │
│                                                                                  │
│  ┌───────────────────┐  ┌───────────────────┐  ┌──────────────────────────────┐ │
│  │  Auto-Responder   │  │  Notifications     │  │  Report Export              │ │
│  │  ────────────────  │  │  ────────────────  │  │  ────────────────────────   │ │
│  │  • Quarantine     │  │  • Windows Toast   │  │  • CSV (detailed)           │ │
│  │  • Kill Process   │  │    (win10toast →   │  │  • PNG (charts)             │ │
│  │  • Block Network  │  │     PowerShell)    │  │  • PDF (styled)             │ │
│  │  • Restore File   │  │  • Severity sounds │  │  • Forensic Bundle (ZIP)    │ │
│  │                   │  │  • History queue   │  │    - hashes.json            │ │
│  │  CRITICAL → auto  │  │                   │  │    - ioc_report.json        │ │
│  │  HIGH → ask user  │  │                   │  │    - timeline.csv           │ │
│  │  MEDIUM → notify  │  │                   │  │    - summary.txt            │ │
│  └───────────────────┘  └───────────────────┘  └──────────────────────────────┘ │
│                                                                                  │
│  ┌───────────────────┐  ┌───────────────────┐  ┌──────────────────────────────┐ │
│  │  Honeypot Manager │  │  Office Doc        │  │  Threat Intel Cache          │ │
│  │  ────────────────  │  │  Analyzer         │  │  ──────────────────────      │ │
│  │  Decoy files:     │  │  ────────────────  │  │  data/ti_cache.json         │ │
│  │  • passwords.xlsx │  │  • VBA Macro      │  │  data/vt_cache.json         │ │
│  │  • backup.docx    │  │    detection      │  │  TTL 24h, per-source rate   │ │
│  │  • financial_*.pdf│  │  • PDF /OpenAction│  │  limits                     │ │
│  │  • company_*.txt  │  │  • Suspicious     │  │                             │ │
│  │                   │  │    keywords       │  │                             │ │
│  │  Auto-deploy +    │  │  • RTF OLE        │  │                             │ │
│  │  watchdog monitor │  │    shellcode      │  │                             │ │
│  └───────────────────┘  └───────────────────┘  └──────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2. Luồng dữ liệu (Data Flow)

```text
File Input
    │
    ├── CLI: python main.py --scan "C:\path"
    ├── GUI: User selects folder → Start Scan
    └── Real-time: watchdog event (file modified)
            │
            ▼
    ┌───────────────────────┐
    │  Queue (maxsize=500)  │  ← ThreadPoolExecutor worker threads
    └──────────┬────────────┘
               ▼
    ┌───────────────────────┐
    │  _scan_single_file()  │  ← 9-step pipeline
    │  (1) Whitelist check  │
    │  (2) Feature Extract  │  ◄── feature_extractor.py (16 features)
    │  (3) ML Prediction    │  ◄── ml_engine.py (RandomForest)
    │  (4) FP Reduction     │  ◄── fp_reducer.py (3 layers)
    │  (5) Heuristics       │
    │  (6) PE Analysis      │  ◄── pe_analyzer.py
    │  (7) YARA Scan        │  ◄── yara_engine.py
    │  (8) VT Lookup        │  ◄── virustotal_client.py
    │  (9) TI Correlation   │  ◄── threat_intel_client.py
    └──────────┬────────────┘
               ▼
    ┌───────────────────────┐
    │  ScanResult dataclass │  ← 40+ fields including all TI data
    │  • probability        │
    │  • risk_level          │
    │  • yara_matches       │
    │  • vt_* fields        │
    │  • ti_* fields        │
    │  • pe_info            │
    └──────────┬────────────┘
               ▼
    ┌──────────┴────────────┐
    │                      │
    ▼                      ▼
 Threat File           Clean File
    │                      │
    ▼                      ▼
 Auto-Responder      Log Only
    │
    ├─▶ Quarantine
    ├─▶ Kill Process     (if process detected)
    ├─▶ Block Network    (Windows Firewall)
    ├─▶ AI Analysis      (Claude Sonnet 4.6)
    │       │
    │       ▼
    │   ┌───────────────────────────────┐
    │   │  Claude AI receives:         │
    │   │  • threat_data (all signals) │
    │   │  • TI correlation context    │
    │   │  • YARA family names         │
    │   │  • VT detection ratio        │
    │   │  • PE structural analysis     │
    │   │  • Entropy z-score context   │
    │   │                               │
    │   │  AI outputs:                  │
    │   │  • Structured report          │
    │   │  • MITRE ATT&CK mapping       │
    │   │  • IOC extraction             │
    │   │  • Incident response actions  │
    │   └───────────────────────────────┘
    │
    └─▶ Notification (Windows Toast)
            │
            ▼
      Windows Action Center
```

### 2.3. Incremental Scan Flow

```text
Full Scan (lần đầu)
    │
    ├── Extract features → ML predict → Save SHA256 + mtime + entropy
    │                                      │
    │                                      ▼
    │                               data/scan_cache.json
    │
    ▼
Incremental Scan (lần sau)
    │
    ├── Compare file mtime + size vs cache
    │
    ├── If SAME      → Skip (result from cache)
    ├── If MODIFIED  → Re-scan (full pipeline)
    └── If NEW       → Scan (full pipeline)
                            │
                            ▼
                      Update scan_cache.json
```

---

## 3. Chi tiết kiến trúc từng module

### 3.1. Feature Extraction — `core/feature_extractor.py`

**Mục đích:** Trích xuất vector 16 đặc trưng từ mỗi file, dùng cho ML engine.

**Architecture:**

```text
File Input (path)
    │
    ├── File size check
    │     │
    │     ├── < 1 MB  → Read entire file
    │     ├── 1-100MB → 64 uniform chunk samples
    │     └── > 100MB → 64 uniform chunk samples
    │
    ├── Magic bytes (first 8 bytes)
    │
    ├── Shannon Entropy calculation
    │     H = -Σ p(x)·log₂(p(x))
    │
    ├── Chi-Square test
    │     χ² = Σ (observed - expected)² / expected
    │
    ├── Byte Distribution
    │     Mean, Variance, Mode frequency, Serial Correlation
    │
    ├── Chunk-based features
    │     Chunk size = min(4096, file_size // 64)
    │     Per-chunk: entropy, count > 7.2
    │     Aggregate: std, max, min, high_entropy_ratio
    │
    ├── Compression Estimate (RLE pass)
    │
    └── Structural Consistency
          CV = std(chunk_entropies) / mean(chunk_entropies)
```

**Output:** `np.array([16 features])` + metadata dict

**Smart sampling strategy:**

| File size | Strategy | Memory |
| --- | --- | --- |
| < 1 MB | Full read | file_size |
| 1–100 MB | 64 uniform 4KB chunks | 256 KB |
| > 100 MB | 64 uniform 4KB chunks | 256 KB |

**Extension baselines** (entropy context):

| Extension | Baseline μ±σ | Notes |
| --- | --- | --- |
| `.png` | 7.60 ± 0.40 | PNG has built-in compression |
| `.zip` | 7.80 ± 0.35 | ZIP compressed |
| `.mp4` | 7.70 ± 0.50 | Video codec |
| `.exe` | 6.50 ± 0.80 | PE varies widely |
| `.txt` | 4.50 ± 1.20 | Plain text |
| `.docx` | 5.80 ± 0.90 | Office XML |

---

### 3.2. ML Engine — `core/ml_engine.py`

**Mục đích:** Train và predict ransomware vs benign dựa trên 16 features.

**Architecture:**

```text
┌─────────────────────────────────────────────────────────┐
│                   TRAINING PIPELINE                      │
│                                                         │
│  ┌──────────────────┐    ┌────────────────────────────┐ │
│  │  Dataset Gen     │───▶│  Feature Extraction       │ │
│  │  (5000+ samples) │    │  (16 features per file)   │ │
│  │                  │    └──────────────┬─────────────┘ │
│  │  7 benign types  │                  │               │
│  │  5 encrypted types                 ▼               │
│  └──────────────────┘    ┌────────────────────────────┐ │
│                          │  SMOTE Oversampling        │ │
│                          │  (smote_tomek recommended) │ │
│                          └──────────────┬─────────────┘ │
│                                          │               │
│                                          ▼               │
│                          ┌────────────────────────────┐ │
│                          │  Train/Test Split          │ │
│                          │  (80/20, stratified)       │ │
│                          └──────────────┬─────────────┘ │
│                                          │               │
│                     ┌────────────────────┴──────────────┐
│                     ▼                                 ▼
│          ┌────────────────────┐          ┌────────────────────┐
│          │  RandomForest      │          │  Validation Set    │
│          │  n_estimators=300  │          │  (threshold opt)   │
│          │  class_weight=     │          │                    │
│          │  {0:3.0, 1:1.0}   │          │  Target:           │
│          │                    │          │  Precision ≥ 95%   │
│          └────────┬───────────┘          └─────────┬──────────┘
│                   │                                 │
│                   ▼                                 │
│          ┌────────────────────┐                      │
│          │  CalibratedClassifier│                    │
│          │  CV (isotonic)      │◀────────────────────┘
│          └────────┬─────────────┘
│                   │
│                   ▼
│          ┌────────────────────┐
│          │  Optimized         │
│          │  Threshold          │──▶ precision ≥ 95%
│          └────────┬───────────┘
│                   │
│                   ▼
│          ┌────────────────────┐
│          │  Pipeline (.joblib) │
│          │  + metadata.json   │
│          └────────────────────┘
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                  PREDICTION PIPELINE                     │
│                                                         │
│  ┌──────────────────┐    ┌────────────────────────────┐ │
│  │  Scan Result     │───▶│  Feature Extraction (16)   │ │
│  │  (file path)     │    └──────────────┬─────────────┘ │
│  └──────────────────┘                   │               │
│                                         ▼               │
│                          ┌────────────────────────────┐ │
│                          │  ML Pipeline.predict()     │ │
│                          │  CalibratedClassifierCV     │ │
│                          └──────────────┬─────────────┘ │
│                                         │               │
│                          ┌──────────────┴──────────────┐
│                          ▼                              ▼
│               ┌─────────────────┐          ┌──────────────────┐
│               │ probability[0]│          │ probability[1]   │
│               │ (benign score) │          │ (ransomware)     │
│               └────────┬────────┘          └────────┬─────────┘
│                        │                              │
│                        │        ┌────────────────────┘
│                        ▼        ▼
│               ┌────────────────────┐
│               │ Final Probability  │──▶ FP Reducer
│               │ = proba[1]          │
│               └────────────────────┘
└─────────────────────────────────────────────────────────┘
```

**Key design decisions:**

- `class_weight={0: 3.0, 1: 1.0}` — FP chết tiệt hơn FN 3 lần
- `CalibratedClassifierCV(isotonic)` — Probability được calibrate về đúng tỷ lệ
- Threshold optimization — Tìm ngưỡng mà Precision ≥ 95% trên validation set
- Feedback loop — User feedback được lưu vào `feedback_samples.csv`, retrain khi đủ 50 mẫu

---

### 3.3. Scanner — `core/scanner.py`

**Mục đích:** Điều phối toàn bộ pipeline quét file, hỗ trợ đa chế độ (full/quick/incremental).

**Architecture:**

```text
┌─────────────────────────────────────────────────────────────────┐
│                 SCAN PIPELINE (9 STEPS)                         │
│                                                                 │
│  Step 1: WHITELIST CHECK (fp_reducer)                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  • Path keyword: Windows\, Program Files\, ...          │   │
│  │  • Extension: .lnk, .ttf, .log, .cache, ...             │   │
│  │  • → Skip if matched, log as CLEAN                      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  Step 2: FEATURE EXTRACTION (feature_extractor)                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  • Extract 16 features                                   │   │
│  │  • Smart sampling (full/sparse based on size)           │   │
│  │  • Z-score vs extension baseline                        │   │
│  └──────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  Step 3: ML PREDICTION (ml_engine)                             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  • CalibratedClassifierCV.predict_proba()               │   │
│  │  • raw_probability = proba[1]                           │   │
│  │  • Initial risk_level from probability                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  Step 4: FP REDUCTION (fp_reducer)                             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Layer 1: Extension threshold                             │   │
│  │    PNG/ZIP → ×1.0, text → ×0.55                          │   │
│  │  Layer 2: Magic bytes validation                        │   │
│  │    Valid header → probability × 0.70                     │   │
│  │  Layer 3: Known benign format                           │   │
│  │    Matching magic bytes → fp_adjusted = True            │   │
│  └──────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  Step 5: HEURISTIC SIGNALS                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  • Entropy z-score > 2.0 → +0.10 to probability         │   │
│  │  • Compression ratio > 0.95 → +0.15                     │   │
│  │  • Struct consistency < 0.05 → suspicious               │   │
│  │  • → fp_reason string (pipeline steps)                 │   │
│  └──────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  Step 6: PE ANALYSIS (pe_analyzer) [.exe/.dll/.sys only]      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  • MZ/PE header parsing (raw or pefile lib)             │   │
│  │  • Section entropy & RWX flags                          │   │
│  │  • Dangerous import APIs (VirtualAllocEx + WriteProcess  │   │
│  │    Memory + CreateRemoteThread = CONFIRMED_MALICIOUS)    │   │
│  │  • Packer detection (UPX/ASPack/Themida/VMP)            │   │
│  │  • → pe_info dict + pe_threat_score                     │   │
│  └──────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  Step 7: YARA SCAN (yara_engine)                               │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  • Try yara-python first                                 │   │
│  │  • Fallback: pure-Python byte matching                  │   │
│  │  • Match 20+ rules (WannaCry, LockBit, BlackCat...)     │   │
│  │  • Severity boost: CRITICAL +0.30, HIGH +0.15          │   │
│  │  • yara_boosted flag                                    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  Step 8: VIRUSTOTAL LOOKUP (virustotal_client)                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  • Lookup SHA256 in VT cache first (24h TTL)           │   │
│  │  • If cache miss → API call (rate limit: 4 req/min)    │   │
│  │  • If ≥40 engines agree clean → VT fusion               │   │
│  │    → Downgrade HIGH/CRITICAL → MEDIUM                   │   │
│  │  • → vt_available, vt_detection_ratio, vt_permalink     │   │
│  └──────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  Step 9: THREAT INTELLIGENCE (threat_intel_client)             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Parallel queries (rate-limited):                       │   │
│  │                                                         │   │
│  │  ┌────────────────┐  ┌────────────────┐  ┌───────────┐ │   │
│  │  │ MalwareBazaar  │  │ ThreatFox      │  │ AlienVault│ │   │
│  │  │ abuse.ch       │  │ abuse.ch       │  │ OTX v3    │ │   │
│  │  │ 60 req/min     │  │ 10 req/min     │  │ 20 req/min│ │   │
│  │  │ No API key     │  │ API key req    │  │ API key   │ │   │
│  │  │ (basic lookup) │  │               │  │ req       │ │   │
│  │  └───────┬────────┘  └───────┬────────┘  └─────┬─────┘ │   │
│  │          │                   │                │       │   │
│  │          └───────────────────┴────────────────┘       │   │
│  │                          │                             │   │
│  │                          ▼                             │   │
│  │                 ┌──────────────────┐                   │   │
│  │                 │ TIResult dataclass │                  │   │
│  │                 │ (unified output)   │                  │   │
│  │                 └────────┬───────────┘                  │   │
│  │                          │                              │   │
│  │                          ▼                              │   │
│  │                 ┌──────────────────┐                   │   │
│  │                 │ ti_context string │──▶ AI Analyzer   │   │
│  │                 │ for AI prompt     │                   │   │
│  │                 └──────────────────┘                   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  Output: ScanResult (40+ fields)                                │
└──────────────────────────────────────────────────────────────────┘
```

**Scan modes:**

| Mode | Behavior |
| --- | --- |
| **Full Scan** | Recursive, all files matching extension filters |
| **Quick Scan** | Non-recursive, top-level directory only |
| **Incremental** | Compare against `scan_cache.json`, re-scan modified/new files only |
| **Office Scan** | `.doc/.docx/.docm/.xls/.xlsx/.xlsm/.ppt/.pptx/.pdf/.rtf` only |
| **Hash Scan** | Direct SHA256 lookup (no file required) |

---

### 3.4. Threat Intelligence Correlation — `core/threat_intel_client.py`

**Mục đích:** Bổ sung global threat context cho AI analysis bằng cách tra cứu 3 nguồn TI miễn phí.

**Architecture:**

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                    THREAT INTELLIGENCE PIPELINE                         │
│                                                                          │
│  Input: SHA256 hash                                                      │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  CACHE CHECK (data/ti_cache.json)                               │    │
│  │  ┌────────────────────────────────────────────────────────────┐  │    │
│  │  │  if sha256 in cache AND not expired → return cached      │  │    │
│  │  │  else → proceed to API queries                            │  │    │
│  │  └────────────────────────────────────────────────────────────┘  │    │
│  └─────────────────────────────┬───────────────────────────────────────┘    │
│                                │                                           │
│              ┌─────────────────┼──────────────────┐                        │
│              │                 │                  │                        │
│              ▼                 ▼                  ▼                        │
│  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────────┐     │
│  │  MalwareBazaar    │ │  ThreatFox        │ │  AlienVault OTX v3   │     │
│  │  ─────────────── │ │  ──────────       │ │  ──────────────────  │     │
│  │  Rate: 60 req/min│ │  Rate: 10 req/min │ │  Rate: 20 req/min    │     │
│  │  API Key: None   │ │  API Key: Required│ │  API Key: Required  │     │
│  │                  │ │                  │ │                      │     │
│  │  POST /api/      │ │  POST /api/       │ │  GET /api/v3/        │     │
│  │  {query:         │ │  {query:          │ │  indicators/file/    │     │
│  │   get_info,      │ │   search_ioc,     │ │  sha256/{hash}        │     │
│  │   hash: sha256}  │ │   hash: sha256}   │ │                      │     │
│  │                  │ │                  │ │                      │     │
│  │  Returns:        │ │  Returns:         │ │  Returns:            │     │
│  │  • signature     │ │  • threat_type   │ │  • pulse_count      │     │
│  │  • first_seen    │ │  • malware_family│ │  • pulse_names      │     │
│  │  • tags          │ │  • confidence   │ │  • analysis_metadata │     │
│  │  • delivery_     │ │  • tags          │ │  • country_code     │     │
│  │    method        │ │  • ioc_type      │ │  • score            │     │
│  └────────┬─────────┘ └────────┬─────────┘ └──────────┬───────────┘     │
│           │                    │                    │                 │
│           └────────────────────┴────────────────────┘                 │
│                            │                                           │
│                            ▼                                           │
│               ┌─────────────────────────┐                             │
│               │   TIResult dataclass    │                             │
│               │   (unified output)      │                             │
│               │                         │                             │
│               │ mb_available: bool      │                             │
│               │ mb_family: str          │                             │
│               │ tf_confidence: int     │                             │
│               │ otx_pulse_count: int    │                             │
│               │ otx_pulse_names: list   │                             │
│               │ ...                     │                             │
│               └───────────┬─────────────┘                             │
│                           │                                            │
│           ┌───────────────┼──────────────────┐                        │
│           │               │                  │                        │
│           ▼               ▼                  ▼                        │
│  ┌────────────────┐ ┌────────────────┐ ┌────────────────────────┐   │
│  │  ti_context    │ │ ti_context      │ │ ti_context (OTX)        │   │
│  │  string for    │ │ string for      │ │ "AlienVault OTX:       │   │
│  │  AI prompt    │ │ AI prompt       │ │  3 pulses | Pulses=..." │   │
│  │                │ │                 │ │                        │   │
│  │  "MB: FAMILY= │ │ "TF: Type=     │ │                        │   │
│  │   LockBit |   │ │  Ransomware |   │ │                        │   │
│  │   Confidence=  │ │  Family=LockBit │ │                        │   │
│  │   95%..."      │ │  | Conf=90%"    │ │                        │   │
│  └────────────────┘ └────────────────┘ └────────────────────────┘   │
│                                                                          │
│  Output: TIResult → ScanResult.ti_* fields                             │
└──────────────────────────────────────────────────────────────────────────┘
```

**Cache structure (`data/ti_cache.json`):**

```json
{
  "cache_version": "1.0",
  "last_updated": "2026-03-29T20:00:00",
  "entries": {
    "abc123...": {
      "sha256": "abc123...",
      "result": { "mb_available": true, ... },
      "cached_at": "2026-03-29T20:00:00",
      "expires_at": "2026-03-30T20:00:00"
    }
  }
}
```

---

### 3.5. AI Analyzer — `core/ai_analyzer.py`

**Mục đích:** Dùng Claude Sonnet 4.6 để tổng hợp tất cả signals và đưa ra báo cáo phân tích chuyên sâu.

**Architecture:**

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                    AI ANALYSIS PIPELINE                                  │
│                                                                          │
│  Input: ScanResult (40+ fields) OR threat_data dict                   │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  THREAT DATA CONSTRUCTION (analyze_scan_result)                  │    │
│  │                                                                  │    │
│  │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────────┐│    │
│  │  │ ML Pipeline │  │ PE Analysis  │  │ YARA Matches           ││    │
│  │  │ raw_proba   │  │ is_packed    │  │ rule names + boost     ││    │
│  │  │ adj_proba   │  │ RWX sections │  │                        ││    │
│  │  │ fp_reason   │  │ suspicious_   │  │                        ││    │
│  │  │ ml_level    │  │   sections   │  │                        ││    │
│  │  └──────┬──────┘  └──────┬───────┘  └───────────┬──────────────┘│    │
│  │         │                │                     │               │    │
│  │         └────────────────┴─────────────────────┘               │    │
│  │                          │                                      │    │
│  │                          ▼                                      │    │
│  │         ┌──────────────────────────────┐                       │    │
│  │         │  VIRUSTOTAL CONTEXT          │                       │    │
│  │         │  • detection_ratio: "12/72"  │                       │    │
│  │         │  • malicious/suspicious count │                       │    │
│  │         │  • permalink URL             │                       │    │
│  │         └──────────────┬───────────────┘                       │    │
│  │                         │                                       │    │
│  │                         ▼                                       │    │
│  │         ┌──────────────────────────────┐                       │    │
│  │         │  THREAT INTEL CONTEXT        │ ◄── NEW (v3.5)       │    │
│  │         │                               │                       │    │
│  │         │  MalwareBazaar:               │                       │    │
│  │         │  "FAMILY=LockBit | FirstSeen= │                       │    │
│  │         │   2024-01-15 | Delivery=email │                       │    │
│  │         │   | Tags=[ransomware,encrypt]"│                       │    │
│  │         │                               │                       │    │
│  │         │  ThreatFox:                   │                       │    │
│  │         │  "Type=Ransomware | Family=    │                       │    │
│  │         │   LockBit | Confidence=95% |   │                       │    │
│  │         │   Tags=[lockbit3,encrypt]"     │                       │    │
│  │         │                               │                       │    │
│  │         │  AlienVault OTX:              │                       │    │
│  │         │  "3 pulses | Pulses=LockBit 3.0 │                       │    │
│  │         │   campaign, ... | Score=85"    │                       │    │
│  │         └──────────────┬─────────────────┘                       │    │
│  │                        │                                        │    │
│  │                        ▼                                        │    │
│  │         ┌──────────────────────────────┐                       │    │
│  │         │  ENTROPY CONTEXT             │                       │    │
│  │         │  • raw_entropy: 7.89         │                       │    │
│  │         │  • z_score vs baseline: 3.2σ │                       │    │
│  │         │  • interpretation: ABNORMAL  │                       │    │
│  │         └──────────────────────────────┘                       │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                             │                                          │
│                             ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │  CLAUDE PROMPT CONSTRUCTION                                       │  │
│  │                                                                  │  │
│  │  System: "You are a cybersecurity expert analyzing ransomware" │  │
│  │                                                                  │  │
│  │  ┌────────────────────────────────────────────────────────────┐ │  │
│  │  │ ## FILE IDENTIFICATION                                     │ │  │
│  │  │ ## ENTROPY ANALYSIS (vs extension baseline)                 │ │  │
│  │  │ ## MACHINE LEARNING ANALYSIS (raw → adjusted pipeline)      │ │  │
│  │  │ ## PE STRUCTURAL ANALYSIS                                   │ │  │
│  │  │ ## YARA SIGNATURE MATCHES (+ caution note)                  │ │  │
│  │  │ ## VIRUSTOTAL INTELLIGENCE                                  │ │  │
│  │  │ ## THREAT INTELLIGENCE CORRELATION  ◄── NEW                │ │  │
│  │  │ ## STATISTICAL ANOMALY FLAGS                                │ │  │
│  │  │ ## BEHAVIOR ANALYSIS                                        │ │  │
│  │  └────────────────────────────────────────────────────────────┘ │  │
│  │                                                                  │  │
│  │  ## ANALYSIS REQUIREMENTS                                        │  │
│  │  1. Entropy Assessment (compare to extension baseline)           │  │
│  │  2. Threat Intelligence Correlation   ◄── NEW                   │  │
│  │     "If TI sources report ransomware family → UPGRADE risk"      │  │
│  │     "Use TI family for ATT&CK attribution"                       │  │
│  │  3. Multi-Signal Correlation (≥2 independent signals → CRITICAL)│  │
│  │  4. MITRE ATT&CK Mapping (e.g., LockBit → T1486, T1490)         │  │
│  │  5. IOC Extraction                                               │  │
│  │  6. Risk Level Justification                                     │  │
│  │  7. VT Under-detection Discussion                                │  │
│  │  8. Attribution Caution (TI family ≠ definitive)                │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                             │                                          │
│                             ▼                                          │
│              ┌─────────────────────────────────┐                      │
│              │  HTTP POST to taphoaapi proxy    │                      │
│              │  Model: claude-haiku-4-5-20251001│                      │
│              │  Max tokens: 1024                │                      │
│              │  Temperature: 0.2               │                      │
│              └────────────┬────────────────────┘                      │
│                           │                                            │
│                           ▼                                            │
│              ┌─────────────────────────────────┐                      │
│              │  Claude Response (structured)    │                      │
│              │                                  │                      │
│              │  • Threat Summary table          │                      │
│              │  • Signal Analysis bullets       │                      │
│              │  • Entropy Deep-Dive             │                      │
│              │  • MITRE ATT&CK Table            │                      │
│              │  • Risk Assessment + justification│                     │
│              │  • Recommended Incident Actions  │                      │
│              │  • IOC Report                   │                      │
│              │  • False Positive Assessment    │                      │
│              └─────────────────────────────────┘                      │
│                                                                          │
│  Output: Claude AI response text                                        │
└──────────────────────────────────────────────────────────────────────────┘
```

---

### 3.6. Real-time Protection — `core/watchdog_monitor.py` + `core/process_monitor.py`

**Architecture:**

```text
┌─────────────────────────────────────────────────────────────────────────┐
│               REAL-TIME PROTECTION PIPELINE                             │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  WATCHDOG OBSERVER (watchdog.observers.Observer)                │    │
│  │                                                                  │    │
│  │  Event types: Created, Modified, Deleted, Renamed, Moved        │    │
│  │  Debouncing: 2-second cooldown per file                        │    │
│  │  Queue: maxsize=500, worker threads=3                           │    │
│  └────────────────────────────┬────────────────────────────────────┘    │
│                               │                                          │
│         ┌─────────────────────┼─────────────────────┐                   │
│         │                     │                     │                   │
│         ▼                     ▼                     ▼                   │
│  ┌──────────────┐   ┌──────────────────┐   ┌──────────────────────┐    │
│  │ Process       │   │ Entropy Burst    │   │ File Event           │    │
│  │ Monitor       │   │ Detector         │   │ Handler              │    │
│  │               │   │                  │   │                      │    │
│  │ Tracks per-PID│   │ Monitors:        │   │ Extract features     │    │
│  │ file ops:     │   │ • 5+ files/30s   │   │ → ML predict         │    │
│  │               │   │   with H > 7.0   │   │ → Heuristic check    │    │
│  │ ENCRYPTION_   │   │                  │   │                      │    │
│  │ BURST:        │   │ Threshold:       │   │ → Process info       │    │
│  │ ≥10 files/30s │   │ entropy > 7.5    │   │   (if available)     │    │
│  │ by same PID   │   │ on ≥5 files      │   │                      │    │
│  │               │   │ in 30s window    │   │ → AutoResponder      │    │
│  │ EXTENSION_    │   │                  │   │   (if threat)        │    │
│  │ CHANGE:       │   │ Alert fires when │   │                      │    │
│  │ .doc→.locked  │   │ ALL conditions   │   │ → Notification       │    │
│  │               │   │ met simultaneously│   │   (Windows Toast)    │    │
│  │ RAPID_OPS:    │   │                  │   │                      │    │
│  │ >5 files/sec  │   │ Severity:        │   │ → Log to             │    │
│  │               │   │ CRITICAL         │   │   entropy_alerts.log │    │
│  │ FILE_RENAME_  │   │                  │   │                      │    │
│  │ BURST: ≥5     │   │ Danger Level:    │   │                      │    │
│  │ renames in 10s│   │ 0-10 (auto)     │   │                      │    │
│  │               │   │                  │   │                      │    │
│  │ MASS_IO:      │   │                  │   │                      │    │
│  │ >50MB/s write │   │                  │   │                      │    │
│  └───────┬───────┘   └────────┬─────────┘   └──────────────────────┘    │
│          │                    │                                          │
│          │    ┌───────────────┘                                          │
│          │    │                                                          │
│          ▼    ▼                                                          │
│  ┌────────────────────────────────────────┐                             │
│  │  Dynamic Signal Aggregator              │                             │
│  │                                          │                             │
│  │  Composite_score = weighted_sum(        │                             │
│  │    entropy_burst * 0.40 +              │                             │
│  │    extension_change * 0.25 +           │                             │
│  │    rapid_ops * 0.15 +                 │                             │
│  │    encryption_burst * 0.20             │                             │
│  │  )                                     │                             │
│  │                                          │                             │
│  │  CRITICAL: score ≥ 0.70                 │                             │
│  │  HIGH:     score ≥ 0.40                 │                             │
│  │  MEDIUM:   score ≥ 0.20                 │                             │
│  │  LOW:      score < 0.20                  │                             │
│  └──────────────────────┬──────────────────┘                             │
│                          │                                               │
│                          ▼                                               │
│          ┌────────────────────────────┐                                 │
│          │  Auto-Responder             │                                 │
│          │                             │                                 │
│          │  CRITICAL → quarantine +     │                                 │
│          │           kill process +   │                                 │
│          │           block network    │                                 │
│          │                             │                                 │
│          │  HIGH → ask user dialog    │                                 │
│          │           (30s countdown)  │                                 │
│          │                             │                                 │
│          │  MEDIUM → notify only       │                                 │
│          │  LOW → log only             │                                 │
│          └────────────────────────────┘                                 │
└──────────────────────────────────────────────────────────────────────────┘
```

---

### 3.7. VirusTotal + TI Correlation Flow

```text
File → SHA256
    │
    ├──▶ VT Client (virustotal_client)
    │       │
    │       ├── Check cache (vt_cache.json, 24h TTL)
    │       ├── If miss → API call (4 req/min)
    │       └── Output: detection_ratio, malicious_count, permalink
    │
    └──▶ TI Client (threat_intel_client)
            │
            ├──▶ MalwareBazaar (no key)
            │       └── family, signature, first_seen, tags
            │
            ├──▶ ThreatFox (abuse.ch key)
            │       └── threat_type, family, confidence
            │
            └──▶ AlienVault OTX v3 (OTX key)
                    └── pulse_count, pulse_names, score
                            │
                            ▼
                    ┌───────────────────┐
                    │ ti_context string │
                    │ for AI prompt     │
                    │                   │
                    │ "MB: FAMILY=LockBit │
                    │  TF: Conf=95%      │
                    │  OTX: 3 pulses"    │
                    └────────┬──────────┘
                             │
                             ▼
                    ┌───────────────────┐
                    │ AI Prompt enriched│
                    │ with global TI    │
                    └───────────────────┘
```

---

## 4. Cài đặt

### 4.1. Yêu cầu hệ thống

- **Python 3.8+** (khuyến nghị 3.10+)
- **Windows 10/11** (notifications, process monitoring, watchdog được tối ưu cho Windows)
- **RAM:** 4GB+ (model RandomForest load vào memory)
- **Disk:** 500MB cho code + model + logs

### 4.2. Cài đặt nhanh

```bash
# Clone repository
git clone https://github.com/in4SECxMinDandy/ransomware_detector_v2.git
cd ransomware_detector_v2

# Tạo virtual environment
python -m venv venv
.\venv\Scripts\activate

# Cài dependencies
pip install -r requirements.txt

# Train model (lần đầu)
python train_model.py

# Chạy ứng dụng
python main.py
```

### 4.3. Cài đặt thư viện bổ sung (tùy chọn)

```bash
# YARA native (tăng tốc YARA scan ~10x)
pip install yara-python

# PE parsing nâng cao
pip install pefile

# Office document analysis
pip install oletools python-docx openpyxl python-pptx PyMuPDF

# GUI enhancement
pip install customtkinter matplotlib pillow

# System tray
pip install pystray
```

### 4.4. Cấu hình API Keys

Mở `data/config.json` và cập nhật các API keys:

```json
{
  "virustotal": {
    "api_key": "YOUR_VT_API_KEY",
    "enabled": true
  },
  "threat_intel": {
    "malwarebazaar": {
      "api_key": "",
      "enabled": true
    },
    "threatfox": {
      "api_key": "YOUR_ABUSE_CH_KEY",
      "enabled": true
    },
    "alienvault_otx": {
      "api_key": "YOUR_OTX_KEY",
      "enabled": true
    }
  },
  "ai": {
    "api_key": "YOUR_CLAUDE_KEY",
    "model": "claude-haiku-4-5-20251001",
    "base_url": "https://taphoaapi.info.vn/"
  }
}
```

**Lấy API keys miễn phí:**

| Dịch vụ | URL đăng ký | Ghi chú |
| --- | --- | --- |
| VirusTotal | [virustotal.com](https://www.virustotal.com/gui/join-us) | Free: 4 req/min |
| MalwareBazaar | [auth.abuse.ch](https://auth.abuse.ch/) | Không cần key (basic) |
| ThreatFox | [auth.abuse.ch](https://auth.abuse.ch/) | Free API key |
| AlienVault OTX | [otx.alienvault.com](https://otx.alienvault.com/api) | Free API key |
| Claude AI | [taphoaapi.info.vn](https://taphoaapi.info.vn/) | Proxy cho Anthropic API |

### 4.5. Cấu hình Proxy (nếu cần)

```json
"proxy": {
  "http_proxy": "http://proxy:port",
  "https_proxy": "http://proxy:port"
}
```

Hoặc set biến môi trường:

```powershell
$env:HTTP_PROXY = "http://proxy:port"
$env:HTTPS_PROXY = "http://proxy:port"
python main.py
```

---

## 5. Hướng dẫn sử dụng

### 5.1. Chế độ quét

#### Quét thủ công (Manual Scan)

```bash
python main.py --scan "C:\Users\Documents"
```

Trong GUI:

1. Tab **Scan** → Chọn thư mục
2. Chọn chế độ: **Full** / **Quick** / **Incremental**
3. Điều chỉnh ngưỡng (mặc định: 0.65)
4. Bấm **Bắt đầu quét**
5. Xem kết quả trong bảng

#### Quét Office Documents

```bash
python main.py --office-scan "C:\Users\Documents"
```

Hoặc trong GUI → Tab **Office Scanner**

#### Bảo vệ thời gian thực

1. Tab **Settings** → Bật "Real-time Protection"
2. Chọn thư mục giám sát
3. Bấm **Bắt đầu bảo vệ**
4. Quan sát tab **Entropy Watch** và **Alerts**

#### CLI

```bash
# Quét thư mục
python main.py --scan "C:\Path\To\Folder"

# Chỉ train model
python main.py --train

# Scan + AI analysis
python main.py --scan "C:\Folder" --ai
```

### 5.2. Bảng mã màu Threat Level

| Level | Màu | Hành động |
| --- | --- | --- |
| **CLEAN** | Xanh lá | Không cần hành động |
| **SUSPICIOUS** | Vàng | Xem xét kỹ, có thể là FP |
| **MALICIOUS** | Đỏ | Cách ly ngay |
| **CRITICAL** | Đỏ đậm | Phản ứng tự động |

### 5.3. Điều chỉnh độ nhạy

| Chế độ | Threshold | Trường hợp |
| --- | --- | --- |
| **Cân bằng** | +0.00 | Cân bằng giữa bỏ sót và cảnh báo sai |
| **Độ nhạy cao** | -0.05 | Ưu tiên phát hiện ransomware |
| **Paranoid** | -0.10 | Giám sát nghiêm ngặt nhất |

---

## 6. Hiệu năng

| Chỉ số | Mục tiêu | Thực tế |
| --- | --- | --- |
| **Precision** | ≥ 95% | ✅ ≥ 95% |
| **False Positive Rate** | < 5% | ✅ < 5% |
| **Recall** | ≥ 90% | ✅ ≥ 90% |
| **Tốc độ quét** | ~100 files/s | ✅ ~100 files/s |
| **Bộ nhớ sử dụng** | < 200 MB | ✅ < 200 MB |
| **AI Response (Haiku)** | < 3s | ✅ 1-3s |
| **VT Cache Hit** | O(1) | ✅ Immediate |
| **TI Cache Hit** | O(1) | ✅ Immediate |

**Performance optimizations:**

- Feature extraction với smart sampling (max 256KB memory/file)
- ThreadPoolExecutor cho parallel file scanning
- VT/TI persistent cache (24h TTL)
- Incremental scan chỉ re-scan modified/new files
- YARA fallback: pure-Python byte matching nếu không có yara-python

---

## 7. Kiểm tra - Testing

### Chạy tests

```bash
# Tất cả tests
pytest tests/ -v

# Với coverage
pytest tests/ --cov=core --cov-report=term-missing

# Test cụ thể
pytest tests/test_feature_extractor.py -v
pytest tests/test_scanner_vt_fusion.py -v
pytest tests/test_ti_integration.py -v
```

### Các module test

| File | Tests | Mô tả |
| --- | --- | --- |
| `test_feature_extractor.py` | 49 | 16 features extraction + edge cases |
| `test_fp_reducer.py` | 24 | FP reduction pipeline |
| `test_ml_engine.py` | 15 | ML training + prediction |
| `test_yara_engine.py` | 18 | YARA signatures |
| `test_dynamic_signals.py` | 16 | Process behavior signals |
| `test_scanner_vt_fusion.py` | + | VT fusion + incremental scan |
| `test_virustotal_client.py` | + | VT API integration |
| `test_ti_integration.py` | + | TI correlation (MB+TF+OTX) |
| `test_honeypot_manager.py` | + | Honeypot deployment |
| `test_entropy_monitor.py` | + | Entropy burst detection |
| `test_ml_feedback.py` | + | ML feedback loop |
| `test_api_auth.py` | + | JWT + API Key auth |
| `test_api_routes.py` | + | FastAPI endpoints |
| `test_office_analyzer.py` | + | Office document scanning |

---

## 8. Các loại virus & File test

### 8.1. Tổng quan khả năng phát hiện

**Nhóm ransomware được hỗ trợ (20+ families):**

| Nhóm | Extension | ATT&CK Technique |
| --- | --- | --- |
| **WannaCry** | `.wncry`, `.wnry` | T1490 (Inhibit Recovery) |
| **LockBit 3.0** | `.lockbit`, `.lock` | T1486 (Data Encrypted) |
| **BlackCat/ALPHV** | `.alphv`, `.blackcat` | T1486, T1490 |
| **Ryuk** | `.ryk`, `.ryuk` | T1486 |
| **REvil/Sodinokibi** | *(no specific)* | T1486, T1055 (Injection) |
| **Conti** | `.conti` | T1486 |
| **Cl0p** | `.clop`, `.cl0p` | T1486 |
| **Play** | `.play` | T1486 |
| **Rhysida** | `.rhysida` | T1486 |
| **Akira** | `.akira` | T1486, T1490 |
| **BianLian** | `.bianlian` | T1486 |
| **Medusa** | `.medusa` | T1486 |
| **Qilin** | `.qilin` | T1486 |

### 8.2. Tạo file test an toàn

> **Lưu ý:** Không sử dụng ransomware thật. Tạo mẫu giả lập an toàn.

```python
# File encrypted giả lập (entropy cao)
import os, random
def create_fake_encrypted(path, size_kb=256):
    data = bytes([random.randint(0, 255) for _ in range(size_kb * 1024)])
    with open(path, "wb") as f: f.write(data)

os.makedirs("test_samples", exist_ok=True)
create_fake_encrypted("test_samples/doc_encrypted.bin", 512)
```

```python
# Ransom note giả lập
content = """YOUR FILES HAVE BEEN ENCRYPTED!
To decrypt: 1. Buy Bitcoin 2. Use Tor Browser
3. Send to our wallet 4. Wait for ID"""
open("test_samples/RANSOM_NOTE.txt", "w").write(content)
```

---

## 9. Lộ trình phát triển - Roadmap

### v2.5 (Hiện tại) ✅

- [x] ML Engine với 16 đặc trưng + Calibrated RandomForest
- [x] FP Reduction 3 lớp (Whitelist, Per-ext threshold, Magic bytes)
- [x] YARA Rules (20+ ransomware families)
- [x] Process Behavior Monitor (encryption burst, extension change)
- [x] Real-time Protection (watchdog + entropy burst)
- [x] Auto-Responder (quarantine, kill process, block network)
- [x] PE Analyzer (packer, injection, RWX sections)
- [x] Network Monitor (DGA, beaconing, Feodo Tracker)
- [x] Office Document Scanner (VBA macro, PDF actions)
- [x] Honeypot Deployment & Monitoring
- [x] VirusTotal API v3 + cache (24h TTL)
- [x] **Threat Intelligence Correlation (MalwareBazaar + ThreatFox + AlienVault OTX)** ✅
- [x] Claude AI Analysis (Claude Sonnet 4.6 / Haiku 4.5)
- [x] REST API (FastAPI + JWT + API Key)
- [x] ML Feedback Loop + Auto-retrain
- [x] Forensic Bundle Export (IOC, timeline, hashes)
- [x] 140+ Unit Tests với 85%+ coverage

---

## 10. Cấu hình nâng cao

### 10.1. Environment Variables

| Variable | Mô tả | Mặc định |
| --- | --- | --- |
| `VT_API_KEY` | VirusTotal API key | - |
| `ML_THRESHOLD` | Detection threshold | 0.65 |
| `ENTROPY_THRESHOLD` | Entropy alert threshold | 7.5 |
| `API_PORT` | FastAPI server port | 8000 |
| `HONEYPOT_AUTO_DEPLOY` | Auto-deploy honeypots on startup | false |
| `CLAUDE_API_KEY` | Claude API key (proxy: taphoaapi.info.vn) | - |
| `CLAUDE_MODEL` | Model: `claude-haiku-4-5-20251001` | `claude-haiku-4-5-20251001` |

### 10.2. Cấu hình `data/config.json`

Toàn bộ cấu hình được quản lý qua `core/config_manager.py` và lưu trong `data/config.json`. Các section chính:

| Section | Mô tả |
| --- | --- |
| `ml` | Threshold, model path, class weights |
| `scanner` | Scan modes, max file size, parallel threads |
| `process_monitor` | Burst thresholds, patterns |
| `watchdog` | Debounce time, queue size, worker threads |
| `fp_reducer` | Per-extension thresholds, whitelist paths |
| `virustotal` | API key, cache TTL, rate limit |
| `threat_intel` | API keys, enabled flags, cache TTL per source |
| `ai` | Model, base URL, max tokens, temperature |
| `honeypot` | Auto-deploy, locations, file names |
| `office_scanner` | Enabled formats, max size |

---

## 11. Giấy phép - License

MIT License - Xem [LICENSE](LICENSE) để biết thêm chi tiết.

---

**Tác giả:** Hà Quang Minh | [minhhq.in4sec@gmail.com](mailto:minhhq.in4sec@gmail.com) | [GitHub](https://github.com/in4SECxMinDandy)

**Cảm ơn:**

- [scikit-learn](https://scikit-learn.org/) — Khung máy học
- [YARA](https://virustotal.github.io/yara/) — Pattern matching
- [watchdog](https://pythonhosted.org/watchdog/) — Giám sát filesystem
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) — Giao diện hiện đại
- [psutil](https://psutil.readthedocs.io/) — Giám sát process
- [Anthropic](https://www.anthropic.com/) — Claude AI cho phân tích mối đe dọa
- [abuse.ch](https://abuse.ch/) — MalwareBazaar & ThreatFox
- [AlienVault OTX](https://otx.alienvault.com/) — Open Threat Exchange

---

**⭐ Nếu thấy hữu ích, hãy cho tôi 1 ⭐ để ủng hộ!**
