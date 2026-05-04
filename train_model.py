#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
train_model.py — v3.0 (Real Data Edition)
==========================================
Training pipeline cho Ransomware Detector v3.0.
Sử dụng dữ liệu THẬT thay vì synthetic.

Thay đổi từ v2.1 → v3.0:
  - LOẠI BỎ hoàn toàn dữ liệu synthetic (generate_synthetic_dataset)
  - Dùng dữ liệu thật từ thu thập qua collect_safe_samples.py
    và collect_malware_samples.py
  - Tích hợp external_dataset_builder để extract features từ file thật
  - Vẫn giữ SMOTE, YARA, anti-FP pipeline

Chuẩn bị dữ liệu (chạy trước):
  1. python collect_safe_samples.py        # Thu SAFE PE từ Windows
  2. python collect_malware_samples.py     # Tải malware từ MalwareBazaar

Chạy training:
  python train_model.py \\
    --safe-dir datasets/prepared/external_pe/safe \\
    --malware-dir datasets/prepared/external_pe/encrypted

Arguments:
  --safe-dir    DIR   Thư mục chứa SAFE PE files (required)
  --malware-dir DIR   Thư mục chứa MALWARE PE files (required)
  --smote    STRATEGY SMOTE strategy: smote_tomek|smote|adasyn|borderline|none
                      Default: smote_tomek
  --no-smote          Tắt SMOTE oversampling
  --output-csv PATH   Lưu dataset features ra CSV (tùy chọn)
"""

import sys
import os
import io
import argparse
from pathlib import Path

# Fix Windows terminal encoding (CP1252 -> UTF-8)
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from core.external_dataset_builder import build_external_dataset  # noqa: E402
from core.ml_engine import (  # noqa: E402
    CalibratedMalwareDetector,
    MODEL_PATH,
    META_PATH,
    CLASS_WEIGHT_SAFE,
    CLASS_WEIGHT_ENC,
)
from core.feature_extractor import N_FEATURES, FEATURE_NAMES  # noqa: E402
from core.yara_engine import get_yara_engine  # noqa: E402
from core.smote_trainer import get_smote_info, SUPPORTED_STRATEGIES  # noqa: E402

# ─── Parse arguments ───
parser = argparse.ArgumentParser(
    description="Ransomware Detector v3.0 — Training Pipeline (Real Data)"
)
parser.add_argument(
    "--safe-dir",
    default=str(BASE_DIR / "datasets" / "prepared" / "external_pe" / "safe"),
    help="Thư mục chứa SAFE PE files (default: datasets/prepared/external_pe/safe)",
)
parser.add_argument(
    "--malware-dir",
    default=str(BASE_DIR / "datasets" / "prepared" / "external_pe" / "encrypted"),
    help="Thư mục chứa MALWARE PE files (default: datasets/prepared/external_pe/encrypted)",
)
parser.add_argument(
    "--smote", default="smote_tomek",
    choices=SUPPORTED_STRATEGIES,
    help="SMOTE oversampling strategy (default: smote_tomek)",
)
parser.add_argument(
    "--no-smote", action="store_true",
    help="Tắt SMOTE oversampling",
)
parser.add_argument(
    "--output-csv", default="",
    help="Lưu dataset features ra CSV (tùy chọn, VD: data/real_dataset.csv)",
)
args = parser.parse_args()

smote_strategy = "none" if args.no_smote else args.smote
safe_dir = args.safe_dir
malware_dir = args.malware_dir

print("=" * 65)
print("  RANSOMWARE DETECTOR v3.0 — Training Pipeline (Real Data)")
print("  SMOTE + Anti-FP + YARA Edition")
print("=" * 65)

# ── Kiểm tra thư mục đầu vào ──
safe_path = Path(safe_dir)
malware_path = Path(malware_dir)

safe_count_est = sum(1 for f in safe_path.iterdir() if f.is_file()) if safe_path.exists() else 0
malware_count_est = sum(1 for f in malware_path.iterdir() if f.is_file()) if malware_path.exists() else 0

print(f"\n  Safe dir     : {safe_dir}")
print(f"  Malware dir  : {malware_dir}")
print(f"  Safe files   : ~{safe_count_est} files found")
print(f"  Malware files: ~{malware_count_est} files found")

if safe_count_est == 0:
    print("\n  [ERROR] Không tìm thấy SAFE files!")
    print(f"  Thư mục '{safe_dir}' trống hoặc không tồn tại.")
    print("\n  Chạy trước: python collect_safe_samples.py")
    sys.exit(1)

if malware_count_est == 0:
    print("\n  [ERROR] Không tìm thấy MALWARE files!")
    print(f"  Thư mục '{malware_dir}' trống hoặc không tồn tại.")
    print("\n  Chạy trước: python collect_malware_samples.py")
    sys.exit(1)

# ── Kiểm tra SMOTE availability ──
smote_info = get_smote_info()
if not smote_info["available"] and smote_strategy != "none":
    print("\n  [!] imbalanced-learn not available -- skipping SMOTE")
    print("  Install: pip install imbalanced-learn")
    smote_strategy = "none"
else:
    print(f"\n  SMOTE Strategy : {smote_strategy}")

# ── Kiểm tra YARA availability ──
yara_eng = get_yara_engine()
print(f"  YARA Engine    : {yara_eng.get_engine_type()} ({yara_eng.get_rules_count()} rules)")
print(f"  N_FEATURES     : {N_FEATURES}")

# ── Step 1: Extract features từ dữ liệu thật ──
output_csv = args.output_csv or str(BASE_DIR / "data" / "real_dataset.csv")
print(f"\n[Step 1/4] Extracting features từ dữ liệu thật...")
print(f"  SAFE dir     : {safe_dir}")
print(f"  MALWARE dir  : {malware_dir}")
print(f"  Output CSV   : {output_csv}")
print("  (Quá trình này có thể mất vài phút tùy số lượng file...)")

dataset = build_external_dataset(
    safe_dir=safe_dir,
    encrypted_dir=malware_dir,
    output_csv=output_csv,
    recursive=True,
)

X: np.ndarray = dataset["X"]
y: np.ndarray = dataset["y"]

print(f"\n  Safe stats   : {dataset['safe_stats']}")
print(f"  Malware stats: {dataset['encrypted_stats']}")

if len(X) == 0:
    print("\n  [ERROR] Dataset rỗng — không có sample hợp lệ nào!")
    print("  Kiểm tra lại format file trong safe_dir và malware_dir.")
    print("  File phải là PE (EXE/DLL/SYS) hợp lệ.")
    sys.exit(1)

safe_n = int(np.sum(y == 0))
malware_n = int(np.sum(y == 1))

print(f"\n  Dataset thật : {len(X)} samples, {X.shape[1]} features")
print(f"  SAFE         : {safe_n} samples")
print(f"  MALWARE      : {malware_n} samples")
print(f"  Skipped      : {dataset['skipped_total']} ({dataset['skipped_ratio']*100:.1f}%)")

if X.shape[1] != N_FEATURES:
    print(f"\n  [ERROR] FEATURE COUNT MISMATCH: {X.shape[1]} != {N_FEATURES}")
    print("  Kiểm tra feature_extractor.py")
    sys.exit(1)

if safe_n < 1 or malware_n < 1:
    print(f"\n  [ERROR] Không có sample nào: SAFE={safe_n}, MALWARE={malware_n}")
    print("  Cần ít nhất 1 sample mỗi class để train.")
    print("  Thu thập thêm dữ liệu:")
    print("    python collect_safe_samples.py")
    print("    python collect_malware_samples.py")
    sys.exit(1)

# Cảnh báo nếu mất cân bằng quá cao
ratio = max(safe_n, malware_n) / max(min(safe_n, malware_n), 1)
if ratio > 10:
    print(f"\n  [WARN] Class imbalance cao: {ratio:.1f}:1")
    if smote_strategy == "none":
        print("  Khuyến nghị: dùng --smote smote_tomek để cân bằng")

# ── Step 2: Lưu dataset ──
print(f"\n[Step 2/4] Dataset features đã lưu: {output_csv}")
print(f"  ({len(X)} rows × {X.shape[1]+1} cols)")

# ── Step 3: Train Model ──
print("\n[Step 3/4] Train CalibratedMalwareDetector v3.0...")
print(f"  -> n_estimators=300, class_weight={{0:{CLASS_WEIGHT_SAFE}, 1:{CLASS_WEIGHT_ENC}}} (cost-aware FN-averse)")
print(f"  -> SMOTE strategy='{smote_strategy}' (training fold only -- no leakage)")
print("  -> Calibration: isotonic regression")
print("  -> Threshold optimizer: Precision >= 95%")
print("  -> Dữ liệu: THẬT (không phải synthetic)")

engine = CalibratedMalwareDetector()
metrics = engine.train(X, y, verbose=True, smote_strategy=smote_strategy)

# ── Step 4: Final Report ──
print("\n[Step 4/4] Evaluation Results")
print("=" * 65)
print(f"  Model saved  : {MODEL_PATH}")
print(f"  Metadata     : {META_PATH}")
print()
print("  -- Performance Metrics (test set) --")
print(f"    Accuracy          : {metrics['accuracy']*100:.2f}%")
print(f"    Precision         : {metrics['precision']*100:.2f}%  (target >= 95%)")
print(f"    Recall            : {metrics['recall']*100:.2f}%")
print(f"    F1-Score          : {metrics['f1_score']*100:.2f}%")
print(f"    AUC-ROC           : {metrics['auc_roc']*100:.2f}%")
print(f"    False Pos. Rate   : {metrics.get('false_positive_rate', 0)*100:.2f}%  (target < 5%)")
print(f"    CV F1 5-fold      : {metrics['cv_mean']*100:.2f}% +/- {metrics['cv_std']*100:.2f}%")
print()
print("  -- Threshold --")
print(f"    Optimal threshold : {metrics.get('optimal_threshold', 0.65):.4f}")
print()

precision = metrics['precision']
fpr = metrics.get('false_positive_rate', 1.0)
if precision >= 0.95 and fpr < 0.05:
    print("  [OK] TARGET MET: Precision >= 95% AND FPR < 5%")
elif precision >= 0.90:
    print("  [!] Precision >= 90% -- Acceptable")
else:
    print("  [FAIL] Precision < 90% -- Cần thêm dữ liệu chất lượng cao hơn")
    print("  Gợi ý: Thu thập thêm malware samples, kiểm tra chất lượng labels")

print()
print("  -- Feature Importances (top 10) --")
fi = metrics.get("feature_importances", {})
for fname, imp in sorted(fi.items(), key=lambda x: x[1], reverse=True)[:10]:
    bar = "#" * int(imp * 50)
    print(f"    {fname:35s}  {imp:.4f}  {bar}")

print()
print("  -- YARA Rules --")
for rule_info in yara_eng.get_builtin_rules_info():
    sev_icon = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[*]"}.get(
        rule_info["severity"], "[.]"
    )
    print(f"    {sev_icon} [{rule_info['severity']:<8}] {rule_info['name']:<35}  {rule_info['family']}")

print("=" * 65)
print()
print("[OK] Training hoàn tất (dữ liệu THẬT).")
print("[OK] Run 'python main.py' to launch GUI.")
print()
print(f"  Dataset: {len(X)} real samples (SAFE={safe_n}, MALWARE={malware_n})")
print(f"  CSV:     {output_csv}")
