#!/usr/bin/env python3
"""
train_model.py — v2.1 (SMOTE + Anti-FP Edition)
==================================================
Training pipeline cho Ransomware Detector v2.1.

Nâng cấp v2.1:
  - SMOTE oversampling: xử lý class imbalance với SMOTETomek
  - YARA engine: tích hợp 10 built-in rules
  - Whitelist: load whitelist từ data/whitelist.json khi train
  - Dataset v2: 7 SAFE + 5 ENCRYPTED types (5000 samples)
  - N_FEATURES=16

Chạy:
  pip install -r requirements.txt
  python train_model.py [--smote STRATEGY] [--samples N]

Arguments (optional):
  --smote   STRATEGY   SMOTE strategy: smote_tomek|smote|adasyn|borderline|none
                       Default: smote_tomek
  --samples N          Số samples mỗi class. Default: 2500
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.dataset_generator import generate_synthetic_dataset
from core.ml_engine import CalibratedMalwareDetector, MODEL_PATH, META_PATH
from core.feature_extractor import N_FEATURES, FEATURE_NAMES
from core.yara_engine import get_yara_engine
from core.smote_trainer import get_smote_info, SUPPORTED_STRATEGIES
import json
import numpy as np

# ─── Parse arguments ───
parser = argparse.ArgumentParser(
    description="Ransomware Entropy Detector v2.1 — Training Pipeline"
)
parser.add_argument("--smote",   default="smote_tomek",
                    choices=SUPPORTED_STRATEGIES,
                    help="SMOTE oversampling strategy (default: smote_tomek)")
parser.add_argument("--samples", default=2500, type=int,
                    help="Số samples mỗi class (default: 2500)")
parser.add_argument("--no-smote", action="store_true",
                    help="Tắt SMOTE oversampling")
args = parser.parse_args()

smote_strategy = "none" if args.no_smote else args.smote
n_samples      = args.samples

print("=" * 65)
print("  RANSOMWARE ENTROPY DETECTOR v2.1 — Training Pipeline")
print("  SMOTE + Anti-FP + YARA Edition")
print("=" * 65)

# ── Kiểm tra SMOTE availability ──
smote_info = get_smote_info()
if not smote_info["available"] and smote_strategy != "none":
    print(f"\n  ⚠️  imbalanced-learn không có — bỏ qua SMOTE")
    print(f"  Cài đặt: pip install imbalanced-learn")
    smote_strategy = "none"
else:
    print(f"\n  SMOTE Strategy : {smote_strategy}")

# ── Kiểm tra YARA availability ──
yara_eng = get_yara_engine()
print(f"  YARA Engine    : {yara_eng.get_engine_type()} ({yara_eng.get_rules_count()} rules)")
print(f"  N_FEATURES     : {N_FEATURES}")
print(f"  Samples/class  : {n_samples}")

# ── Step 1: Generate Dataset v2 ──
print(f"\n[Step 1/4] Sinh dataset v2 ({n_samples} SAFE + {n_samples} ENCRYPTED)...")
print("  SAFE   types: text_ascii(25%), pe_valid(20%), compressed_png(15%),")
print("                compressed_zip(15%), media_mp4(10%), office_doc(10%), binary_struct(5%)")
print("  ENCRYPT types: full_aes(35%), intermittent(25%), header_only(15%),")
print("                 disguised_png(15%), disguised_zip(10%)")

X, y = generate_synthetic_dataset(n_safe=n_samples, n_encrypted=n_samples)

print(f"\n  Dataset đã sinh: {len(X)} samples, {X.shape[1]} features")
print(f"  Class distribution: SAFE={np.sum(y==0)}, ENCRYPTED={np.sum(y==1)}")

if X.shape[1] != N_FEATURES:
    print(f"\n  ❌ FEATURE COUNT MISMATCH: {X.shape[1]} != {N_FEATURES}")
    print(f"  → Kiểm tra feature_extractor.py và dataset_generator.py")
    sys.exit(1)

# ── Step 2: Lưu dataset ──
print("\n[Step 2/4] Lưu dataset v2.1...")
import pandas as pd

fn_list   = FEATURE_NAMES[:X.shape[1]]
df        = pd.DataFrame(X, columns=fn_list)
df["label"] = y

data_path = os.path.join(os.path.dirname(__file__), "data", "synthetic_dataset_v2.csv")
os.makedirs(os.path.dirname(data_path), exist_ok=True)
df.to_csv(data_path, index=False)
print(f"  Saved: {data_path} ({len(df)} rows × {len(fn_list)+1} cols)")

# ── Step 3: Train Model ──
print("\n[Step 3/4] Train CalibratedMalwareDetector v2.1...")
print(f"  → n_estimators=300, class_weight={{0:3.0, 1:1.0}}")
print(f"  → SMOTE strategy='{smote_strategy}'")
print(f"  → Calibration: isotonic regression")
print(f"  → Threshold optimizer: Precision ≥ 95%")

engine  = CalibratedMalwareDetector()
metrics = engine.train(X, y, verbose=True, smote_strategy=smote_strategy)

# ── Step 4: Final Report ──
print("\n[Step 4/4] Kết quả Evaluation")
print("=" * 65)
print(f"  Model saved  : {MODEL_PATH}")
print(f"  Metadata     : {META_PATH}")
print()
print("  ── Performance Metrics (test set) ──")
print(f"    Accuracy          : {metrics['accuracy']*100:.2f}%")
print(f"    Precision         : {metrics['precision']*100:.2f}%  (mục tiêu ≥ 95%)")
print(f"    Recall            : {metrics['recall']*100:.2f}%")
print(f"    F1-Score          : {metrics['f1_score']*100:.2f}%")
print(f"    AUC-ROC           : {metrics['auc_roc']*100:.2f}%")
print(f"    False Pos. Rate   : {metrics.get('false_positive_rate', 0)*100:.2f}%  (mục tiêu < 5%)")
print(f"    CV F1 5-fold      : {metrics['cv_mean']*100:.2f}% ± {metrics['cv_std']*100:.2f}%")
print()
print(f"  ── Threshold ──")
print(f"    Optimal threshold : {metrics.get('optimal_threshold', 0.65):.4f}")
print()

# Đánh giá kết quả
precision = metrics['precision']
fpr       = metrics.get('false_positive_rate', 1.0)
if precision >= 0.95 and fpr < 0.05:
    print("  ✅ MỤC TIÊU ĐẠT: Precision ≥ 95% VÀ FPR < 5%")
elif precision >= 0.90:
    print("  ⚠️  Precision ≥ 90% — Chấp nhận được")
else:
    print("  ❌ Precision < 90% — Cần xem lại")

print()
print("  ── Feature Importances (top 10) ──")
fi = metrics.get("feature_importances", {})
for fname, imp in sorted(fi.items(), key=lambda x: x[1], reverse=True)[:10]:
    bar = "█" * int(imp * 50)
    print(f"    {fname:35s}  {imp:.4f}  {bar}")

print()
print("  ── YARA Rules (10 built-in) ──")
for rule_info in yara_eng.get_builtin_rules_info():
    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(
        rule_info["severity"], "⚪"
    )
    print(f"    {sev_icon} [{rule_info['severity']:<8}] {rule_info['name']:<35}  {rule_info['family']}")

print("=" * 65)
print()
print("✓ Training hoàn tất.")
print("✓ Chạy 'python main.py' để khởi động GUI.")
print()
print("  Tính năng v2.1:")
print("  ✓ SMOTE oversampling   — xử lý class imbalance")
print("  ✓ YARA rules           — 10 built-in signature rules")
print("  ✓ PDF export           — Model Analysis Report PDF")
print("  ✓ Whitelist Editor     — GUI quản lý danh sách trắng")
print("  ✓ Anti-FP              — PNG/ZIP/EXE không bị flagged nhầm")
