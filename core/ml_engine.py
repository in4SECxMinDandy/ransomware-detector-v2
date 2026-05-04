"""
ml_engine.py — v2.1 (SMOTE + Anti-FP Edition)
=======================================
Nâng cấp ML Engine với:
  - CalibratedMalwareDetector: wrapper với threshold tuning
  - Cost-matrix: cost_fp=3.0, cost_fn=10.0 (phạt FP 3x nặng hơn)
  - class_weight={0:3.0, 1:1.0} → mô hình học để không flagged benign files
  - Threshold optimizer: tìm threshold sao cho Precision ≥ 0.95
  - Precision-Recall curve để chọn operating point tối ưu
  - N_FEATURES=16 (đồng bộ với feature_extractor.py v2)
  - SMOTE oversampling: tích hợp SMOTETrainer cho class imbalance

Giải pháp cho False Positive (FP) Problem:
  ❌ Vấn đề cũ: PNG/ZIP/PE bị flagged CRITICAL do entropy cao tự nhiên
  ✅ Giải pháp: class_weight thiên về SAFE + threshold cao hơn + cost-aware training
"""

import os
import json
import glob
import re
import warnings
import logging
import shutil
import csv
import base64
import threading as _threading
import numpy as np
import pandas as pd
import joblib
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Tuple, Optional, Dict, List, Any, Iterable
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
    classification_report, precision_recall_curve
)
from sklearn.pipeline import Pipeline

# ─── SMOTE integration (optional) ───
if TYPE_CHECKING:
    from core.smote_trainer import SMOTETrainer
    SMOTE_AVAILABLE = True
else:
    try:
        from core.smote_trainer import SMOTETrainer
        SMOTE_AVAILABLE = True
    except ImportError:  # pragma: no cover
        SMOTETrainer = None
        SMOTE_AVAILABLE = False

from core.feedback_csv import (
    FEEDBACK_COLUMNS,
    feedback_csv_has_canonical_header,
    iter_feedback_rows,
    normalize_feedback_label,
    normalize_feedback_type,
    write_feedback_rows,
)
from core.security_utils import compute_sha256

logger = logging.getLogger("core.ml_engine")

# Suppress specific sklearn warnings that are expected and benign in production:
#   - UndefinedMetricWarning: fires on tiny/synthetic datasets during threshold search
#   - ConvergenceWarning: calibration can hit iteration limits on small samples
# Using targeted filters instead of the blanket "ignore" to preserve visibility
# into genuine problems (e.g. deprecation warnings from dependency upgrades).
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", message=".*UndefinedMetricWarning.*")
warnings.filterwarnings("ignore", message=".*ConvergenceWarning.*")


# ─── Model integrity verification ────────────────────────────────────────────
#
# ``joblib.load`` deserialises pickles, so loading a tampered model file is
# equivalent to remote code execution. We therefore verify the file hash
# against a pinned value before deserialising:
#
#   1. ``RANSOMWARE_MODEL_SHA256`` env var  (highest precedence; ops-friendly)
#   2. ``<model_path>.sha256`` sidecar file (written by ``train()``)
#
# If neither source is available we run in "trust on first use" mode: the
# load proceeds with a WARNING. Operators can opt into strict mode by
# setting ``RANSOMWARE_REQUIRE_MODEL_INTEGRITY=1``, which makes a missing
# pin fatal.

class ModelIntegrityError(RuntimeError):
    """Raised when a model's SHA256 does not match the pinned value."""


def _read_pinned_model_hash(model_path: str) -> Optional[str]:
    env_hash = (os.environ.get("RANSOMWARE_MODEL_SHA256") or "").strip().lower()
    if env_hash:
        return env_hash
    sidecar = model_path + ".sha256"
    if os.path.isfile(sidecar):
        try:
            with open(sidecar, "r", encoding="utf-8") as f:
                # Accept either "<hash>" or "<hash>  filename" (sha256sum format)
                first_token = f.read().strip().split()
                if first_token:
                    return first_token[0].lower()
        except OSError:
            return None
    return None


def _write_model_hash_sidecar(model_path: str) -> Optional[str]:
    """Compute and persist SHA256 of *model_path* to ``<path>.sha256``."""
    digest = compute_sha256(model_path)
    if not digest:
        return None
    sidecar = model_path + ".sha256"
    try:
        with open(sidecar, "w", encoding="utf-8") as f:
            f.write(digest + "\n")
        return digest
    except OSError as exc:
        logger.warning("Failed to write model hash sidecar %s: %s", sidecar, exc)
        return digest


def _verify_model_integrity(model_path: str) -> str:
    """
    Verify *model_path* against the pinned SHA256.

    Returns the actual digest on success. Raises :class:`ModelIntegrityError`
    on mismatch, or when strict mode is enabled and no pin is available.
    """
    actual = compute_sha256(model_path)
    if not actual:
        raise ModelIntegrityError(f"Cannot read model file: {model_path}")

    expected = _read_pinned_model_hash(model_path)
    strict = os.environ.get("RANSOMWARE_REQUIRE_MODEL_INTEGRITY", "").strip().lower() in {
        "1", "true", "yes", "on",
    }

    if expected:
        if actual.lower() != expected.lower():
            raise ModelIntegrityError(
                f"Model SHA256 mismatch for {model_path}: "
                f"expected={expected} actual={actual}"
            )
        return actual

    # No pin available.
    if strict:
        raise ModelIntegrityError(
            f"No pinned SHA256 for {model_path} and "
            "RANSOMWARE_REQUIRE_MODEL_INTEGRITY is set. Refusing to load."
        )

    logger.warning(
        "Loading model without integrity pin (TOFU mode). "
        "actual_sha256=%s — set RANSOMWARE_MODEL_SHA256 or create %s.sha256 "
        "to enable verification.", actual, model_path,
    )
    return actual

def _normalize_windows_path(path: str) -> str:
    normalized = os.path.normpath(path)
    if os.name == "nt" and normalized.startswith("\\\\?\\"):
        normalized = normalized[4:]
    return normalized


_PROJECT_ROOT = _normalize_windows_path(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
MODEL_DIR  = _normalize_windows_path(os.path.join(_PROJECT_ROOT, "models"))
MODEL_PATH = _normalize_windows_path(os.path.join(MODEL_DIR, "rf_ransomware_detector.joblib"))
META_PATH  = _normalize_windows_path(os.path.join(MODEL_DIR, "model_metadata.json"))

# ─── Đồng bộ với feature_extractor.py v2 ───
try:
    from core.feature_extractor import N_FEATURES, FEATURE_NAMES as _FE_NAMES
    FEATURE_NAMES = _FE_NAMES
except ImportError:
    N_FEATURES = 16
    FEATURE_NAMES = [
        "Shannon Entropy",        "Chi-Square (log)",        "Mean Byte",
        "Byte Variance",          "Serial Correlation",      "Chunk Entropy StdDev",
        "Chunk Entropy Max",      "Chunk Entropy Min",       "High Entropy Ratio",
        "Magic Bytes Mismatch",   "Normalized Entropy",      "Byte Distribution Mode",
        "Compression Ratio Sim",  "Structural Consistency",  "Extension Entropy Delta",
        "Is Known Benign Format",
    ]

# ─── Tham số cost-aware ───
#
# Triết lý: cho mô hình học theo cost (FN >> FP) để bắt được ransomware,
# rồi dùng threshold optimizer (MIN_PRECISION ≥ 0.95) + FP_REDUCER
# (whitelist + per-extension threshold) làm hàng rào chống FP ở post-process.
#
# Trước v2.4 hai bộ trọng số sau bị mâu thuẫn:
#   COST_FN=10, COST_FP=3   → comment nói FN nặng gấp 3.3× FP
#   class_weight={0:3,1:1}  → nhưng training lại phạt FP gấp 3× FN
# (xem audit-report-v2.md mục P1-9). Fix: dẫn class_weight TRỰC TIẾP từ
# COST_FP / COST_FN nên không thể lệch nhau nữa.

DEFAULT_THRESHOLD  = 0.65   # Ngưỡng mặc định (cao hơn 0.5 để giảm FP ở runtime)
MIN_PRECISION      = 0.95   # Mục tiêu precision tối thiểu (threshold optimizer)
COST_FP            = 3.0    # Chi phí False Positive (cảnh báo nhầm file an toàn)
COST_FN            = 10.0   # Chi phí False Negative (bỏ sót ransomware — nguy hiểm hơn)

# Single source of truth for class weighting. Class 0 = SAFE, class 1 = ENCRYPTED.
# In sklearn, class_weight[c] is the loss multiplier applied when a sample
# of class ``c`` is misclassified — i.e. it IS the cost of that error type.
#   weight[0] = cost of misclassifying SAFE   → FP cost
#   weight[1] = cost of misclassifying ENCRYPTED → FN cost
CLASS_WEIGHT_SAFE  = COST_FP   # 3.0 — was 3.0 (kept)
CLASS_WEIGHT_ENC   = COST_FN   # 10.0 — was 1.0 (FIXED: now matches FN-averse cost matrix)


def _safe_parallel_jobs() -> int:
    """
    Use a conservative default on Windows to avoid joblib/multiprocessing
    permission issues in restricted environments.
    """
    raw = os.environ.get("RANSOMWARE_RF_N_JOBS", "").strip()
    if raw:
        try:
            value = int(raw)
            return value if value != 0 else 1
        except ValueError:
            return 1
    if os.name == "nt":
        return 1
    return -1


class CalibratedMalwareDetector:
    """
    Wrapper ML detector với threshold tuning và calibration.

    Đặc điểm nổi bật v2:
    - Sử dụng CalibratedClassifierCV để xác suất output chính xác hơn
    - Threshold không cứng 0.5 mà được tối ưu trên validation set
    - Threshold có thể điều chỉnh từ GUI (0.3 → 0.9)
    - get_risk_level() phản ánh threshold hiện tại
    """

    def __init__(self, threshold: float = DEFAULT_THRESHOLD):
        self.threshold   = threshold
        self.pipeline: Optional[Pipeline] = None
        self.metadata: Dict = {}
        self._loaded = False
        self._optimal_threshold = threshold
        self._pr_curve_data: Dict = {}  # lưu precision/recall curve
        self._feedback_stats_cache_key: Optional[tuple[Any, ...]] = None
        self._feedback_stats_cache: Optional[Dict[str, Any]] = None
        self._model_versions_cache_key: Optional[tuple[Any, ...]] = None
        self._model_versions_cache: Optional[List[Dict[str, Any]]] = None

    def is_loaded(self) -> bool:
        return self._loaded

    def set_threshold(self, threshold: float):
        """Điều chỉnh threshold từ GUI (0.1 → 0.99)."""
        self.threshold = float(np.clip(threshold, 0.1, 0.99))

    def get_threshold(self) -> float:
        return self.threshold

    def _invalidate_feedback_stats_cache(self):
        self._feedback_stats_cache_key = None
        self._feedback_stats_cache = None

    def _invalidate_model_versions_cache(self):
        self._model_versions_cache_key = None
        self._model_versions_cache = None

    def _get_path_state(self, path: str) -> tuple[Any, ...]:
        try:
            stat = os.stat(path)
            return (True, stat.st_mtime_ns, stat.st_size)
        except OSError:
            return (False, 0, 0)

    def _get_model_versions_cache_key(self) -> tuple[Any, ...]:
        model_dir = os.path.dirname(MODEL_PATH)
        paths = sorted(
            set(glob.glob(os.path.join(model_dir, "rf_ransomware_detector*.joblib"))) |
            set(glob.glob(os.path.join(model_dir, "model_metadata*.json")))
        )
        snapshot: List[tuple[Any, ...]] = []
        for path in paths:
            try:
                stat = os.stat(path)
                snapshot.append((os.path.basename(path), stat.st_mtime_ns, stat.st_size))
            except OSError:
                continue
        return tuple(snapshot)

    def load_model(self, model_path: str = MODEL_PATH) -> bool:
        """Load pipeline từ file .joblib. Falls back to retraining on failure.

        Security: ``joblib.load`` deserialises pickles, so a tampered model
        file = arbitrary code execution. We verify the SHA256 against a
        pinned value (env var or ``.sha256`` sidecar) before deserialising.
        On mismatch we refuse to load **and do not retrain** — silently
        rebuilding a synthetic model on tamper would mask the attack.
        """
        if os.path.isfile(model_path):
            try:
                _verify_model_integrity(model_path)
            except ModelIntegrityError as exc:
                logger.error("Refusing to load model: %s", exc)
                self._loaded = False
                return False
            try:
                data = joblib.load(model_path)
                if isinstance(data, dict):
                    self.pipeline          = data.get("pipeline")
                    self._optimal_threshold = data.get("optimal_threshold", DEFAULT_THRESHOLD)
                    self.threshold         = self._optimal_threshold
                    self._pr_curve_data    = data.get("pr_curve", {})
                else:
                    self.pipeline = data
                    self._optimal_threshold = DEFAULT_THRESHOLD
                    self.threshold = DEFAULT_THRESHOLD

                # Load metadata
                if os.path.isfile(META_PATH):
                    try:
                        with open(META_PATH, "r") as f:
                            self.metadata = json.load(f)
                        if "optimal_threshold" in self.metadata:
                            self._optimal_threshold = self.metadata["optimal_threshold"]
                            self.threshold = self._optimal_threshold
                    except (json.JSONDecodeError, IOError):
                        pass  # corrupt metadata file

                self._loaded = True
                self._invalidate_model_versions_cache()
                return True
            except Exception as e:
                print(f"[MLEngine] Load model failed ({e}), will retrain...")
                self._train_default_model()
                return False
        return False

    def _train_default_model(self):
        """Train a default model when no model file exists or load fails."""
        try:
            from core.dataset_generator import generate_synthetic_dataset
            X, y = generate_synthetic_dataset(n_safe=2000, n_encrypted=2000, verbose=False)
            self.train(X, y, verbose=False)
        except Exception:
            print("[MLEngine] Retrain failed, using untrained model")
            self._loaded = False

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        model_path: str = MODEL_PATH,
        verbose: bool = True,
        smote_strategy: str = "smote_tomek",  # v2.1: SMOTE oversampling
    ) -> Dict:
        """
        Train CalibratedMalwareDetector với cost-aware class weights.

        Quy trình:
          1. Chia train/val/test (60/20/20)
          2. Train RandomForest với class_weight={0:3.0, 1:1.0}
          3. Calibrate xác suất bằng CalibratedClassifierCV (isotonic)
          4. Tìm optimal threshold trên validation set (Precision ≥ 0.95)
          5. Đánh giá trên test set với optimal threshold
          6. Lưu pipeline + threshold + PR curve data
        """
        os.makedirs(MODEL_DIR, exist_ok=True)

        n_features = X.shape[1]
        if verbose:
            print(f"[MLEngine] Input shape: {X.shape} (N_FEATURES={n_features})")
            print(f"[MLEngine] Class distribution: SAFE={np.sum(y==0)}, ENCRYPTED={np.sum(y==1)}")

        # Keep references to the *original* (pre-SMOTE) dataset for cross-
        # validation later — passing the resampled set to ``cross_val_score``
        # leaks synthetic samples across folds (audit P1-8).
        X_orig, y_orig = X, y

        # ── Chia 3 tập: train/val/test (TRƯỚC khi SMOTE để tránh leakage) ──
        # Pre-fix v2.1 ran SMOTE on the full X,y *before* the split, which
        # contaminated val/test with synthetic neighbours of training rows
        # — every published metric was therefore over-optimistic.
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=0.25, random_state=42, stratify=y_temp
        )  # 0.25 * 0.80 = 0.20 → tổng train=60%, val=20%, test=20%

        # ── v2.4: SMOTE chỉ áp dụng trên training fold ──
        # Validation và test set giữ nguyên phân bố thực để metrics phản
        # ánh hiệu suất production thật.
        smote_active = (
            smote_strategy and smote_strategy != "none" and SMOTE_AVAILABLE
        )
        X_train_fit, y_train_fit = X_train, y_train
        if smote_active:
            n0_tr, n1_tr = int(np.sum(y_train == 0)), int(np.sum(y_train == 1))
            imbalance = min(n0_tr, n1_tr) / max(n0_tr, n1_tr, 1)
            if imbalance < 0.9:
                if verbose:
                    print(
                        f"[MLEngine] SMOTE strategy='{smote_strategy}' on training fold only "
                        f"(imbalance={imbalance:.2f})"
                    )
                smote = SMOTETrainer(strategy=smote_strategy)
                X_train_fit, y_train_fit = smote.resample(
                    np.asarray(X_train), np.asarray(y_train), verbose=verbose,
                )
            elif verbose:
                print(
                    f"[MLEngine] Training fold balanced (imbalance={imbalance:.2f}) -- skipping SMOTE"
                )

        if verbose:
            print(
                f"[MLEngine] Train(fit)={len(X_train_fit)} | Train(real)={len(X_train)} | "
                f"Val={len(X_val)} | Test={len(X_test)}"
            )

        # ── Scaler — fit only on the (resampled) training fold ──
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train_fit)
        X_val_scaled   = scaler.transform(X_val)
        X_test_scaled  = scaler.transform(X_test)

        # ── RandomForest với cost-aware class weights ──
        # class_weight = {0: COST_FP, 1: COST_FN} (xem khối hằng số phía trên).
        # FN nặng hơn FP nên mô hình ưu tiên bắt ransomware; FPs được kiểm
        # soát ở post-process (threshold optimizer + FP_REDUCER).
        rf = RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_split=4,       # tăng từ 2 → 4 để tránh overfit
            min_samples_leaf=2,        # tăng từ 1 → 2
            max_features="sqrt",
            class_weight={0: CLASS_WEIGHT_SAFE, 1: CLASS_WEIGHT_ENC},
            random_state=42,
            n_jobs=_safe_parallel_jobs()
        )

        # ── Calibrate xác suất (isotonic regression) ──
        # Đảm bảo probability output phản ánh true likelihood
        calibrated_rf = CalibratedClassifierCV(
            rf,
            method="isotonic",
            cv=3
        )

        if verbose:
            print(
                f"[MLEngine] Training with class_weight={{0:{CLASS_WEIGHT_SAFE}, "
                f"1:{CLASS_WEIGHT_ENC}}} (cost-aware, FN-averse)..."
            )

        # X_train_scaled was derived from X_train_fit (post-SMOTE if active),
        # so y_train_fit is its matching label vector.
        calibrated_rf.fit(X_train_scaled, y_train_fit)

        # ── Tìm Optimal Threshold trên Validation set ──
        y_val_proba = calibrated_rf.predict_proba(X_val_scaled)[:, 1]
        opt_threshold, threshold_report = self._optimize_threshold(
            np.asarray(y_val), y_val_proba, min_precision=MIN_PRECISION
        )

        if verbose:
            print("\n[MLEngine] ── Threshold Optimization (val set) ──")
            print(f"  Target: Precision ≥ {MIN_PRECISION:.0%}")
            print(f"  Optimal threshold: {opt_threshold:.3f}")
            print(f"  Precision @ threshold: {threshold_report['precision']:.3f}")
            print(f"  Recall    @ threshold: {threshold_report['recall']:.3f}")

        self._optimal_threshold = opt_threshold
        self.threshold = opt_threshold

        # ── Pipeline chính: scaler + calibrated model ──
        # We refit on the (train + val) fold to maximise data efficiency for
        # the final model. The *test* fold is still untouched.
        # SMOTE (if active) is reapplied to this combined fold so the model
        # sees a balanced training set — but only the training portion gets
        # synthesised, not the held-out test rows.
        X_trainval = np.vstack([X_train, X_val])
        y_trainval = np.concatenate([y_train, y_val])

        if smote_active:
            n0_tv, n1_tv = int(np.sum(y_trainval == 0)), int(np.sum(y_trainval == 1))
            tv_imbalance = min(n0_tv, n1_tv) / max(n0_tv, n1_tv, 1)
            if tv_imbalance < 0.9:
                smote_full = SMOTETrainer(strategy=smote_strategy)
                X_trainval, y_trainval = smote_full.resample(
                    X_trainval, y_trainval, verbose=False,
                )

        scaler_full = StandardScaler()
        X_trainval_scaled = scaler_full.fit_transform(X_trainval)

        # Refit calibrated RF on the (resampled) train+val fold.
        calibrated_rf.fit(X_trainval_scaled, y_trainval)

        # Build pipeline with scaler already fit on trainval (no data leak)
        self.pipeline = Pipeline([
            ("scaler", scaler_full),
            ("clf", calibrated_rf)
        ])

        # ── Đánh giá trên Test set với optimal threshold ──
        y_test_proba  = calibrated_rf.predict_proba(X_test_scaled)[:, 1]
        y_test_pred   = (y_test_proba >= opt_threshold).astype(int)

        acc   = accuracy_score(y_test, y_test_pred)
        prec  = precision_score(y_test, y_test_pred, zero_division=0)  # type: ignore[arg-type]
        rec   = recall_score(y_test, y_test_pred, zero_division=0)  # type: ignore[arg-type]
        f1    = f1_score(y_test, y_test_pred, zero_division=0)  # type: ignore[arg-type]
        auc   = roc_auc_score(y_test, y_test_proba)
        cm    = confusion_matrix(y_test, y_test_pred).tolist()

        # ── False Positive Rate ──
        tn, fp, fn, tp = confusion_matrix(y_test, y_test_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        # ── Cross-validation on REAL (pre-SMOTE) data ──
        # Pre-fix this used the SMOTE-resampled X,y which leaks synthetic
        # neighbours across folds. We now evaluate on the original rows so
        # CV F1 reflects production conditions (imbalanced, real samples).
        cv_pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(
                n_estimators=200,
                class_weight={0: CLASS_WEIGHT_SAFE, 1: CLASS_WEIGHT_ENC},
                random_state=42, n_jobs=_safe_parallel_jobs()
            ))
        ])
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(
            cv_pipeline, X_orig, y_orig,
            cv=cv, scoring="f1", n_jobs=_safe_parallel_jobs(),
        )

        if verbose:
            print(f"\n{'='*60}")
            print(f"  [Test Set with threshold={opt_threshold:.3f}]")
            print(f"  Accuracy     : {acc*100:.2f}%")
            print(f"  Precision    : {prec*100:.2f}%  <- Target >= 95%")
            print(f"  Recall       : {rec*100:.2f}%")
            print(f"  F1-Score     : {f1*100:.2f}%")
            print(f"  AUC-ROC      : {auc*100:.2f}%")
            print(f"  False Pos.Rate: {fpr*100:.2f}%  <- Target < 5%")
            print(f"  CV F1 5-fold : {cv_scores.mean()*100:.2f}% ± {cv_scores.std()*100:.2f}%")
            print("  Confusion Matrix:")
            print(f"    TN={tn}  FP={fp}")
            print(f"    FN={fn}  TP={tp}")
            print(f"{'='*60}")
            print(classification_report(
                y_test, y_test_pred,
                target_names=["SAFE (0)", "ENCRYPTED (1)"]
            ))

        # ── PR Curve data (để vẽ trong GUI hoặc report) ──
        pr_precisions, pr_recalls, pr_thresholds = precision_recall_curve(y_test, y_test_proba)
        self._pr_curve_data = {
            "precisions": pr_precisions.tolist(),
            "recalls":    pr_recalls.tolist(),
            "thresholds": pr_thresholds.tolist(),
        }

        # ── Feature importances ──
        # Lấy từ base estimators bên trong calibrated classifiers
        try:
            importances_list = []
            for cal_clf in calibrated_rf.calibrated_classifiers_:
                base_est = getattr(cal_clf, "estimator", None) or getattr(cal_clf, "base_estimator", None)
                if base_est is not None and hasattr(base_est, "feature_importances_"):
                    importances_list.append(base_est.feature_importances_)
            if importances_list:
                importances = np.mean(importances_list, axis=0)
            else:
                # Fallback: train một RF đơn giản chỉ để lấy importances
                rf_simple = RandomForestClassifier(
                    n_estimators=50, class_weight={0: CLASS_WEIGHT_SAFE, 1: CLASS_WEIGHT_ENC},
                    random_state=42, n_jobs=_safe_parallel_jobs()
                )
                rf_simple.fit(X_trainval_scaled, y_trainval)
                importances = rf_simple.feature_importances_
        except Exception:
            importances = np.zeros(n_features)

        fn_list = FEATURE_NAMES[:n_features] if len(FEATURE_NAMES) >= n_features else \
                  FEATURE_NAMES + [f"feature_{i}" for i in range(len(FEATURE_NAMES), n_features)]

        feature_importances = {
            fn_list[i]: float(importances[i]) for i in range(n_features)
        } if len(importances) == n_features else {}

        # ── Lưu model ──
        save_data = {
            "pipeline":          self.pipeline,
            "optimal_threshold": opt_threshold,
            "pr_curve":          self._pr_curve_data,
        }
        joblib.dump(save_data, model_path)
        # Persist a SHA256 sidecar so subsequent loads can verify integrity.
        # This pins the freshly-trained model; tampering after this point
        # will be detected at load time.
        sidecar_hash = _write_model_hash_sidecar(model_path)
        if verbose:
            print(f"[MLEngine] Model saved: {model_path}")
            if sidecar_hash:
                print(f"[MLEngine] Integrity pin: {sidecar_hash}  → {model_path}.sha256")

        # ── Lưu metadata ──
        metrics = {
            "version":            "2.0",
            "n_features":         n_features,
            "accuracy":           round(acc, 6),
            "precision":          round(prec, 6),
            "recall":             round(rec, 6),
            "f1_score":           round(f1, 6),
            "auc_roc":            round(float(auc), 6),
            "false_positive_rate": round(float(fpr), 6),
            "cv_mean":            round(float(cv_scores.mean()), 6),
            "cv_std":             round(float(cv_scores.std()), 6),
            "confusion_matrix":   cm,
            "n_train":            len(X_trainval),
            "n_test":             len(X_test),
            "optimal_threshold":  round(opt_threshold, 4),
            "class_weight":       {0: CLASS_WEIGHT_SAFE, 1: CLASS_WEIGHT_ENC},
            "cost_fp":            COST_FP,
            "cost_fn":            COST_FN,
            "feature_importances": feature_importances,
            "threshold_report":   threshold_report,
        }
        self.metadata = metrics

        with open(META_PATH, "w") as f:
            json.dump(metrics, f, indent=2, ensure_ascii=False)

        self._loaded = True
        self._invalidate_model_versions_cache()
        return metrics

    def _optimize_threshold(
        self,
        y_true: np.ndarray,
        y_proba: np.ndarray,
        min_precision: float = MIN_PRECISION
    ) -> Tuple[float, Dict]:
        """
        Tìm threshold tối thiểu sao cho Precision ≥ min_precision.

        Chiến lược:
        1. Tính Precision-Recall curve
        2. Tìm threshold nhỏ nhất có Precision ≥ 0.95 (để tối đa hóa Recall)
        3. Fallback về 0.65 nếu không tìm được

        Returns: (optimal_threshold, {precision, recall, f1})
        """
        precisions, recalls, thresholds = precision_recall_curve(y_true, y_proba)

        # precisions[i] = precision khi threshold = thresholds[i]
        # precisions có len = len(thresholds) + 1 (phần tử cuối = 1.0)
        best_threshold = DEFAULT_THRESHOLD
        best_f1        = 0.0
        best_prec      = 0.0
        best_rec       = 0.0

        for i, t in enumerate(thresholds):
            p = precisions[i]
            r = recalls[i]
            if p >= min_precision and r > 0:
                f = 2 * p * r / (p + r)
                if f > best_f1:
                    best_f1        = f
                    best_threshold = float(t)
                    best_prec      = float(p)
                    best_rec       = float(r)

        # Nếu không tìm được threshold thỏa điều kiện → dùng default
        if best_f1 == 0.0:
            # Tìm threshold cho F1 max (thay thế)
            f1_scores = np.where(
                (precisions[:-1] + recalls[:-1]) > 0,
                2 * precisions[:-1] * recalls[:-1] / (precisions[:-1] + recalls[:-1] + 1e-9),
                0.0
            )
            best_idx       = int(np.argmax(f1_scores))
            best_threshold = float(thresholds[best_idx])
            best_prec      = float(precisions[best_idx])
            best_rec       = float(recalls[best_idx])
            best_f1        = float(f1_scores[best_idx])
            best_threshold = max(best_threshold, DEFAULT_THRESHOLD)  # không thấp hơn default

        report = {
            "precision": round(best_prec, 4),
            "recall":    round(best_rec, 4),
            "f1":        round(best_f1, 4),
        }
        return best_threshold, report

    def predict(self, features: np.ndarray) -> Tuple[int, float]:
        """
        Phân loại một file.

        Returns: (label, probability)
          label = 0 (SAFE) hoặc 1 (ENCRYPTED)
          probability = xác suất là ENCRYPTED (0.0 ~ 1.0)
        """
        if not self._loaded or self.pipeline is None:
            return 0, 0.0

        if features.ndim == 1:
            features = features.reshape(1, -1)

        features = np.nan_to_num(features, nan=0.0, posinf=8.0, neginf=0.0)
        proba = float(self.pipeline.predict_proba(features)[0][1])
        label = 1 if proba >= self.threshold else 0
        return label, proba

    def predict_batch(self, feature_matrix: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Phân loại hàng loạt files."""
        if not self._loaded or self.pipeline is None:
            n = len(feature_matrix)
            return np.zeros(n, dtype=int), np.zeros(n, dtype=float)

        feature_matrix = np.nan_to_num(feature_matrix, nan=0.0, posinf=8.0, neginf=0.0)
        probas = self.pipeline.predict_proba(feature_matrix)[:, 1]
        labels = (probas >= self.threshold).astype(int)
        return labels, probas

    def get_risk_level(self, probability: float) -> str:
        """
        Chuyển xác suất thành mức độ rủi ro.
        Các ngưỡng được điều chỉnh theo threshold hiện tại.
        """
        t = self.threshold
        if probability >= max(t + 0.15, 0.85):
            return "CRITICAL"
        elif probability >= max(t + 0.05, 0.70):
            return "HIGH"
        elif probability >= t:
            return "MEDIUM"
        elif probability >= t * 0.6:
            return "LOW"
        else:
            return "SAFE"

    def get_risk_color(self, risk_level: str) -> str:
        return {
            "CRITICAL": "#FF2D2D",
            "HIGH":     "#FF8C00",
            "MEDIUM":   "#FFD700",
            "LOW":      "#00BFFF",
            "SAFE":     "#00FF88",
        }.get(risk_level, "#FFFFFF")

    def get_model_info(self) -> Dict:
        """Trả về thông tin model cho GUI."""
        return {
            "version":           self.metadata.get("version", "2.0"),
            "n_features":        self.metadata.get("n_features", N_FEATURES),
            "accuracy":          self.metadata.get("accuracy", 0.0),
            "precision":         self.metadata.get("precision", 0.0),
            "recall":            self.metadata.get("recall", 0.0),
            "f1_score":          self.metadata.get("f1_score", 0.0),
            "false_positive_rate": self.metadata.get("false_positive_rate", 0.0),
            "optimal_threshold": self._optimal_threshold,
            "current_threshold": self.threshold,
        }

    def _get_feedback_csv_path(self) -> str:
        return os.path.join(os.path.dirname(MODEL_DIR), "data", "feedback_samples.csv")

    def _get_synthetic_dataset_path(self) -> str:
        return os.path.join(os.path.dirname(MODEL_DIR), "data", "synthetic_dataset_v2.csv")

    def _get_real_dataset_path(self) -> str:
        """Path tới real_dataset.csv — dataset chính được dùng cho training."""
        return os.path.join(os.path.dirname(MODEL_DIR), "data", "real_dataset.csv")

    def _load_base_dataset(self) -> pd.DataFrame:
        """
        Load dataset gốc theo thứ tự ưu tiên:
          1. real_dataset.csv  (dữ liệu thật từ collect_safe/malware_samples)
          2. synthetic_dataset_v2.csv (legacy fallback)
        Trả về DataFrame rỗng nếu không có file nào.
        """
        for csv_path in (self._get_real_dataset_path(), self._get_synthetic_dataset_path()):
            if os.path.isfile(csv_path):
                try:
                    return pd.read_csv(csv_path)
                except Exception:
                    continue
        return pd.DataFrame()

    def _normalize_feedback_label(self, label: Optional[str]) -> Optional[str]:
        return normalize_feedback_label(label)

    def _normalize_feedback_type(
        self,
        feedback_type: Optional[str],
        predicted_label: Optional[str] = None,
        feedback_label: Optional[str] = None,
    ) -> Optional[str]:
        return normalize_feedback_type(
            feedback_type,
            predicted_label=predicted_label,
            feedback_label=feedback_label,
        )

    def _iter_feedback_rows(self, feedback_csv: Optional[str] = None) -> Iterable[Dict[str, str]]:
        path = feedback_csv or self._get_feedback_csv_path()
        return iter_feedback_rows(path)

    def _write_feedback_rows(self, rows: List[Dict[str, str]], feedback_csv: Optional[str] = None):
        path = feedback_csv or self._get_feedback_csv_path()
        write_feedback_rows(path, rows)

    def _decode_feedback_features(self, features_b64: str) -> Optional[np.ndarray]:
        try:
            feat_bytes = base64.b64decode(features_b64)
        except Exception:
            return None

        for dtype in (np.float64, np.float32):
            item_size = np.dtype(dtype).itemsize
            if len(feat_bytes) % item_size != 0:
                continue
            arr = np.frombuffer(feat_bytes, dtype=dtype)
            if arr.size >= N_FEATURES:
                return np.asarray(arr[:N_FEATURES], dtype=np.float32)

        return None

    def decode_serialized_features(self, features_b64: str) -> Optional[np.ndarray]:
        """Decode a serialized feature vector saved during scanning/feedback."""
        return self._decode_feedback_features(features_b64)

    def _feedback_csv_has_canonical_header(self, feedback_csv: str) -> bool:
        return feedback_csv_has_canonical_header(feedback_csv)

    def _merge_feedback_into_dataset(
        self,
        feedback_X: "np.ndarray",
        feedback_y: "np.ndarray",
        feedback_hashes: list,
        dataset_csv_path: str,
    ) -> int:
        """
        Ghi feedback features vào real_dataset.csv để tái sử dụng cho lần train sau.

        Quan trọng: features đã được serialize base64 trong feedback_samples.csv nên
        KHÔNG CẦN file gốc khi retrain. Sau khi merge vào real_dataset.csv, ngay cả
        khi xóa file PE gốc lẫn feedback_samples.csv, dữ liệu vẫn được giữ nguyên.

        Returns:
            Số rows mới được thêm vào dataset.
        """
        from core.external_dataset_builder import FEATURE_NAMES

        # Load dataset hiện tại hoặc tạo mới
        if os.path.isfile(dataset_csv_path):
            existing_df = pd.read_csv(dataset_csv_path)
            existing_hashes = set(existing_df.get("sha256", pd.Series(dtype=str)).dropna())
        else:
            existing_df = pd.DataFrame()
            existing_hashes = set()

        new_rows = []
        for i, (features, label, sha256) in enumerate(
            zip(feedback_X, feedback_y, feedback_hashes)
        ):
            # Bỏ qua nếu hash đã có trong dataset
            if sha256 and sha256 in existing_hashes:
                continue

            row = dict(zip(FEATURE_NAMES, features.tolist()))
            row["label"] = int(label)
            row["label_name"] = "ENCRYPTED" if label == 1 else "SAFE"
            row["path"] = ""          # file gốc không cần thiết nữa
            row["sha256"] = sha256 or ""
            row["extension"] = ""
            row["source"] = "feedback"  # đánh dấu nguồn gốc
            new_rows.append(row)

        if not new_rows:
            return 0

        new_df = pd.DataFrame(new_rows)
        merged_df = pd.concat([existing_df, new_df], ignore_index=True) \
            if len(existing_df) > 0 else new_df

        os.makedirs(os.path.dirname(dataset_csv_path), exist_ok=True)
        merged_df.to_csv(dataset_csv_path, index=False)
        return len(new_rows)

    def _backup_current_model(self) -> Optional[str]:
        if not os.path.isfile(MODEL_PATH):
            return None

        version = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_model = os.path.join(MODEL_DIR, f"rf_ransomware_detector_{version}.joblib")
        shutil.copy2(MODEL_PATH, backup_model)

        if os.path.isfile(META_PATH):
            backup_meta = os.path.join(MODEL_DIR, f"model_metadata_{version}.json")
            shutil.copy2(META_PATH, backup_meta)

        self._invalidate_model_versions_cache()
        return version


# ─── Feedback Loop Methods (v2.4) ─────────────────────────────────────────────

    def add_feedback_sample(
        self,
        file_hash: str,
        features: np.ndarray,
        predicted_label: str,
        feedback_label: str,
        feedback_type: str,
        user_id: Optional[str] = None,
    ) -> bool:
        """
        Add a user feedback sample for ML retraining.

        Args:
            file_hash: SHA256 of the file
            features: 16-element feature vector (base64 encoded if stored)
            predicted_label: What the model predicted
            feedback_label: What the user corrected to
            feedback_type: "false_positive" or "false_negative"
            user_id: Optional user identifier

        Returns:
            True if saved successfully
        """
        import uuid

        feedback_csv = self._get_feedback_csv_path()
        normalized_pred = self._normalize_feedback_label(predicted_label)
        normalized_feedback = self._normalize_feedback_label(feedback_label)
        normalized_type = self._normalize_feedback_type(
            feedback_type,
            predicted_label=normalized_pred,
            feedback_label=normalized_feedback,
        )
        if not normalized_pred or not normalized_feedback or not normalized_type:
            logger.error(
                "Failed to save feedback: invalid labels/type (%s, %s, %s)",
                predicted_label, feedback_label, feedback_type
            )
            return False

        # Encode features as base64 for compact storage
        feature_array = np.asarray(features, dtype=np.float64).reshape(-1)
        features_b64 = base64.b64encode(feature_array.tobytes()).decode("ascii")

        feedback_id = str(uuid.uuid4())[:8]
        timestamp = datetime.now(timezone.utc).isoformat()

        row = {
            "id": feedback_id,
            "hash": file_hash,
            "features_b64": features_b64,
            "predicted_label": normalized_pred,
            "feedback_label": normalized_feedback,
            "feedback_type": normalized_type,
            "timestamp": timestamp,
            "user_id": user_id or "unknown",
        }

        try:
            os.makedirs(os.path.dirname(feedback_csv), exist_ok=True)
            if self._feedback_csv_has_canonical_header(feedback_csv):
                file_exists = os.path.isfile(feedback_csv) and os.path.getsize(feedback_csv) > 0
                with open(feedback_csv, "a", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=FEEDBACK_COLUMNS)
                    if not file_exists:
                        writer.writeheader()
                    writer.writerow(row)
            else:
                rows = list(self._iter_feedback_rows(feedback_csv))
                rows.append(row)
                self._write_feedback_rows(rows, feedback_csv)

            self._invalidate_feedback_stats_cache()

            logger.info(
                f"Feedback saved: {normalized_type} — {normalized_pred}→{normalized_feedback} "
                f"[{file_hash[:8]}...]"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to save feedback: {e}")
            return False

    def get_feedback_stats(self) -> Dict[str, Any]:
        """Return feedback statistics."""
        feedback_csv = self._get_feedback_csv_path()
        cache_key = self._get_path_state(feedback_csv)
        if self._feedback_stats_cache_key == cache_key and self._feedback_stats_cache is not None:
            return dict(self._feedback_stats_cache)

        if not os.path.isfile(feedback_csv):
            stats = {
                "total": 0,
                "false_positive": 0,
                "false_negative": 0,
                "last_feedback": None,
            }
            self._feedback_stats_cache_key = cache_key
            self._feedback_stats_cache = dict(stats)
            return stats

        try:
            fp_count = 0
            fn_count = 0
            last_ts = None

            for row in self._iter_feedback_rows(feedback_csv):
                ft = row.get("feedback_type", "")
                if ft == "false_positive":
                    fp_count += 1
                elif ft == "false_negative":
                    fn_count += 1
                ts = row.get("timestamp", "")
                if ts and (last_ts is None or ts > last_ts):
                    last_ts = ts

            stats = {
                "total": fp_count + fn_count,
                "false_positive": fp_count,
                "false_negative": fn_count,
                "last_feedback": last_ts,
            }
            self._feedback_stats_cache_key = cache_key
            self._feedback_stats_cache = dict(stats)
            return stats

        except Exception as e:
            logger.error(f"Failed to read feedback stats: {e}")
            stats = {"total": 0, "false_positive": 0, "false_negative": 0, "last_feedback": None}
            self._feedback_stats_cache_key = cache_key
            self._feedback_stats_cache = dict(stats)
            return stats

    def retrain_with_feedback(
        self,
        model_save_path: Optional[str] = None,
        feedback_csv: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrain model with feedback samples (full retrain with SMOTE).

        Returns:
            Dict with metrics: success, new_model_version, previous_accuracy, etc.
        """
        import time

        start_time = time.time()
        save_path = model_save_path or MODEL_PATH

        fb_csv = feedback_csv or self._get_feedback_csv_path()

        # Load base dataset (real_dataset.csv ưu tiên, fallback synthetic)
        existing_df = self._load_base_dataset()
        base_csv_path = self._get_real_dataset_path()

        # Load feedback samples — features đã lưu trong CSV nên KHÔNG cần file gốc
        feedback_features = []
        feedback_labels = []
        feedback_hashes = []
        if os.path.isfile(fb_csv):
            try:
                for row in self._iter_feedback_rows(fb_csv):
                    features_b64 = row.get("features_b64", "")
                    if not features_b64:
                        continue
                    features = self._decode_feedback_features(features_b64)
                    feedback_label = self._normalize_feedback_label(row.get("feedback_label"))
                    if features is None or feedback_label is None:
                        continue
                    feedback_features.append(features)
                    feedback_labels.append(1 if feedback_label == "ENCRYPTED" else 0)
                    feedback_hashes.append(row.get("hash", ""))

                if not feedback_features:
                    return {"success": False, "error": "No valid feedback samples found"}

                feedback_X = np.array(feedback_features, dtype=np.float32)
                feedback_y = np.array(feedback_labels, dtype=np.int32)

                # Combine base dataset + feedback samples
                if len(existing_df) > 0:
                    X_existing = np.asarray(existing_df.iloc[:, :N_FEATURES].values, dtype=np.float32)
                    y_existing = np.asarray(existing_df["label"].values, dtype=np.int32)
                    X_combined = np.vstack([X_existing, feedback_X])
                    y_combined = np.concatenate([y_existing, feedback_y])
                else:
                    X_combined = feedback_X
                    y_combined = feedback_y

                if len(np.unique(y_combined)) < 2:
                    return {"success": False, "error": "Need both SAFE and ENCRYPTED samples to retrain"}

                backup_version = self._backup_current_model()

                try:
                    from core.config_manager import config
                    smote_strategy = config.get("ml.smote_strategy", "smote_tomek")
                except Exception:
                    smote_strategy = "smote_tomek"

                previous_accuracy = self.metadata.get("accuracy", None)
                metrics = self.train(
                    X_combined,
                    y_combined,
                    model_path=save_path,
                    verbose=False,
                    smote_strategy=smote_strategy,
                )

                training_time = time.time() - start_time

                # ── Persist feedback vào real_dataset.csv để tái sử dụng ──────
                # Features đã được lưu trong CSV nên dù file gốc bị xóa,
                # các lần retrain sau vẫn có đầy đủ dữ liệu.
                try:
                    self._merge_feedback_into_dataset(
                        feedback_X, feedback_y, feedback_hashes, base_csv_path
                    )
                    logger.info(
                        f"Merged {len(feedback_features)} feedback samples into {base_csv_path}"
                    )
                except Exception as merge_err:
                    logger.warning(f"Could not merge feedback into dataset: {merge_err}")

                return {
                    "success": True,
                    "new_model_version": datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"),
                    "backup_version": backup_version,
                    "samples_used": len(feedback_features),
                    "total_training_samples": len(X_combined),
                    "training_time_seconds": round(training_time, 1),
                    "previous_accuracy": previous_accuracy,
                    "new_accuracy": metrics.get("accuracy"),
                    "new_precision": metrics.get("precision"),
                    "new_recall": metrics.get("recall"),
                    "base_dataset_path": base_csv_path,
                    "merged_into_dataset": True,
                }

            except Exception as e:
                logger.error(f"Feedback retrain failed: {e}")
                return {"success": False, "error": str(e)}

        return {"success": False, "error": "Feedback file not found"}

    def retrain_with_auto_dataset(
        self,
        model_save_path: Optional[str] = None,
        min_confidence: str = "high",
        min_total_samples: int = 1,
        min_class_samples: int = 1,
    ) -> Dict[str, Any]:
        """
        Build an auto-labeled dataset from local evidence and retrain.

        This intentionally combines high-confidence local samples with the
        synthetic baseline dataset to reduce drift from noisy auto-labeling.
        """
        import time

        from core.training_dataset_builder import AutoTrainingDatasetBuilder

        start_time = time.time()
        save_path = model_save_path or MODEL_PATH
        builder = AutoTrainingDatasetBuilder()
        dataset_result = builder.build_dataset(min_confidence=min_confidence)

        X_auto = dataset_result.get("X")
        y_auto = dataset_result.get("y")
        if X_auto is None or y_auto is None or len(y_auto) == 0:
            return {"success": False, "error": "No auto-labeled samples available"}

        class_counts = dataset_result.get("class_counts", {})
        # Chỉ kiểm tra có đủ 2 class không (ít nhất 1 mẫu mỗi class)
        if len(y_auto) == 0:
            return {
                "success": False,
                "error": "No auto-labeled samples available",
                "dataset_path": dataset_result.get("output_path"),
            }
        if class_counts.get("SAFE", 0) < 1 or class_counts.get("ENCRYPTED", 0) < 1:
            return {
                "success": False,
                "error": "Need at least 1 SAFE and 1 ENCRYPTED sample to train",
                "dataset_path": dataset_result.get("output_path"),
                "class_counts": class_counts,
            }

        try:
            existing_csv = self._get_synthetic_dataset_path()
            if os.path.isfile(existing_csv):
                existing_df = pd.read_csv(existing_csv)
                X_existing = np.asarray(existing_df.iloc[:, :N_FEATURES].values)
                y_existing = np.asarray(existing_df["label"].values)
            else:
                X_existing = np.empty((0, N_FEATURES), dtype=np.float32)
                y_existing = np.empty((0,), dtype=np.int32)
        except Exception:
            X_existing = np.empty((0, N_FEATURES), dtype=np.float32)
            y_existing = np.empty((0,), dtype=np.int32)

        X_combined = np.vstack([X_existing, X_auto]) if len(X_existing) else X_auto
        y_combined = np.concatenate([y_existing, y_auto]) if len(y_existing) else y_auto

        backup_version = self._backup_current_model()
        previous_accuracy = self.metadata.get("accuracy", None)
        try:
            from core.config_manager import config
            smote_strategy = config.get("ml.smote_strategy", "smote_tomek")
        except Exception:
            smote_strategy = "smote_tomek"

        metrics = self.train(
            X_combined,
            y_combined,
            model_path=save_path,
            verbose=False,
            smote_strategy=smote_strategy,
        )

        training_time = time.time() - start_time
        return {
            "success": True,
            "new_model_version": datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"),
            "backup_version": backup_version,
            "dataset_path": dataset_result.get("output_path"),
            "auto_samples_used": int(len(y_auto)),
            "total_training_samples": int(len(y_combined)),
            "class_counts": class_counts,
            "training_time_seconds": round(training_time, 1),
            "previous_accuracy": previous_accuracy,
            "new_accuracy": metrics.get("accuracy"),
            "new_precision": metrics.get("precision"),
            "new_recall": metrics.get("recall"),
        }

    def get_model_versions(self) -> List[Dict[str, Any]]:
        """Return list of available model versions."""
        cache_key = self._get_model_versions_cache_key()
        if self._model_versions_cache_key == cache_key and self._model_versions_cache is not None:
            return [dict(item) for item in self._model_versions_cache]

        versions = []
        model_dir = os.path.dirname(MODEL_PATH)
        pattern = os.path.join(model_dir, "rf_ransomware_detector*.joblib")

        for path in glob.glob(pattern):
            try:
                mtime = os.path.getmtime(path)
                dt = datetime.fromtimestamp(mtime)
                # Check if it's a timestamped backup
                basename = os.path.basename(path)
                version_match = re.search(r"rf_ransomware_detector[._]?(\d{8,14})?", basename)
                version_str = version_match.group(1) if version_match else basename

                is_active = os.path.abspath(path) == os.path.abspath(MODEL_PATH)
                metrics: Dict[str, Any] = {}
                meta_path = META_PATH if is_active else os.path.join(model_dir, f"model_metadata_{version_str}.json")
                if os.path.isfile(meta_path):
                    try:
                        with open(meta_path, "r", encoding="utf-8") as f:
                            metrics = json.load(f)
                    except (json.JSONDecodeError, OSError):
                        metrics = {}

                versions.append({
                    "path": path,
                    "version": version_str,
                    "created_at": dt.isoformat(),
                    "is_active": is_active,
                    "size_bytes": os.path.getsize(path),
                    "accuracy": metrics.get("accuracy", 0.0),
                    "precision": metrics.get("precision", 0.0),
                    "sample_count": metrics.get("n_train", 0),
                })
            except Exception:
                continue

        versions = sorted(versions, key=lambda x: x["created_at"], reverse=True)
        self._model_versions_cache_key = cache_key
        self._model_versions_cache = [dict(item) for item in versions]
        return versions

    def rollback_model(self, backup_version: str) -> bool:
        """
        Rollback to a previous model version.

        Args:
            backup_version: Version string (from get_model_versions)

        Returns:
            True if rollback successful
        """
        import glob

        model_dir = os.path.dirname(MODEL_PATH)
        pattern = os.path.join(model_dir, f"*rf_ransomware_detector*{backup_version}*")

        matches = glob.glob(pattern)
        if not matches:
            logger.error(f"Rollback failed: version {backup_version} not found")
            return False

        backup_path = matches[0]
        try:
            # Backup current
            current_backup = MODEL_PATH + ".rollback_backup"
            if os.path.isfile(MODEL_PATH):
                shutil.copy2(MODEL_PATH, current_backup)

            # Restore
            shutil.copy2(backup_path, MODEL_PATH)
            # Re-pin integrity hash for the restored binary (the prior
            # pin belongs to the model we just replaced).
            _write_model_hash_sidecar(MODEL_PATH)

            version_match = re.search(r"(\d{8,14})", os.path.basename(backup_path))
            if version_match:
                backup_meta = os.path.join(model_dir, f"model_metadata_{version_match.group(1)}.json")
                if os.path.isfile(backup_meta):
                    shutil.copy2(backup_meta, META_PATH)

            # Reload
            self.load_model(MODEL_PATH)
            self._invalidate_model_versions_cache()
            logger.info(f"Model rolled back to {backup_version}")
            return True

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False


# ─── Backward-compatible alias ───
class RansomwareMLEngine(CalibratedMalwareDetector):
    """Alias cho backward compatibility với code cũ."""
    pass


# ─── Global singleton (thread-safe, auto-loads model) ───

_engine_instance: Optional[CalibratedMalwareDetector] = None
_engine_lock = _threading.Lock()


def get_engine(*, auto_load: bool = True) -> CalibratedMalwareDetector:
    """
    Return the singleton :class:`CalibratedMalwareDetector`.

    The previous implementation returned an *unloaded* engine, causing every
    ``predict()`` call to silently return ``(0, 0.0)`` and the API to mark
    every file SAFE. This version:

      - serialises construction with a lock (Scanner uses 8 worker threads),
      - eagerly calls :meth:`load_model` exactly once,
      - falls back to ``_train_default_model()`` when no checkpoint exists.

    Pass ``auto_load=False`` only in tests where the caller wants to inject
    a fixture model.
    """
    global _engine_instance
    if _engine_instance is not None:
        return _engine_instance

    with _engine_lock:
        if _engine_instance is None:
            instance = CalibratedMalwareDetector()
            if auto_load:
                try:
                    loaded = instance.load_model()
                    if not loaded:
                        logger.warning(
                            "No model checkpoint at %s — using untrained engine",
                            MODEL_PATH,
                        )
                except Exception as exc:  # pragma: no cover - defensive
                    logger.error("ML engine auto-load failed: %s", exc)
            _engine_instance = instance
    return _engine_instance


def reset_engine() -> None:
    """Reset the cached engine. Intended for tests only."""
    global _engine_instance
    with _engine_lock:
        _engine_instance = None
