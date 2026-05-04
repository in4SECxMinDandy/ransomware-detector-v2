"""
smote_trainer.py — v2.1 (MỚI)
================================
SMOTE Oversampling module cho Ransomware Detector.

Giải quyết class imbalance khi training trên real-world data:
  - Dataset thực tế thường có ít ENCRYPTED samples hơn SAFE
  - Imbalanced data → model bias về SAFE (tăng FN rate)
  - SMOTE tạo synthetic minority samples → cân bằng classes

Các chiến lược được cung cấp:
  1. SMOTE (cơ bản)         — tạo synthetic samples từ k-nearest neighbors
  2. SMOTE + Tomek Links    — SMOTE rồi loại bỏ noisy borderline samples
  3. SMOTE + ENN            — SMOTE + Edited Nearest Neighbors (clean borders)
  4. ADASYN                 — Adaptive Synthetic Sampling (focus vùng khó)
  5. BorderlineSMOTE        — SMOTE chỉ ở vùng borderline (mạnh hơn vs ransomware variants)

Sử dụng:
  from core.smote_trainer import SMOTETrainer
  trainer = SMOTETrainer(strategy="smote_tomek")
  X_res, y_res = trainer.resample(X, y)
"""

import numpy as np
import warnings
from typing import TYPE_CHECKING, Tuple, Dict

# Suppress imbalanced-learn warnings that are expected when SMOTE operates on
# small datasets (e.g. k_neighbors > minority class size). These are benign in
# the project context. A blanket "ignore" was used before; now we only silence
# the specific message patterns to keep other warnings visible.
warnings.filterwarnings("ignore", message=".*n_neighbors.*")
warnings.filterwarnings("ignore", message=".*The number of samples.*")
warnings.filterwarnings("ignore", category=UserWarning, module="imblearn")

# ─── Try import imbalanced-learn ───
if TYPE_CHECKING:
    from imblearn.over_sampling import (  # type: ignore[import-not-found]
        SMOTE, ADASYN, BorderlineSMOTE
    )
    from imblearn.combine import SMOTETomek, SMOTEENN  # type: ignore[import-not-found]
    IMBLEARN_AVAILABLE = True
else:
    try:
        from imblearn.over_sampling import (
            SMOTE, ADASYN, BorderlineSMOTE
        )
        from imblearn.combine import SMOTETomek, SMOTEENN
        IMBLEARN_AVAILABLE = True
    except ImportError:  # pragma: no cover
        SMOTE = None
        ADASYN = None
        BorderlineSMOTE = None
        SMOTETomek = None
        SMOTEENN = None
        IMBLEARN_AVAILABLE = False

# ─── Constants ───
SUPPORTED_STRATEGIES = [
    "smote",           # Basic SMOTE
    "smote_tomek",     # SMOTE + Tomek Links cleanup (recommended)
    "smote_enn",       # SMOTE + Edited Nearest Neighbors
    "adasyn",          # Adaptive Synthetic (ADASYN)
    "borderline",      # BorderlineSMOTE
    "none",            # No oversampling (disable)
]


class SMOTETrainer:
    """
    SMOTE-based oversampler với nhiều chiến lược.

    Recommended cho ransomware detection:
      - 'smote_tomek': Cân bằng tốt + loại noisy samples
        → giảm FP do không có overlap vùng ranh giới
      - 'borderline': Chú trọng vào samples gần ranh giới
        → tốt hơn cho ransomware variants khó phát hiện
    """

    def __init__(
        self,
        strategy: str = "smote_tomek",
        random_state: int = 42,
        k_neighbors: int = 5,
        sampling_ratio: float = 1.0,   # 1.0 = balance hoàn toàn
    ):
        self.strategy       = strategy
        self.random_state   = random_state
        self.k_neighbors    = k_neighbors
        self.sampling_ratio = sampling_ratio
        self._sampler       = None
        self._is_available  = IMBLEARN_AVAILABLE
        self._stats: Dict   = {}

    def is_available(self) -> bool:
        return IMBLEARN_AVAILABLE

    def get_strategy(self) -> str:
        return self.strategy

    def resample(
        self,
        X: np.ndarray,
        y: np.ndarray,
        verbose: bool = True
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Áp dụng SMOTE oversampling.

        Parameters
        ----------
        X       : feature matrix (n_samples, n_features)
        y       : labels (0=SAFE, 1=ENCRYPTED)
        verbose : in thống kê trước/sau

        Returns
        -------
        X_resampled, y_resampled — dataset sau oversampling
        """
        n_safe  = int(np.sum(y == 0))
        n_enc   = int(np.sum(y == 1))
        total   = len(y)

        self._stats["before"] = {
            "total": total, "safe": n_safe, "encrypted": n_enc,
            "ratio": round(n_enc / max(n_safe, 1), 4),
        }

        if verbose:
            print(f"\n[SMOTE] Strategy: {self.strategy}")
            print(f"[SMOTE] Before: SAFE={n_safe}, ENCRYPTED={n_enc} "
                  f"(ratio={n_enc/max(n_safe,1):.2f})")

        if self.strategy == "none" or not IMBLEARN_AVAILABLE:
            if not IMBLEARN_AVAILABLE and self.strategy != "none":
                print("[SMOTE] [!] imbalanced-learn not available -- skipping SMOTE")
                print("[SMOTE]     Install: pip install imbalanced-learn")
            return X, y

        # Chỉ áp dụng SMOTE nếu có imbalance đáng kể
        imbalance_ratio = min(n_safe, n_enc) / max(n_safe, n_enc)
        if imbalance_ratio > 0.9:
            if verbose:
                print(f"[SMOTE] Dataset near balanced (ratio={imbalance_ratio:.2f}) -- skipping")
            return X, y

        # Tính số k_neighbors phù hợp (không vượt quá minority class size)
        k = min(self.k_neighbors, min(n_safe, n_enc) - 1)
        k = max(k, 1)

        try:
            sampler = self._build_sampler(k)
            resampled = sampler.fit_resample(X, y)
            X_res, y_res = resampled[0], resampled[1]

            n_safe_after = int(np.sum(y_res == 0))
            n_enc_after  = int(np.sum(y_res == 1))

            self._stats["after"] = {
                "total":     len(y_res),
                "safe":      n_safe_after,
                "encrypted": n_enc_after,
                "ratio":     round(n_enc_after / max(n_safe_after, 1), 4),
                "new_samples": len(y_res) - total,
            }

            if verbose:
                print(f"[SMOTE] After:  SAFE={n_safe_after}, ENCRYPTED={n_enc_after} "
                      f"(+{len(y_res)-total} synthetic samples)")
                print("[SMOTE] [OK] Resampling complete")

            return np.asarray(X_res), np.asarray(y_res)

        except Exception as e:
            print(f"[SMOTE] [ERROR] {e} -- returning original dataset")
            return X, y

    def _build_sampler(self, k: int):
        """Tạo sampler theo strategy."""
        rs = self.random_state

        if self.strategy == "smote":
            return SMOTE(k_neighbors=k, random_state=rs)  # type: ignore[call-arg]

        elif self.strategy == "smote_tomek":
            return SMOTETomek(  # type: ignore[call-arg]
                smote=SMOTE(k_neighbors=k, random_state=rs),  # type: ignore[call-arg]
                random_state=rs,
            )

        elif self.strategy == "smote_enn":
            return SMOTEENN(  # type: ignore[call-arg]
                smote=SMOTE(k_neighbors=k, random_state=rs),  # type: ignore[call-arg]
                random_state=rs,
            )

        elif self.strategy == "adasyn":
            return ADASYN(n_neighbors=k, random_state=rs)  # type: ignore[call-arg]

        elif self.strategy == "borderline":
            return BorderlineSMOTE(  # type: ignore[call-arg]
                k_neighbors=k,
                kind="borderline-2",
                random_state=rs,
            )

        else:
            # Fallback to basic SMOTE
            return SMOTE(k_neighbors=k, random_state=rs)  # type: ignore[call-arg]

    def get_stats(self) -> Dict:
        """Trả về thống kê trước/sau resampling."""
        return self._stats

    def get_recommendation(self, n_safe: int, n_encrypted: int) -> str:
        """
        Gợi ý strategy tốt nhất dựa trên tỷ lệ imbalance.

        Returns: tên strategy được khuyến nghị
        """
        ratio = min(n_safe, n_encrypted) / max(n_safe, n_encrypted, 1)

        if ratio > 0.8:
            return "none"        # Dataset đủ cân bằng
        elif ratio > 0.5:
            return "smote"       # Imbalance nhẹ
        elif ratio > 0.2:
            return "smote_tomek" # Imbalance vừa (recommended)
        else:
            return "adasyn"      # Imbalance nặng → ADASYN tốt hơn


def get_smote_info() -> Dict:
    """Trả về thông tin về SMOTE module."""
    return {
        "available":   IMBLEARN_AVAILABLE,
        "strategies":  SUPPORTED_STRATEGIES,
        "recommended": "smote_tomek",
        "description": {
            "smote":       "Cơ bản — tạo synthetic samples từ k-NN",
            "smote_tomek": "SMOTE + Tomek Links — giảm noise vùng ranh giới (recommended)",
            "smote_enn":   "SMOTE + ENN — mạnh hơn Tomek trong làm sạch ranh giới",
            "adasyn":      "Adaptive — focus vùng khó phân loại",
            "borderline":  "Chỉ oversample vùng borderline — tốt cho ransomware variants",
            "none":        "Không oversampling",
        },
    }
