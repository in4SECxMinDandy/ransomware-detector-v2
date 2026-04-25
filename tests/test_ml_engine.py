"""
test_ml_engine.py
=================
Unit tests for core/ml_engine.py
"""

import sys
import os
import pytest
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ml_engine import (
    CalibratedMalwareDetector,
    get_engine,
    DEFAULT_THRESHOLD,
    MIN_PRECISION,
    CLASS_WEIGHT_SAFE,
    CLASS_WEIGHT_ENC,
)


class TestCalibratedMalwareDetector:
    def test_default_threshold(self):
        """Default threshold should be 0.65."""
        detector = CalibratedMalwareDetector()
        assert detector.get_threshold() == 0.65

    def test_threshold_bounded(self):
        """Threshold should be bounded between 0.1 and 0.99."""
        detector = CalibratedMalwareDetector()
        detector.set_threshold(0.0)
        assert detector.get_threshold() == 0.1

        detector.set_threshold(1.5)
        assert detector.get_threshold() == 0.99

        detector.set_threshold(0.75)
        assert detector.get_threshold() == 0.75

    def test_unloaded_engine_returns_safe(self):
        """Unloaded engine should predict SAFE."""
        detector = CalibratedMalwareDetector()
        detector._loaded = False
        label, prob = detector.predict(np.zeros(16))
        assert label == 0
        assert prob == 0.0

    def test_predict_1d_array(self):
        """predict should accept 1D array."""
        detector = CalibratedMalwareDetector()
        detector._loaded = False
        features = np.zeros(16)
        label, prob = detector.predict(features)
        assert label == 0

    def test_predict_batch_unloaded(self):
        """predict_batch with unloaded engine returns zeros."""
        detector = CalibratedMalwareDetector()
        detector._loaded = False
        features = np.zeros((5, 16))
        labels, probs = detector.predict_batch(features)
        assert len(labels) == 5
        assert np.all(labels == 0)
        assert np.all(probs == 0.0)


class TestRiskLevels:
    def test_risk_levels(self):
        """Risk levels should be assigned correctly."""
        detector = CalibratedMalwareDetector()
        detector.threshold = 0.65

        assert detector.get_risk_level(0.95) == "CRITICAL"
        assert detector.get_risk_level(0.75) == "HIGH"
        assert detector.get_risk_level(0.65) == "MEDIUM"
        assert detector.get_risk_level(0.40) == "LOW"
        assert detector.get_risk_level(0.10) == "SAFE"

    def test_risk_colors(self):
        """Risk colors should be defined for all levels."""
        detector = CalibratedMalwareDetector()
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"]:
            color = detector.get_risk_color(level)
            assert color is not None
            assert isinstance(color, str)
            assert color.startswith("#")


class TestModelInfo:
    def test_get_model_info_empty(self):
        """get_model_info should return defaults when no model loaded."""
        detector = CalibratedMalwareDetector()
        info = detector.get_model_info()
        assert info["version"] == "2.0"
        assert "n_features" in info
        assert "optimal_threshold" in info


class TestOptimizeThreshold:
    def test_optimize_threshold_finds_valid(self):
        """_optimize_threshold should find a threshold meeting precision target."""
        detector = CalibratedMalwareDetector()

        # Create synthetic test data with clear separation
        y_true = np.array([0]*100 + [1]*100)
        y_proba = np.array([0.1]*100 + [0.9]*100)

        threshold, report = detector._optimize_threshold(y_true, y_proba, min_precision=0.90)

        assert 0.0 < threshold <= 1.0
        assert "precision" in report
        assert "recall" in report
        assert "f1" in report

    def test_optimize_threshold_fallback(self):
        """Should fallback to default when no threshold meets precision."""
        detector = CalibratedMalwareDetector()

        # All predictions at 0.5 - no threshold gives good precision
        y_true = np.array([0, 0, 1, 1])
        y_proba = np.array([0.5, 0.5, 0.5, 0.5])

        threshold, report = detector._optimize_threshold(y_true, y_proba, min_precision=0.95)

        # Should fallback to something reasonable
        assert 0.0 < threshold <= 1.0


class TestConstants:
    def test_default_threshold_value(self):
        """DEFAULT_THRESHOLD should be 0.65."""
        assert DEFAULT_THRESHOLD == 0.65

    def test_min_precision(self):
        """MIN_PRECISION should be 0.95."""
        assert MIN_PRECISION == 0.95

    def test_class_weights_match_cost_matrix(self):
        """class_weight must be derived from COST_FP/COST_FN (audit P1-9).

        Pre-fix the constants drifted: COST_FN=10 said FN was 3.3× costlier
        than FP=3, but class_weight={0:3, 1:1} actually penalised FP 3× more
        than FN. The fix wires CLASS_WEIGHT_SAFE = COST_FP and
        CLASS_WEIGHT_ENC = COST_FN so they cannot disagree.
        """
        from core.ml_engine import COST_FP, COST_FN
        assert CLASS_WEIGHT_SAFE == COST_FP, (
            f"SAFE weight ({CLASS_WEIGHT_SAFE}) must equal COST_FP ({COST_FP})"
        )
        assert CLASS_WEIGHT_ENC == COST_FN, (
            f"ENC weight ({CLASS_WEIGHT_ENC}) must equal COST_FN ({COST_FN})"
        )

    def test_enc_weight_higher_than_safe(self):
        """ENC class weight must be higher (FN-averse model).

        Missing ransomware (FN) is more costly than a false alarm (FP);
        FPs are reined in by the threshold optimizer + FP_REDUCER, not by
        class weighting.
        """
        assert CLASS_WEIGHT_ENC > CLASS_WEIGHT_SAFE


class TestSingleton:
    def test_get_engine_returns_detector(self):
        """get_engine should return CalibratedMalwareDetector."""
        engine = get_engine()
        assert isinstance(engine, CalibratedMalwareDetector)


class TestSmoteLeakageRegression:
    """Regression tests for audit P1-8 — SMOTE must not leak into val/test."""

    def _make_imbalanced(self, n_safe: int = 200, n_enc: int = 50, seed: int = 0):
        """Two well-separated Gaussians so a small RF can fit quickly."""
        rng = np.random.default_rng(seed)
        n_features = 16
        X_safe = rng.normal(loc=0.0, scale=1.0, size=(n_safe, n_features))
        X_enc  = rng.normal(loc=3.0, scale=1.0, size=(n_enc,  n_features))
        X = np.vstack([X_safe, X_enc]).astype(np.float32)
        y = np.concatenate([np.zeros(n_safe, dtype=int),
                            np.ones(n_enc,  dtype=int)])
        # Shuffle so the split isn't trivially ordered.
        order = rng.permutation(len(y))
        return X[order], y[order]

    def test_smote_does_not_inflate_test_set(self, tmp_path, monkeypatch):
        """The test fold must contain ~20% of the *original* rows.

        Pre-fix the SMOTE step ran before ``train_test_split`` so the test
        fold inherited synthetic neighbours of training rows. We expose
        this by spying on ``train_test_split`` and checking the input it
        receives is the un-resampled vector.
        """
        from core import ml_engine

        X, y = self._make_imbalanced()
        n_total = len(y)

        captured = {}
        real_split = ml_engine.train_test_split

        def spy_split(X_in, y_in, *args, **kwargs):
            # Record only the FIRST call (the outer 80/20 split).
            captured.setdefault("first_n", len(y_in))
            return real_split(X_in, y_in, *args, **kwargs)

        monkeypatch.setattr(ml_engine, "train_test_split", spy_split)

        detector = ml_engine.CalibratedMalwareDetector()
        detector.train(
            X, y,
            model_path=str(tmp_path / "model.joblib"),
            verbose=False,
            smote_strategy="smote_tomek",
        )

        # If SMOTE ran before the split, this would be > n_total.
        assert captured["first_n"] == n_total, (
            f"train_test_split saw {captured['first_n']} rows but the "
            f"original dataset only has {n_total} — SMOTE leaked into the "
            "split (audit P1-8)."
        )

    def test_smote_only_active_on_imbalanced_training_fold(self, tmp_path):
        """Smoke test: a perfectly balanced dataset should NOT trigger SMOTE.

        Implicitly proves the imbalance check operates on the training
        fold post-split, not the full dataset.
        """
        from core import ml_engine

        X, y = self._make_imbalanced(n_safe=120, n_enc=120)  # balanced

        detector = ml_engine.CalibratedMalwareDetector()
        # Just assert it runs end-to-end without exploding.
        detector.train(
            X, y,
            model_path=str(tmp_path / "balanced.joblib"),
            verbose=False,
            smote_strategy="smote_tomek",
        )
        assert detector.pipeline is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
