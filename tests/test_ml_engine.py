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
        rng = np.random.default_rng(42)
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

    def test_class_weights(self):
        """Class weights should be SAFE=3.0, ENC=1.0."""
        assert CLASS_WEIGHT_SAFE == 3.0
        assert CLASS_WEIGHT_ENC == 1.0

    def test_safe_weight_higher_than_enc(self):
        """SAFE class weight should be higher to penalize FP."""
        assert CLASS_WEIGHT_SAFE > CLASS_WEIGHT_ENC


class TestSingleton:
    def test_get_engine_returns_detector(self):
        """get_engine should return CalibratedMalwareDetector."""
        engine = get_engine()
        assert isinstance(engine, CalibratedMalwareDetector)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
