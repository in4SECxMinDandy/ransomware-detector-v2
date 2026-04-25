"""
test_ml_feedback.py
=========================
Unit tests for ML feedback loop methods in ml_engine.py.
"""

import sys
import pytest
import csv
import base64
import numpy as np
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def _redirect_ml_paths(monkeypatch, temp_dir):
    import core.ml_engine as ml_engine

    model_dir = temp_dir / "models"
    data_dir = temp_dir / "data"
    model_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(ml_engine, "MODEL_DIR", str(model_dir))
    monkeypatch.setattr(ml_engine, "MODEL_PATH", str(model_dir / "rf_ransomware_detector.joblib"))
    monkeypatch.setattr(ml_engine, "META_PATH", str(model_dir / "model_metadata.json"))

    return ml_engine, model_dir, data_dir


def test_ml_feedback_stats_empty(temp_dir, monkeypatch):
    """Test feedback stats with no data."""
    _redirect_ml_paths(monkeypatch, temp_dir)
    from core.ml_engine import CalibratedMalwareDetector

    engine = CalibratedMalwareDetector()
    engine._loaded = True

    stats = engine.get_feedback_stats()

    assert stats["total"] == 0
    assert stats["false_positive"] == 0
    assert stats["false_negative"] == 0


def test_ml_feedback_stats_with_data(temp_dir, monkeypatch):
    """Test feedback stats with CSV data."""
    _, _, data_dir = _redirect_ml_paths(monkeypatch, temp_dir)
    from core.ml_engine import CalibratedMalwareDetector

    # Create feedback CSV
    csv_path = data_dir / "feedback_samples.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "id", "hash", "features_b64", "predicted_label",
            "feedback_label", "feedback_type", "timestamp", "user_id"
        ])
        writer.writeheader()
        writer.writerow({
            "id": "fb1",
            "hash": "a" * 64,
            "features_b64": "",
            "predicted_label": "ENCRYPTED",
            "feedback_label": "SAFE",
            "feedback_type": "false_positive",
            "timestamp": "2025-03-21T10:00:00",
            "user_id": "test_user",
        })
        writer.writerow({
            "id": "fb2",
            "hash": "b" * 64,
            "features_b64": "",
            "predicted_label": "SAFE",
            "feedback_label": "ENCRYPTED",
            "feedback_type": "false_negative",
            "timestamp": "2025-03-21T11:00:00",
            "user_id": "test_user",
        })

    engine = CalibratedMalwareDetector()
    engine._loaded = True

    stats = engine.get_feedback_stats()

    assert stats["total"] == 2
    assert stats["false_positive"] == 1
    assert stats["false_negative"] == 1
    assert stats["last_feedback"] == "2025-03-21T11:00:00"


def test_ml_feedback_stats_reads_legacy_feedback_rows(temp_dir, monkeypatch):
    """Legacy files with comments + no header should still be parsed."""
    _redirect_ml_paths(monkeypatch, temp_dir)
    from core.ml_engine import CalibratedMalwareDetector

    csv_path = temp_dir / "data" / "feedback_samples.csv"
    csv_path.write_text(
        "# ML Feedback Samples\n"
        "# legacy export\n"
        "fb1,test_hash,AAAA,ENCRYPTED,SAFE,FP,2026-03-21T09:48:19+00:00,test_user\n",
        encoding="utf-8",
    )

    engine = CalibratedMalwareDetector()
    stats = engine.get_feedback_stats()

    assert stats["total"] == 1
    assert stats["false_positive"] == 1
    assert stats["false_negative"] == 0


def test_get_model_versions(temp_dir, monkeypatch):
    """Test get_model_versions() method."""
    _redirect_ml_paths(monkeypatch, temp_dir)
    from core.ml_engine import CalibratedMalwareDetector

    engine = CalibratedMalwareDetector()
    engine._loaded = True

    versions = engine.get_model_versions()

    # Should return a list (may be empty if no backup versions exist)
    assert isinstance(versions, list)


def test_add_feedback_sample(temp_dir, monkeypatch):
    """Test adding a feedback sample."""
    _redirect_ml_paths(monkeypatch, temp_dir)
    from core.ml_engine import CalibratedMalwareDetector

    engine = CalibratedMalwareDetector()
    engine._loaded = True

    # Create features
    features = np.random.rand(16).astype(np.float64)

    success = engine.add_feedback_sample(
        file_hash="test_hash_abc123",
        features=features,
        predicted_label="ENCRYPTED",
        feedback_label="SAFE",
        feedback_type="false_positive",
        user_id="test_user",
    )

    assert success is True

    csv_path = temp_dir / "data" / "feedback_samples.csv"
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 1
    assert rows[0]["predicted_label"] == "ENCRYPTED"
    assert rows[0]["feedback_label"] == "SAFE"
    assert rows[0]["feedback_type"] == "false_positive"


def test_add_feedback_sample_appends_to_canonical_csv(temp_dir, monkeypatch):
    """Canonical feedback CSV should be appended without full rewrite."""
    _redirect_ml_paths(monkeypatch, temp_dir)
    from core.ml_engine import CalibratedMalwareDetector

    csv_path = temp_dir / "data" / "feedback_samples.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "id", "hash", "features_b64", "predicted_label",
            "feedback_label", "feedback_type", "timestamp", "user_id"
        ])
        writer.writeheader()
        writer.writerow({
            "id": "fb1",
            "hash": "seed_hash",
            "features_b64": "",
            "predicted_label": "SAFE",
            "feedback_label": "ENCRYPTED",
            "feedback_type": "false_negative",
            "timestamp": "2025-03-21T09:00:00",
            "user_id": "seed",
        })

    engine = CalibratedMalwareDetector()
    engine._loaded = True

    def fail_rewrite(*args, **kwargs):
        raise AssertionError("full rewrite path should not run for canonical CSV")

    monkeypatch.setattr(engine, "_write_feedback_rows", fail_rewrite)

    success = engine.add_feedback_sample(
        file_hash="test_hash_append",
        features=np.random.rand(16).astype(np.float64),
        predicted_label="ENCRYPTED",
        feedback_label="SAFE",
        feedback_type="false_positive",
        user_id="test_user",
    )

    assert success is True
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2


def test_model_version_struct(temp_dir, monkeypatch):
    """Test model version data structure."""
    _redirect_ml_paths(monkeypatch, temp_dir)
    from core.ml_engine import CalibratedMalwareDetector

    engine = CalibratedMalwareDetector()
    engine._loaded = True

    versions = engine.get_model_versions()

    for v in versions:
        assert "path" in v
        assert "version" in v
        assert "created_at" in v
        assert "is_active" in v


def test_retrain_with_feedback_no_data(temp_dir, monkeypatch):
    """Test retrain with no feedback data."""
    _redirect_ml_paths(monkeypatch, temp_dir)
    from core.ml_engine import CalibratedMalwareDetector

    engine = CalibratedMalwareDetector()
    engine._loaded = True

    # Should return error since no feedback file exists
    result = engine.retrain_with_feedback()

    # Either success=False or error about no data
    assert not result.get("success") or result.get("error") is not None


def test_ml_feedback_stats_uses_cache_until_file_changes(temp_dir, monkeypatch):
    """Repeated stats reads should reuse cached data until the file changes."""
    _, _, data_dir = _redirect_ml_paths(monkeypatch, temp_dir)
    from core.ml_engine import CalibratedMalwareDetector

    csv_path = data_dir / "feedback_samples.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "id", "hash", "features_b64", "predicted_label",
            "feedback_label", "feedback_type", "timestamp", "user_id"
        ])
        writer.writeheader()
        writer.writerow({
            "id": "fb1",
            "hash": "a" * 64,
            "features_b64": "",
            "predicted_label": "ENCRYPTED",
            "feedback_label": "SAFE",
            "feedback_type": "false_positive",
            "timestamp": "2025-03-21T10:00:00",
            "user_id": "test_user",
        })

    engine = CalibratedMalwareDetector()
    engine._loaded = True

    calls = {"count": 0}
    original = engine._iter_feedback_rows

    def wrapped(feedback_csv=None):
        calls["count"] += 1
        return original(feedback_csv)

    monkeypatch.setattr(engine, "_iter_feedback_rows", wrapped)

    stats1 = engine.get_feedback_stats()
    stats2 = engine.get_feedback_stats()

    assert stats1 == stats2
    assert calls["count"] == 1

    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "fb2", "b" * 64, "", "SAFE", "ENCRYPTED",
            "false_negative", "2025-03-21T11:00:00", "test_user"
        ])

    stats3 = engine.get_feedback_stats()
    assert stats3["total"] == 2
    assert calls["count"] == 2


def test_retrain_with_feedback_uses_feedback_labels(temp_dir, monkeypatch):
    """Retrain should preserve SAFE/ENCRYPTED labels from feedback."""
    _redirect_ml_paths(monkeypatch, temp_dir)
    from core.ml_engine import CalibratedMalwareDetector, FEATURE_NAMES

    dataset_path = temp_dir / "data" / "synthetic_dataset_v2.csv"
    with open(dataset_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES + ["label"])
        writer.writerow([0.1] * 16 + [0])
        writer.writerow([0.9] * 16 + [1])

    feedback_path = temp_dir / "data" / "feedback_samples.csv"
    with open(feedback_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "id", "hash", "features_b64", "predicted_label",
            "feedback_label", "feedback_type", "timestamp", "user_id"
        ])
        writer.writeheader()
        writer.writerow({
            "id": "fb1",
            "hash": "a" * 64,
            "features_b64": base64.b64encode(np.zeros(16, dtype=np.float64).tobytes()).decode("ascii"),
            "predicted_label": "ENCRYPTED",
            "feedback_label": "SAFE",
            "feedback_type": "false_positive",
            "timestamp": "2025-03-21T10:00:00",
            "user_id": "test_user",
        })
        writer.writerow({
            "id": "fb2",
            "hash": "b" * 64,
            "features_b64": base64.b64encode(np.ones(16, dtype=np.float64).tobytes()).decode("ascii"),
            "predicted_label": "SAFE",
            "feedback_label": "ENCRYPTED",
            "feedback_type": "false_negative",
            "timestamp": "2025-03-21T11:00:00",
            "user_id": "test_user",
        })

    engine = CalibratedMalwareDetector()
    engine.metadata = {"accuracy": 0.9}

    captured = {}

    def fake_train(X, y, model_path=None, verbose=True, smote_strategy="smote_tomek"):
        captured["X"] = X
        captured["y"] = y
        return {"accuracy": 0.95, "precision": 0.96, "recall": 0.94}

    monkeypatch.setattr(engine, "train", fake_train)

    result = engine.retrain_with_feedback()

    assert result["success"] is True
    assert 0 in captured["y"]
    assert 1 in captured["y"]
    assert result["new_accuracy"] == 0.95


def test_retrain_with_auto_dataset_uses_builder_output(temp_dir, monkeypatch):
    """Auto-dataset retrain should combine auto-labeled and synthetic samples."""
    _redirect_ml_paths(monkeypatch, temp_dir)
    from core.ml_engine import CalibratedMalwareDetector, FEATURE_NAMES
    import core.training_dataset_builder as tdb

    dataset_path = temp_dir / "data" / "synthetic_dataset_v2.csv"
    with open(dataset_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES + ["label"])
        writer.writerow([0.1] * 16 + [0])
        writer.writerow([0.9] * 16 + [1])

    class FakeBuilder:
        def build_dataset(self, min_confidence="high"):
            return {
                "output_path": str(temp_dir / "data" / "auto_labeled_samples.csv"),
                "class_counts": {"SAFE": 1, "ENCRYPTED": 1},
                "X": np.array([[0.2] * 16, [0.8] * 16], dtype=np.float32),
                "y": np.array([0, 1], dtype=np.int32),
            }

    monkeypatch.setattr(tdb, "AutoTrainingDatasetBuilder", FakeBuilder)

    engine = CalibratedMalwareDetector()
    engine.metadata = {"accuracy": 0.88}

    captured = {}

    def fake_train(X, y, model_path=None, verbose=True, smote_strategy="smote_tomek"):
        captured["X"] = X
        captured["y"] = y
        return {"accuracy": 0.97, "precision": 0.98, "recall": 0.96}

    monkeypatch.setattr(engine, "train", fake_train)

    result = engine.retrain_with_auto_dataset(min_total_samples=2, min_class_samples=1)

    assert result["success"] is True
    assert len(captured["y"]) == 4
    assert result["auto_samples_used"] == 2
    assert result["new_accuracy"] == 0.97


def test_rollback_model_not_found(temp_dir, monkeypatch):
    """Test rollback with non-existent version."""
    _redirect_ml_paths(monkeypatch, temp_dir)
    from core.ml_engine import CalibratedMalwareDetector

    engine = CalibratedMalwareDetector()
    engine._loaded = True

    # Should return False for non-existent version
    success = engine.rollback_model("nonexistent_version_xyz")
    assert not success


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
