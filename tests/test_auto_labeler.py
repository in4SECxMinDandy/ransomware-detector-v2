import base64
import numpy as np

from core.auto_labeler import auto_label_sample
from core.training_dataset_builder import AutoTrainingDatasetBuilder, record_scan_history


def test_auto_label_feedback_is_high_confidence():
    result = auto_label_sample({"source": "feedback", "feedback_label": "SAFE"})
    assert result["label"] == "SAFE"
    assert result["confidence"] == "high"


def test_auto_label_honeypot_triggered_is_encrypted():
    result = auto_label_sample({"source": "honeypot", "honeypot_triggered": True})
    assert result["label"] == "ENCRYPTED"
    assert result["confidence"] == "high"


def test_build_dataset_from_scan_history(temp_dir):
    history_path = temp_dir / "scan_history.jsonl"
    output_csv = temp_dir / "auto_labeled.csv"

    features = np.ones(16, dtype=np.float32)

    class FakeResult:
        def to_dict(self):
            return {
                "sha256": "abc123",
                "path": str(temp_dir / "suspicious.exe"),
                "probability": 0.99,
                "risk_level": "CRITICAL",
                "fp_reason": "",
                "yara_match_count": 1,
                "yara_severities": ["CRITICAL"],
                "pe_info": {"suspicious_sections": [".evil"], "rwx_sections": [], "is_packed": False},
                "features_b64": base64.b64encode(features.tobytes()).decode("ascii"),
            }

    record_scan_history([FakeResult()], scan_mode="full", history_path=str(history_path))

    builder = AutoTrainingDatasetBuilder(
        feedback_csv=str(temp_dir / "missing_feedback.csv"),
        history_path=str(history_path),
        quarantine_manifest=str(temp_dir / "missing_manifest.json"),
        honeypot_registry=str(temp_dir / "missing_honeypot.json"),
        output_csv=str(output_csv),
    )
    result = builder.build_dataset(min_confidence="high")

    assert result["usable_samples"] == 1
    assert result["class_counts"]["ENCRYPTED"] == 1
    assert output_csv.exists()
