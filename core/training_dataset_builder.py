"""
training_dataset_builder.py
===========================
Build a high-confidence training dataset from local evidence only.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import numpy as np
import pandas as pd

from core.auto_labeler import CONFIDENCE_RANK, auto_label_sample
from core.feedback_csv import iter_feedback_rows
from core.feature_extractor import FEATURE_NAMES, N_FEATURES, extract_features


SCAN_HISTORY_PATH = "data/scan_history.jsonl"
AUTO_LABELED_DATASET_PATH = "data/auto_labeled_samples.csv"
FEEDBACK_CSV_PATH = "data/feedback_samples.csv"
QUARANTINE_MANIFEST_PATH = "quarantine/quarantine_manifest.json"
HONEYPOT_REGISTRY_PATH = "data/honeypot_registry.json"
SOURCE_PRIORITY = {
    "feedback": 4,
    "quarantine": 3,
    "honeypot": 2,
    "scan_history": 1,
}


def _project_root() -> str:
    return _normalize_windows_path(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )


def _normalize_windows_path(path: str) -> str:
    """
    Normalize Windows extended-length paths (\\\\?\\C:\\...) into a form that
    pandas/open handle reliably, while preserving regular absolute paths.
    """
    normalized = os.path.normpath(path)
    if os.name == "nt" and normalized.startswith("\\\\?\\"):
        normalized = normalized[4:]
    return normalized


def resolve_path(path: str) -> str:
    if os.path.isabs(path):
        return _normalize_windows_path(path)
    return _normalize_windows_path(os.path.join(_project_root(), path))


def _decode_features_b64(features_b64: str) -> Optional[np.ndarray]:
    try:
        raw = base64.b64decode(features_b64)
    except Exception:
        return None

    for dtype in (np.float32, np.float64):
        item_size = np.dtype(dtype).itemsize
        if len(raw) % item_size != 0:
            continue
        arr = np.frombuffer(raw, dtype=dtype)
        if arr.size >= N_FEATURES:
            return np.asarray(arr[:N_FEATURES], dtype=np.float32)
    return None


def _encode_features(features: np.ndarray) -> str:
    return base64.b64encode(np.asarray(features, dtype=np.float32).tobytes()).decode("ascii")


def _safe_read_json(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _extract_features_with_original_name(file_path: str, original_name: str) -> Optional[np.ndarray]:
    if not os.path.isfile(file_path):
        return None

    suffix = os.path.splitext(original_name)[1]
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="auto-train-", suffix=suffix)
        os.close(fd)
        shutil.copy2(file_path, tmp_path)
        return extract_features(tmp_path)
    except Exception:
        return None
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def _sanitize_record_paths(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact personally-identifiable filesystem paths from a scan record before
    persisting it to disk.

    The ``path`` field is replaced with just the filename (basename) so the
    JSONL file can be shared without leaking home-directory structure or user
    names. The original SHA-256 is kept for deduplication; the ``filename``
    field is unchanged because it contains no directory component.
    """
    sanitized = dict(record)
    raw_path: str = sanitized.get("path", "")
    if raw_path:
        # Keep only the final filename component — strip all directory info.
        sanitized["path"] = os.path.basename(raw_path)
    return sanitized


def record_scan_history(results: List[Any], scan_mode: str, target_count: int = 0, history_path: str = SCAN_HISTORY_PATH) -> int:
    """Persist scan results to JSONL for future auto-labeling.

    Paths are sanitized (basename only) before writing so the history file
    does not leak personal directory structure or user names.
    """
    path = resolve_path(history_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    scan_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    count = 0
    with open(path, "a", encoding="utf-8") as f:
        for result in results:
            record = result.to_dict() if hasattr(result, "to_dict") else dict(result)
            payload = {
                "scan_id": scan_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "scan_history",
                "scan_mode": scan_mode,
                "target_count": target_count,
                "record": _sanitize_record_paths(record),
            }
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
            count += 1
    return count


class AutoTrainingDatasetBuilder:
    def __init__(
        self,
        feedback_csv: str = FEEDBACK_CSV_PATH,
        history_path: str = SCAN_HISTORY_PATH,
        quarantine_manifest: str = QUARANTINE_MANIFEST_PATH,
        honeypot_registry: str = HONEYPOT_REGISTRY_PATH,
        output_csv: str = AUTO_LABELED_DATASET_PATH,
    ):
        self.feedback_csv = resolve_path(feedback_csv)
        self.history_path = resolve_path(history_path)
        self.quarantine_manifest = resolve_path(quarantine_manifest)
        self.honeypot_registry = resolve_path(honeypot_registry)
        self.output_csv = resolve_path(output_csv)

    def build_dataset(self, min_confidence: str = "high") -> Dict[str, Any]:
        samples = []
        samples.extend(self._collect_feedback_samples())
        samples.extend(self._collect_quarantine_samples())
        samples.extend(self._collect_honeypot_samples())
        samples.extend(self._collect_scan_history_samples())

        deduped = self._dedupe_samples(samples)
        min_rank = CONFIDENCE_RANK.get(min_confidence, CONFIDENCE_RANK["high"])
        usable = [s for s in deduped if CONFIDENCE_RANK.get(s["confidence"], 0) >= min_rank]

        df = pd.DataFrame([
            {
                **{FEATURE_NAMES[i]: float(sample["features"][i]) for i in range(N_FEATURES)},
                "label": sample["label_value"],
                "label_name": sample["label"],
                "confidence": sample["confidence"],
                "source": sample["source"],
                "sha256": sample.get("sha256", ""),
                "path": sample.get("path", ""),
                "reasons": "|".join(sample.get("reasons", [])),
            }
            for sample in usable
        ])

        os.makedirs(os.path.dirname(self.output_csv), exist_ok=True)
        df.to_csv(self.output_csv, index=False)

        class_counts = {
            "SAFE": sum(1 for s in usable if s["label"] == "SAFE"),
            "ENCRYPTED": sum(1 for s in usable if s["label"] == "ENCRYPTED"),
        }
        return {
            "output_path": self.output_csv,
            "total_collected": len(samples),
            "deduped_samples": len(deduped),
            "usable_samples": len(usable),
            "class_counts": class_counts,
            "samples": usable,
            "X": np.array([s["features"] for s in usable], dtype=np.float32) if usable else np.empty((0, N_FEATURES), dtype=np.float32),
            "y": np.array([s["label_value"] for s in usable], dtype=np.int32) if usable else np.empty((0,), dtype=np.int32),
        }

    def _collect_feedback_samples(self) -> List[Dict[str, Any]]:
        if not os.path.isfile(self.feedback_csv):
            return []

        rows = self._read_feedback_rows()
        samples = []
        for row in rows:
            features = _decode_features_b64(row.get("features_b64", ""))
            label = row.get("feedback_label", "").upper()
            if features is None or label not in {"SAFE", "ENCRYPTED"}:
                continue
            samples.append({
                "source": "feedback",
                "sha256": row.get("hash", ""),
                "path": row.get("path", ""),
                "features": features,
                "label": label,
                "label_value": 1 if label == "ENCRYPTED" else 0,
                "confidence": "high",
                "reasons": [f"feedback:{label.lower()}"],
            })
        return samples

    def _collect_quarantine_samples(self) -> List[Dict[str, Any]]:
        manifest = _safe_read_json(self.quarantine_manifest, {})
        samples = []
        for entry in manifest.values():
            quarantined_path = entry.get("quarantined_path", "")
            original_path = entry.get("original_path", "")
            features = _extract_features_with_original_name(
                quarantined_path,
                os.path.basename(original_path) or "sample.bin",
            )
            if features is None:
                continue
            evidence = {
                "source": "quarantine",
                "quarantined": True,
                "quarantine_reason": entry.get("reason", ""),
            }
            decision = auto_label_sample(evidence)
            if decision["label"] == "UNKNOWN":
                continue
            samples.append({
                "source": "quarantine",
                "sha256": entry.get("hash", ""),
                "path": original_path,
                "features": features,
                "label": decision["label"],
                "label_value": 1 if decision["label"] == "ENCRYPTED" else 0,
                "confidence": decision["confidence"],
                "reasons": decision["reasons"],
            })
        return samples

    def _collect_honeypot_samples(self) -> List[Dict[str, Any]]:
        registry = _safe_read_json(self.honeypot_registry, {})
        honeypots = registry.get("honeypots", [])
        samples = []
        for hp in honeypots:
            if not hp.get("is_triggered"):
                continue
            path = hp.get("path", "")
            features = extract_features(path) if os.path.isfile(path) else None
            if features is None:
                continue
            evidence = {
                "source": "honeypot",
                "honeypot_triggered": True,
                "trigger_reason": hp.get("trigger_reason", ""),
            }
            decision = auto_label_sample(evidence)
            if decision["label"] == "UNKNOWN":
                continue
            samples.append({
                "source": "honeypot",
                "sha256": "",
                "path": path,
                "features": features,
                "label": decision["label"],
                "label_value": 1 if decision["label"] == "ENCRYPTED" else 0,
                "confidence": decision["confidence"],
                "reasons": decision["reasons"],
            })
        return samples

    def _collect_scan_history_samples(self) -> List[Dict[str, Any]]:
        if not os.path.isfile(self.history_path):
            return []

        samples = []
        with open(self.history_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                record = payload.get("record", {})
                features = _decode_features_b64(record.get("features_b64", ""))
                if features is None:
                    path = record.get("path", "")
                    if os.path.isfile(path):
                        features = extract_features(path)
                if features is None:
                    continue

                evidence = {
                    "source": "scan_history",
                    "probability": record.get("probability", 0.0),
                    "risk_level": record.get("risk_level", ""),
                    "fp_reason": record.get("fp_reason", ""),
                    "yara_match_count": record.get("yara_match_count", 0),
                    "yara_severities": record.get("yara_severities", []),
                    "pe_info": record.get("pe_info", {}),
                }
                decision = auto_label_sample(evidence)
                if decision["label"] == "UNKNOWN":
                    continue
                samples.append({
                    "source": "scan_history",
                    "sha256": record.get("sha256", ""),
                    "path": record.get("path", ""),
                    "features": features,
                    "label": decision["label"],
                    "label_value": 1 if decision["label"] == "ENCRYPTED" else 0,
                    "confidence": decision["confidence"],
                    "reasons": decision["reasons"],
                })
        return samples

    def _read_feedback_rows(self) -> List[Dict[str, str]]:
        return list(iter_feedback_rows(self.feedback_csv))

    def _dedupe_samples(self, samples: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        best: Dict[str, Dict[str, Any]] = {}
        for sample in samples:
            key = sample.get("sha256") or sample.get("path") or _encode_features(sample["features"])
            current = best.get(key)
            if current is None:
                best[key] = sample
                continue

            current_rank = (CONFIDENCE_RANK.get(current["confidence"], 0), SOURCE_PRIORITY.get(current["source"], 0))
            sample_rank = (CONFIDENCE_RANK.get(sample["confidence"], 0), SOURCE_PRIORITY.get(sample["source"], 0))
            if sample_rank > current_rank:
                best[key] = sample
        return list(best.values())
