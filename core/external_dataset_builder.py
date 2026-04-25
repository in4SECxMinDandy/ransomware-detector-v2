"""
external_dataset_builder.py
===========================
Build a PE-only labeled training dataset from user-provided SAFE and
ENCRYPTED folders.
"""

from __future__ import annotations

import hashlib
import os
from typing import Dict, Iterable, List, Tuple

import numpy as np
import pandas as pd

from core.feature_extractor import FEATURE_NAMES, N_FEATURES, extract_features


PE_EXTENSIONS = {".exe", ".dll", ".sys", ".msi"}
PLACEHOLDER_TOKENS = (
    "...",
    "path\\to",
    "path/to",
    "duong-dan-that",
)


def normalize_windows_path(path: str) -> str:
    normalized = os.path.normpath(path)
    if os.name == "nt" and normalized.startswith("\\\\?\\"):
        normalized = normalized[4:]
    return normalized


def is_placeholder_path(path: str) -> bool:
    lowered = normalize_windows_path(path).strip().lower()
    return any(token in lowered for token in PLACEHOLDER_TOKENS)


def is_pe_file(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in PE_EXTENSIONS


def compute_sha256(file_path: str) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_files(root: str, recursive: bool = True) -> Iterable[str]:
    root = normalize_windows_path(root)
    if os.path.isfile(root):
        yield os.path.abspath(root)
        return

    if not os.path.isdir(root):
        return

    if recursive:
        for current_root, _, filenames in os.walk(root):
            for name in filenames:
                yield os.path.abspath(os.path.join(current_root, name))
    else:
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isfile(path):
                yield os.path.abspath(path)


def _empty_stats(label_name: str) -> Dict[str, int | str]:
    return {
        "label_name": label_name,
        "files_seen": 0,
        "usable": 0,
        "non_pe_skipped": 0,
        "feature_skipped": 0,
        "duplicate_skipped": 0,
    }


def _collect_labeled_features(
    directory: str,
    label: int,
    recursive: bool = True,
) -> Tuple[List[Dict[str, object]], Dict[str, int | str]]:
    label_name = "ENCRYPTED" if label == 1 else "SAFE"
    stats = _empty_stats(label_name)
    seen_hashes: set[str] = set()
    rows: List[Dict[str, object]] = []

    for path in iter_files(directory, recursive=recursive):
        stats["files_seen"] = int(stats["files_seen"]) + 1
        if not is_pe_file(path):
            stats["non_pe_skipped"] = int(stats["non_pe_skipped"]) + 1
            continue

        try:
            sha256 = compute_sha256(path)
        except OSError:
            stats["feature_skipped"] = int(stats["feature_skipped"]) + 1
            continue

        if sha256 in seen_hashes:
            stats["duplicate_skipped"] = int(stats["duplicate_skipped"]) + 1
            continue

        features = extract_features(path)
        if features is None or len(features) != N_FEATURES:
            stats["feature_skipped"] = int(stats["feature_skipped"]) + 1
            continue

        seen_hashes.add(sha256)
        features_arr = np.asarray(features, dtype=np.float32)
        row: Dict[str, object] = {
            FEATURE_NAMES[i]: float(features_arr[i])
            for i in range(N_FEATURES)
        }
        row["label"] = label
        row["label_name"] = label_name
        row["path"] = normalize_windows_path(path)
        row["sha256"] = sha256
        row["extension"] = os.path.splitext(path)[1].lower()
        row["_features"] = features_arr
        rows.append(row)
        stats["usable"] = int(stats["usable"]) + 1

    return rows, stats


def _drop_conflicting_hashes(
    safe_rows: List[Dict[str, object]],
    enc_rows: List[Dict[str, object]],
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], int]:
    safe_hashes = {str(row["sha256"]) for row in safe_rows}
    enc_hashes = {str(row["sha256"]) for row in enc_rows}
    conflicting = safe_hashes & enc_hashes
    if not conflicting:
        return safe_rows, enc_rows, 0

    safe_filtered = [row for row in safe_rows if str(row["sha256"]) not in conflicting]
    enc_filtered = [row for row in enc_rows if str(row["sha256"]) not in conflicting]
    return safe_filtered, enc_filtered, len(conflicting)


def _collect_external_dataset(
    safe_dir: str,
    encrypted_dir: str,
    recursive: bool = True,
) -> Dict:
    safe_dir = normalize_windows_path(safe_dir)
    encrypted_dir = normalize_windows_path(encrypted_dir)

    if is_placeholder_path(safe_dir):
        raise ValueError(f"SAFE directory looks like a placeholder path: {safe_dir}")
    if is_placeholder_path(encrypted_dir):
        raise ValueError(f"ENCRYPTED directory looks like a placeholder path: {encrypted_dir}")

    safe_rows, safe_stats = _collect_labeled_features(safe_dir, 0, recursive=recursive)
    enc_rows, enc_stats = _collect_labeled_features(encrypted_dir, 1, recursive=recursive)
    safe_rows, enc_rows, conflict_count = _drop_conflicting_hashes(safe_rows, enc_rows)

    rows = safe_rows + enc_rows

    export_rows = []
    for row in rows:
        export_row = {k: v for k, v in row.items() if k != "_features"}
        export_rows.append(export_row)

    feature_parts = [np.asarray(row["_features"], dtype=np.float32) for row in rows]
    X = np.vstack(feature_parts) if feature_parts else np.empty((0, N_FEATURES), dtype=np.float32)
    y = np.array([int(row["label"]) for row in rows], dtype=np.int32)

    safe_count = len(safe_rows)
    encrypted_count = len(enc_rows)
    total = len(rows)
    skipped_total = (
        int(safe_stats["non_pe_skipped"]) + int(safe_stats["feature_skipped"]) + int(safe_stats["duplicate_skipped"])
        + int(enc_stats["non_pe_skipped"]) + int(enc_stats["feature_skipped"]) + int(enc_stats["duplicate_skipped"])
        + conflict_count
    )
    seen_total = int(safe_stats["files_seen"]) + int(enc_stats["files_seen"])
    skipped_ratio = skipped_total / seen_total if seen_total else 0.0

    return {
        "X": X,
        "y": y,
        "rows": export_rows,
        "safe_count": safe_count,
        "encrypted_count": encrypted_count,
        "safe_stats": safe_stats,
        "encrypted_stats": enc_stats,
        "conflicting_hashes": conflict_count,
        "skipped_total": skipped_total,
        "skipped_ratio": skipped_ratio,
        "total": total,
        "pe_only": True,
        "extensions": sorted(PE_EXTENSIONS),
    }


def analyze_external_dataset(
    safe_dir: str,
    encrypted_dir: str,
    recursive: bool = True,
) -> Dict:
    return _collect_external_dataset(
        safe_dir=safe_dir,
        encrypted_dir=encrypted_dir,
        recursive=recursive,
    )


def build_external_dataset(
    safe_dir: str,
    encrypted_dir: str,
    output_csv: str,
    recursive: bool = True,
) -> Dict:
    output_csv = normalize_windows_path(output_csv)
    dataset = _collect_external_dataset(
        safe_dir=safe_dir,
        encrypted_dir=encrypted_dir,
        recursive=recursive,
    )

    output_dir = os.path.dirname(output_csv)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    csv_columns = FEATURE_NAMES + ["label", "label_name", "path", "sha256", "extension"]
    df = pd.DataFrame(dataset["rows"], columns=csv_columns)
    df.to_csv(output_csv, index=False)
    dataset["output_csv"] = output_csv
    return dataset
