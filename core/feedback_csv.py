"""
feedback_csv.py
================
Shared helpers for parsing and normalizing ML feedback CSV files.
"""

from __future__ import annotations

import csv
import io
import os
from typing import Dict, Iterable, List, Optional


FEEDBACK_COLUMNS = [
    "id",
    "hash",
    "features_b64",
    "predicted_label",
    "feedback_label",
    "feedback_type",
    "timestamp",
    "user_id",
]

FEEDBACK_TYPE_ALIASES = {
    "false_positive": "false_positive",
    "fp": "false_positive",
    "false_negative": "false_negative",
    "fn": "false_negative",
}

LABEL_ALIASES = {
    "SAFE": "SAFE",
    "BENIGN": "SAFE",
    "CLEAN": "SAFE",
    "ENCRYPTED": "ENCRYPTED",
    "RANSOMWARE": "ENCRYPTED",
    "MALICIOUS": "ENCRYPTED",
    "MALWARE": "ENCRYPTED",
    "THREAT": "ENCRYPTED",
}


def normalize_feedback_label(label: Optional[str]) -> Optional[str]:
    return LABEL_ALIASES.get(str(label or "").strip().upper())


def normalize_feedback_type(
    feedback_type: Optional[str],
    *,
    predicted_label: Optional[str] = None,
    feedback_label: Optional[str] = None,
) -> Optional[str]:
    raw_type = str(feedback_type or "").strip().lower()
    if raw_type in FEEDBACK_TYPE_ALIASES:
        return FEEDBACK_TYPE_ALIASES[raw_type]

    pred = normalize_feedback_label(predicted_label)
    fb = normalize_feedback_label(feedback_label)
    if pred == "ENCRYPTED" and fb == "SAFE":
        return "false_positive"
    if pred == "SAFE" and fb == "ENCRYPTED":
        return "false_negative"
    return None


def feedback_csv_has_canonical_header(feedback_csv: str) -> bool:
    if not os.path.isfile(feedback_csv):
        return True

    try:
        with open(feedback_csv, "r", encoding="utf-8", newline="") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or line.lstrip().startswith("#"):
                    continue
                header = next(csv.reader([line]), [])
                return [cell.strip() for cell in header] == FEEDBACK_COLUMNS
    except OSError:
        return False

    return True


def iter_feedback_rows(feedback_csv: str) -> Iterable[Dict[str, str]]:
    if not os.path.isfile(feedback_csv):
        return []

    try:
        with open(feedback_csv, "r", encoding="utf-8", newline="") as f:
            cleaned_lines = [
                line for line in f
                if line.strip() and not line.lstrip().startswith("#")
            ]
    except OSError:
        return []

    if not cleaned_lines:
        return []

    first_row = next(csv.reader([cleaned_lines[0]]), [])
    first_cells = {cell.strip() for cell in first_row}
    rows: List[Dict[str, str]] = []

    if {"feedback_label", "feedback_type"}.issubset(first_cells):
        reader = csv.DictReader(io.StringIO("".join(cleaned_lines)))
        raw_rows = list(reader)
    else:
        reader = csv.reader(cleaned_lines)
        raw_rows = []
        for row in reader:
            if not row:
                continue
            mapped = {
                FEEDBACK_COLUMNS[i]: row[i] if i < len(row) else ""
                for i in range(len(FEEDBACK_COLUMNS))
            }
            raw_rows.append(mapped)

    for raw in raw_rows:
        predicted_label = normalize_feedback_label(raw.get("predicted_label"))
        feedback_label = normalize_feedback_label(raw.get("feedback_label"))
        feedback_type = normalize_feedback_type(
            raw.get("feedback_type"),
            predicted_label=predicted_label,
            feedback_label=feedback_label,
        )
        if not feedback_label or not feedback_type:
            continue

        row = {key: str(raw.get(key, "") or "") for key in FEEDBACK_COLUMNS}
        row["predicted_label"] = predicted_label or ""
        row["feedback_label"] = feedback_label
        row["feedback_type"] = feedback_type
        rows.append(row)

    return rows


def write_feedback_rows(feedback_csv: str, rows: List[Dict[str, str]]):
    os.makedirs(os.path.dirname(feedback_csv), exist_ok=True)
    with open(feedback_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FEEDBACK_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in FEEDBACK_COLUMNS})
