"""
pe_corpus_preparer.py
=====================
Prepare PE-only sample folders from downloaded corpora.
"""

from __future__ import annotations

import csv
import os
import shutil
from typing import Dict

from core.external_dataset_builder import (
    compute_sha256,
    is_pe_file,
    is_placeholder_path,
    iter_files,
    normalize_windows_path,
)


def prepare_pe_samples(
    input_dir: str,
    output_dir: str,
    recursive: bool = True,
    max_files: int | None = None,
    move: bool = False,
) -> Dict:
    input_dir = normalize_windows_path(input_dir)
    output_dir = normalize_windows_path(output_dir)

    if is_placeholder_path(input_dir):
        raise ValueError(f"Input directory looks like a placeholder path: {input_dir}")
    if is_placeholder_path(output_dir):
        raise ValueError(f"Output directory looks like a placeholder path: {output_dir}")
    if not os.path.isdir(input_dir):
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    os.makedirs(output_dir, exist_ok=True)
    manifest_path = os.path.join(output_dir, "manifest.csv")
    existing_hashes: set[str] = set()
    if os.path.isfile(manifest_path):
        with open(manifest_path, "r", encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                sha256 = row.get("sha256", "")
                if sha256:
                    existing_hashes.add(sha256)

    copied = 0
    non_pe_skipped = 0
    duplicate_skipped = 0
    errors = 0
    rows = []

    for path in iter_files(input_dir, recursive=recursive):
        if max_files is not None and copied >= max_files:
            break
        if not is_pe_file(path):
            non_pe_skipped += 1
            continue

        try:
            sha256 = compute_sha256(path)
            extension = os.path.splitext(path)[1].lower()
            if sha256 in existing_hashes:
                duplicate_skipped += 1
                continue

            filename = f"{sha256}{extension}"
            destination = os.path.join(output_dir, filename)
            if move:
                shutil.move(path, destination)
            else:
                shutil.copy2(path, destination)

            existing_hashes.add(sha256)
            copied += 1
            rows.append({
                "sha256": sha256,
                "extension": extension,
                "original_path": normalize_windows_path(path),
                "prepared_path": normalize_windows_path(destination),
            })
        except Exception:
            errors += 1

    file_exists = os.path.isfile(manifest_path)
    with open(manifest_path, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["sha256", "extension", "original_path", "prepared_path"],
        )
        if not file_exists:
            writer.writeheader()
        for row in rows:
            writer.writerow(row)

    return {
        "input_dir": input_dir,
        "output_dir": output_dir,
        "manifest_path": manifest_path,
        "copied": copied,
        "non_pe_skipped": non_pe_skipped,
        "duplicate_skipped": duplicate_skipped,
        "errors": errors,
        "move": move,
        "recursive": recursive,
    }
