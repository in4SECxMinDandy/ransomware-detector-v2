"""
training_progress.py
====================
Progress reporting for the PE-only training workflow.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from core.external_dataset_builder import analyze_external_dataset, is_pe_file, iter_files
from core.training_source_planner import build_training_source_plan
from core.training_source_registry import get_scale_preset


def _count_files(directory: str) -> Dict[str, int]:
    if not os.path.isdir(directory):
        return {"total": 0, "pe_only": 0}
    total = 0
    pe_only = 0
    for path in iter_files(directory, recursive=True):
        total += 1
        if is_pe_file(path):
            pe_only += 1
    return {"total": total, "pe_only": pe_only}


def get_training_progress(
    scale: str = "pilot",
    base_dir: str | None = None,
) -> Dict[str, Any]:
    plan = build_training_source_plan(kind="both", pe_only=True, scale=scale, base_dir=base_dir)
    preset = get_scale_preset(scale)

    source_progress: List[Dict[str, Any]] = []
    for entry in plan["safe_sources"] + plan["encrypted_sources"]:
        counts = _count_files(entry["source_dir"])
        source_progress.append({
            "id": entry["id"],
            "name": entry["name"],
            "kind": entry["kind"],
            "status": entry["status"],
            "source_dir": entry["source_dir"],
            "target_per_class": entry["target_per_class"],
            "file_counts": counts,
        })

    prepared_dataset = analyze_external_dataset(
        safe_dir=plan["layout"]["prepared_safe"],
        encrypted_dir=plan["layout"]["prepared_encrypted"],
        recursive=True,
    )
    target = int(preset["target_per_class"])
    safe_ready = prepared_dataset["safe_count"] >= target
    encrypted_ready = prepared_dataset["encrypted_count"] >= target

    return {
        "scale": scale,
        "target_per_class": target,
        "layout": plan["layout"],
        "sources": source_progress,
        "prepared_dataset": prepared_dataset,
        "ready_for_scale": safe_ready and encrypted_ready,
        "next_scale_hint": "production" if scale == "pilot" and safe_ready and encrypted_ready else None,
    }


def render_training_progress(progress: Dict[str, Any]) -> str:
    lines = [
        f"Scale target: {progress['scale']} ({progress['target_per_class']} per class)",
        f"Datasets root: {progress['layout']['root']}",
        "",
        "Source folders:",
    ]
    for item in progress["sources"]:
        counts = item["file_counts"]
        lines.append(
            f"  - {item['kind']}::{item['id']} -> total={counts['total']} pe={counts['pe_only']} "
            f"target={item['target_per_class']}"
        )

    dataset = progress["prepared_dataset"]
    lines.extend(
        [
            "",
            "Prepared dataset:",
            f"  SAFE usable      : {dataset['safe_count']}",
            f"  ENCRYPTED usable : {dataset['encrypted_count']}",
            f"  Conflicting hash : {dataset['conflicting_hashes']}",
            f"  Skipped ratio    : {dataset['skipped_ratio']:.1%}",
            f"  Ready for scale  : {progress['ready_for_scale']}",
        ]
    )
    if progress.get("next_scale_hint"):
        lines.append(f"  Next scale hint  : {progress['next_scale_hint']}")
    return "\n".join(lines)
