"""
training_source_planner.py
==========================
Plan, manifest, prepare, and train orchestration for curated PE-only sources.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from core.external_dataset_builder import build_external_dataset, normalize_windows_path
from core.pe_corpus_preparer import prepare_pe_samples
from core.training_source_registry import (
    get_scale_preset,
    get_source_by_id,
    search_training_sources,
)


def _project_root() -> str:
    return normalize_windows_path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def get_training_layout(base_dir: str | None = None) -> Dict[str, str]:
    root = normalize_windows_path(base_dir or os.path.join(_project_root(), "datasets"))
    layout = {
        "root": root,
        "sources_safe": os.path.join(root, "sources", "safe"),
        "sources_encrypted": os.path.join(root, "sources", "encrypted"),
        "manifests": os.path.join(root, "manifests"),
        "prepared_safe": os.path.join(root, "prepared", "external_pe", "safe"),
        "prepared_encrypted": os.path.join(root, "prepared", "external_pe", "encrypted"),
        "datasets": os.path.join(root, "datasets"),
        "logs": os.path.join(root, "logs"),
    }
    return {key: normalize_windows_path(value) for key, value in layout.items()}


def ensure_training_layout(base_dir: str | None = None) -> Dict[str, str]:
    layout = get_training_layout(base_dir)
    for path in layout.values():
        if path != layout["root"]:
            os.makedirs(path, exist_ok=True)
    os.makedirs(layout["root"], exist_ok=True)
    return layout


def _select_default_sources(kind: str, pe_only: bool, scale: str) -> Dict[str, List[Dict[str, object]]]:
    if not pe_only:
        safe_candidates = search_training_sources(kind="safe")
        enc_candidates = search_training_sources(kind="encrypted")
    else:
        safe_candidates = search_training_sources(kind="safe")
        enc_candidates = search_training_sources(kind="encrypted", pe_only=True)

    source_map = {str(source["id"]): source for source in safe_candidates + enc_candidates}
    safe_defaults: List[Dict[str, object]] = []
    enc_defaults: List[Dict[str, object]] = []

    if kind in {"safe", "both"}:
        for source_id in ("napierone", "trusted-vendors"):
            source = source_map.get(source_id) or get_source_by_id(source_id)
            if source:
                safe_defaults.append(source)
    if kind in {"encrypted", "both"}:
        for source_id in ("sorel20m-github", "sorel20m-aws"):
            source = source_map.get(source_id) or get_source_by_id(source_id)
            if source:
                enc_defaults.append(source)

    return {
        "safe": safe_defaults,
        "encrypted": enc_defaults,
    }


def _build_source_plan_entry(
    source: Dict[str, object],
    kind: str,
    scale: str,
    layout: Dict[str, str],
) -> Dict[str, Any]:
    source_id = str(source["id"])
    source_dir_root = layout["sources_safe"] if kind == "safe" else layout["sources_encrypted"]
    prepare_dir = layout["prepared_safe"] if kind == "safe" else layout["prepared_encrypted"]
    source_dir = normalize_windows_path(os.path.join(source_dir_root, source_id))
    preset = get_scale_preset(scale)
    manifest_path = normalize_windows_path(
        os.path.join(layout["manifests"], f"{kind}_{source_id}_{scale}.json")
    )
    status = "source-ready" if os.path.isdir(source_dir) and os.listdir(source_dir) else "manual-acquire-required"

    next_commands = [
        f'python main.py --download-training-source --source-id {source_id} --kind {kind} --scale {scale}',
        f'python main.py --prepare-training-source --source-id {source_id} --kind {kind} --scale {scale}',
    ]
    return {
        "id": source_id,
        "name": source["name"],
        "kind": kind,
        "access_mode": source["access_mode"],
        "download_risk": source["download_risk"],
        "status": status,
        "source_dir": source_dir,
        "prepare_dir": prepare_dir,
        "manifest_path": manifest_path,
        "target_per_class": int(preset["target_per_class"]),
        "prepare_limit": int(preset["prepare_limit"]),
        "url": source.get("url", ""),
        "summary": source.get("summary", ""),
        "notes": source.get("notes", ""),
        "license_notes": source.get("license_notes", ""),
        "safety_notes": source.get("safety_notes", ""),
        "prepare_hint": source.get("prepare_hint", ""),
        "next_step_template": source.get("next_step_template", ""),
        "next_commands": next_commands,
    }


def build_training_source_plan(
    kind: str = "both",
    pe_only: bool = True,
    scale: str = "pilot",
    base_dir: str | None = None,
) -> Dict[str, Any]:
    layout = ensure_training_layout(base_dir)
    preset = get_scale_preset(scale)
    selected = _select_default_sources(kind, pe_only, scale)

    safe_entries = [
        _build_source_plan_entry(source, "safe", scale, layout)
        for source in selected["safe"]
    ]
    encrypted_entries = [
        _build_source_plan_entry(source, "encrypted", scale, layout)
        for source in selected["encrypted"]
    ]

    commands: List[str] = []
    if kind in {"safe", "both"}:
        commands.extend(entry["next_commands"][0] for entry in safe_entries)
    if kind in {"encrypted", "both"}:
        commands.extend(entry["next_commands"][0] for entry in encrypted_entries)
    commands.append(f"python main.py --train-from-source-plan --scale {scale}")

    return {
        "kind": kind,
        "pe_only": pe_only,
        "scale": scale,
        "scale_preset": preset,
        "layout": layout,
        "safe_sources": safe_entries,
        "encrypted_sources": encrypted_entries,
        "recommended_commands": commands,
    }


def write_training_manifest(plan_entry: Dict[str, Any]) -> str:
    manifest_path = normalize_windows_path(plan_entry["manifest_path"])
    os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_id": plan_entry["id"],
        "kind": plan_entry["kind"],
        "status": plan_entry["status"],
        "access_mode": plan_entry["access_mode"],
        "source_dir": plan_entry["source_dir"],
        "prepare_dir": plan_entry["prepare_dir"],
        "target_per_class": plan_entry["target_per_class"],
        "prepare_limit": plan_entry["prepare_limit"],
        "url": plan_entry["url"],
        "summary": plan_entry["summary"],
        "notes": plan_entry["notes"],
        "license_notes": plan_entry["license_notes"],
        "safety_notes": plan_entry["safety_notes"],
        "prepare_hint": plan_entry["prepare_hint"],
        "next_step_template": plan_entry["next_step_template"],
        "next_commands": plan_entry["next_commands"],
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return manifest_path


def download_training_source(
    source_id: str,
    kind: str,
    scale: str = "pilot",
    base_dir: str | None = None,
) -> Dict[str, Any]:
    plan = build_training_source_plan(kind=kind, pe_only=True, scale=scale, base_dir=base_dir)
    entries = plan["safe_sources"] if kind == "safe" else plan["encrypted_sources"]
    entry = next((item for item in entries if item["id"] == source_id), None)
    if entry is None:
        raise ValueError(f"Unknown source for kind={kind}: {source_id}")

    manifest_path = write_training_manifest(entry)
    source_dir = entry["source_dir"]
    os.makedirs(source_dir, exist_ok=True)
    status = "source-ready" if os.listdir(source_dir) else "manual-acquire-required"
    return {
        "status": status,
        "manifest_path": manifest_path,
        "source_dir": source_dir,
        "prepare_dir": entry["prepare_dir"],
        "source": entry,
    }


def prepare_training_source(
    source_id: str,
    kind: str,
    scale: str = "pilot",
    base_dir: str | None = None,
    move: bool = False,
    recursive: bool = True,
) -> Dict[str, Any]:
    info = download_training_source(source_id, kind, scale=scale, base_dir=base_dir)
    source_dir = info["source_dir"]
    if not os.path.isdir(source_dir) or not os.listdir(source_dir):
        return {
            "success": False,
            "status": "manual-acquire-required",
            "manifest_path": info["manifest_path"],
            "source_dir": source_dir,
            "prepare_dir": info["prepare_dir"],
            "message": "Source directory is empty. Acquire the subset manually, then run prepare again.",
        }

    result = prepare_pe_samples(
        input_dir=source_dir,
        output_dir=info["prepare_dir"],
        recursive=recursive,
        max_files=int(info["source"]["prepare_limit"]),
        move=move,
    )
    return {
        "success": True,
        "status": "prepared",
        "manifest_path": info["manifest_path"],
        "source": info["source"],
        "prepare_result": result,
    }


def train_from_source_plan(
    kind: str = "both",
    scale: str = "pilot",
    base_dir: str | None = None,
    min_class_samples: int = 5,
) -> Dict[str, Any]:
    plan = build_training_source_plan(kind=kind, pe_only=True, scale=scale, base_dir=base_dir)

    if kind != "both":
        return {
            "success": False,
            "status": "kind-not-supported-for-training",
            "plan": plan,
            "message": (
                "Training requires both SAFE and ENCRYPTED source plans. "
                "Use kind='both' for training, or use Download / Prepare for one-sided setup."
            ),
        }

    manual_required: List[Dict[str, Any]] = []
    prepare_results: List[Dict[str, Any]] = []

    for entry in plan["safe_sources"] + plan["encrypted_sources"]:
        result = prepare_training_source(
            source_id=entry["id"],
            kind=entry["kind"],
            scale=scale,
            base_dir=base_dir,
        )
        if result["status"] == "manual-acquire-required":
            manual_required.append({
                "id": entry["id"],
                "kind": entry["kind"],
                "manifest_path": result["manifest_path"],
                "source_dir": result["source_dir"],
            })
        else:
            prepare_results.append(result)

    if manual_required:
        return {
            "success": False,
            "status": "manual-acquire-required",
            "plan": plan,
            "manual_required": manual_required,
            "message": "One or more sources still need manual acquisition before training.",
        }

    layout = plan["layout"]
    output_csv = normalize_windows_path(
        os.path.join(layout["datasets"], f"external_pe_dataset_{scale}.csv")
    )
    dataset = build_external_dataset(
        safe_dir=layout["prepared_safe"],
        encrypted_dir=layout["prepared_encrypted"],
        output_csv=output_csv,
        recursive=True,
    )
    if dataset["safe_count"] < min_class_samples or dataset["encrypted_count"] < min_class_samples:
        return {
            "success": False,
            "status": "insufficient-data",
            "plan": plan,
            "prepare_results": prepare_results,
            "dataset": dataset,
            "message": f"Need at least {min_class_samples} usable SAFE and ENCRYPTED samples before training.",
        }

    from core.ml_engine import MODEL_PATH, get_engine

    engine = get_engine()
    backup_version = engine._backup_current_model()
    metrics = engine.train(dataset["X"], dataset["y"], model_path=MODEL_PATH, verbose=False)
    return {
        "success": True,
        "status": "trained",
        "plan": plan,
        "prepare_results": prepare_results,
        "dataset": dataset,
        "backup_version": backup_version,
        "metrics": metrics,
        "output_csv": output_csv,
    }


def render_training_plan(plan: Dict[str, Any]) -> str:
    lines = [
        f"Scale: {plan['scale']}",
        f"PE-only: {plan['pe_only']}",
        f"Datasets root: {plan['layout']['root']}",
    ]
    if plan["safe_sources"]:
        lines.append("SAFE sources:")
        for entry in plan["safe_sources"]:
            lines.append(
                f"  - {entry['name']} [{entry['status']}] -> {entry['source_dir']}"
            )
    if plan["encrypted_sources"]:
        lines.append("ENCRYPTED sources:")
        for entry in plan["encrypted_sources"]:
            lines.append(
                f"  - {entry['name']} [{entry['status']}] -> {entry['source_dir']}"
            )
    lines.append("Recommended commands:")
    lines.extend(f"  {command}" for command in plan["recommended_commands"])
    return "\n".join(lines)
