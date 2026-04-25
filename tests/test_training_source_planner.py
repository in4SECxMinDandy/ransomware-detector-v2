import json
from pathlib import Path

from core.training_source_planner import (
    build_training_source_plan,
    download_training_source,
    prepare_training_source,
    train_from_source_plan,
)


def test_build_training_source_plan_defaults(temp_dir):
    plan = build_training_source_plan(kind="both", pe_only=True, scale="pilot", base_dir=str(temp_dir / "datasets"))

    assert plan["scale"] == "pilot"
    assert plan["pe_only"] is True
    assert any(entry["id"] == "napierone" for entry in plan["safe_sources"])
    assert any(entry["id"] == "sorel20m-github" for entry in plan["encrypted_sources"])
    assert Path(plan["layout"]["root"]).exists()


def test_build_training_source_plan_safe_only_excludes_encrypted_sources(temp_dir):
    plan = build_training_source_plan(kind="safe", pe_only=True, scale="pilot", base_dir=str(temp_dir / "datasets"))

    assert len(plan["safe_sources"]) >= 1
    assert plan["encrypted_sources"] == []


def test_download_training_source_creates_manifest(temp_dir):
    result = download_training_source(
        source_id="napierone",
        kind="safe",
        scale="pilot",
        base_dir=str(temp_dir / "datasets"),
    )

    manifest = Path(result["manifest_path"])
    assert manifest.exists()
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["source_id"] == "napierone"
    assert result["status"] == "manual-acquire-required"


def test_prepare_training_source_requires_manual_acquisition(temp_dir):
    result = prepare_training_source(
        source_id="napierone",
        kind="safe",
        scale="pilot",
        base_dir=str(temp_dir / "datasets"),
    )

    assert result["success"] is False
    assert result["status"] == "manual-acquire-required"
    assert "manifest_path" in result


def test_train_from_source_plan_requires_sources(temp_dir):
    result = train_from_source_plan(
        scale="pilot",
        base_dir=str(temp_dir / "datasets"),
        min_class_samples=1,
    )

    assert result["success"] is False
    assert result["status"] == "manual-acquire-required"
    assert len(result["manual_required"]) >= 1


def test_train_from_source_plan_rejects_one_sided_kind(temp_dir):
    result = train_from_source_plan(
        kind="safe",
        scale="pilot",
        base_dir=str(temp_dir / "datasets"),
        min_class_samples=1,
    )

    assert result["success"] is False
    assert result["status"] == "kind-not-supported-for-training"
    assert "both SAFE and ENCRYPTED" in result["message"]
