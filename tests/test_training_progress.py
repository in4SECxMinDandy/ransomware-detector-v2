from pathlib import Path

from core.training_progress import get_training_progress, render_training_progress


def test_training_progress_reports_layout_and_targets(temp_dir):
    progress = get_training_progress(scale="smoke", base_dir=str(temp_dir / "datasets"))

    assert progress["scale"] == "smoke"
    assert progress["target_per_class"] == 100
    assert Path(progress["layout"]["root"]).exists()
    assert progress["ready_for_scale"] is False
    assert len(progress["sources"]) >= 1


def test_render_training_progress_contains_prepared_summary(temp_dir):
    progress = get_training_progress(scale="pilot", base_dir=str(temp_dir / "datasets"))
    text = render_training_progress(progress)

    assert "Prepared dataset:" in text
    assert "SAFE usable" in text
    assert "ENCRYPTED usable" in text
