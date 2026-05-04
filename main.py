#!/usr/bin/env python3
"""
Ransomware Entropy Detector v1.0
=================================
Entry point - Khởi chạy ứng dụng Desktop.

Usage:
    python main.py              # Khởi chạy GUI
    python main.py --train      # Chỉ train model, không mở GUI
    python main.py --scan PATH  # CLI scan (không GUI)
    python main.py --build-auto-dataset [--retrain]
    python main.py --search-training-sources [--query TEXT] [--kind safe|encrypted|both]
    python main.py --plan-training-source [--kind safe|encrypted|both] [--scale smoke|pilot|production]
    python main.py --training-progress [--scale smoke|pilot|production]
    python main.py --download-training-source --source-id ID --kind safe|encrypted [--scale ...]
    python main.py --prepare-external-pe --input-dir PATH --output-dir PATH [--max-files N]
    python main.py --prepare-training-source --source-id ID --kind safe|encrypted [--scale ...]
    python main.py --train-external --safe-dir PATH --encrypted-dir PATH [--output-csv PATH]
    python main.py --train-from-source-plan [--scale smoke|pilot|production]

Author: PTIT Security Research Lab
"""

import sys
import os
import argparse

# Đảm bảo import path chính xác
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)


def _handle_missing_feature_module(feature_name: str, error: ModuleNotFoundError) -> int:
    """Report missing optional workflow modules without a hard crash."""
    missing_name = getattr(error, "name", None) or str(error)
    print(f"{feature_name} is currently unavailable because module '{missing_name}' is missing.")
    print("Add the corresponding training workflow files to the project before using this command.")
    return 1


def run_gui():
    """Khởi chạy giao diện GUI."""
    import threading
    from gui.main_window import launch

    # Task 4: Start tray in daemon thread so it never blocks main GUI
    try:
        from gui.tray_manager import get_tray_manager
        tray = get_tray_manager()
        tray_thread = threading.Thread(target=tray.run, daemon=True)
        tray_thread.start()
    except Exception as e:
        print(f"[WARNING] Tray manager failed (optional): {e}")

    # GUI must run on main thread
    launch()


def run_train():
    """Train model từ CLI."""
    print("=" * 60)
    print("  RANSOMWARE ENTROPY DETECTOR - Model Trainer")
    print("=" * 60)
    from core.dataset_generator import generate_synthetic_dataset
    from core.ml_engine import RansomwareMLEngine, MODEL_PATH

    print("\n[1/2] Generating synthetic dataset...")
    X, y = generate_synthetic_dataset(n_safe=2000, n_encrypted=2000, verbose=True)

    print("\n[2/2] Training Random Forest model...")
    engine = RansomwareMLEngine()
    metrics = engine.train(X, y, verbose=True)

    print(f"\n✓ Model saved to: {MODEL_PATH}")
    print(f"  Accuracy:  {metrics['accuracy']*100:.2f}%")
    print(f"  AUC-ROC:   {metrics['auc_roc']*100:.2f}%")
    print(f"  CV 5-fold: {metrics['cv_mean']*100:.2f}% ± {metrics['cv_std']*100:.2f}%")
    print("=" * 60)


def run_cli_scan(path: str):
    """Quét thư mục từ CLI."""
    import time
    from core.ml_engine import get_engine, MODEL_PATH
    from core.scanner import Scanner
    from core.report_generator import export_csv

    print("=" * 60)
    print("  RANSOMWARE ENTROPY DETECTOR - CLI Scanner")
    print("=" * 60)
    print(f"Target: {path}")

    engine = get_engine()
    if not engine.load_model(MODEL_PATH):
        print("Model not found. Training first...")
        from core.dataset_generator import generate_synthetic_dataset
        X, y = generate_synthetic_dataset(n_safe=1000, n_encrypted=1000)
        engine.train(X, y, verbose=False)

    print(f"ML Engine loaded (Accuracy: {engine.metadata.get('accuracy', 0)*100:.1f}%)\n")

    scanner = Scanner()
    results_holder = []
    start = time.time()

    done_event = __import__("threading").Event()

    def on_progress(done, total, result):
        bar_len = 30
        filled = int(bar_len * done / total)
        bar = "█" * filled + "░" * (bar_len - filled)
        print(f"\r  [{bar}] {done}/{total}", end="", flush=True)

    def on_complete(results):
        results_holder.extend(results)
        done_event.set()

    scanner.scan(path, recursive=True,
                 on_progress=on_progress,
                 on_complete=on_complete)

    done_event.wait()
    elapsed = time.time() - start
    print()

    summary = scanner.get_summary()
    print(f"\n{'='*60}")
    print(f"  RESULTS: {summary['total']} files in {elapsed:.1f}s")
    print(f"  SAFE:     {summary['safe']}")
    print(f"  THREATS:  {summary['encrypted']}")
    print(f"  CRITICAL: {summary['critical']}")
    print(f"  HIGH:     {summary['high']}")
    print(f"  AVG Entropy: {summary['avg_entropy']:.4f} bits/byte")
    print(f"{'='*60}")

    # In threats
    threats = [r for r in results_holder if r.label == 1]
    if threats:
        print("\n⚠  THREATS DETECTED:")
        for r in sorted(threats, key=lambda x: x.probability, reverse=True)[:20]:
            print(f"  [{r.risk_level:8s}] {r.probability*100:5.1f}%  "
                  f"H={r.entropy:.3f}  {r.filename}")

    # Export CSV
    csv_path = os.path.join(os.path.dirname(path) if os.path.isfile(path) else path,
                            "scan_report.csv")
    export_csv(results_holder, csv_path)
    print(f"\n✓ Report saved: {csv_path}")


def run_build_auto_dataset():
    """Build auto-labeled dataset from local evidence, optionally retrain."""
    try:
        from build_auto_dataset import main as build_main
    except ModuleNotFoundError as e:
        return _handle_missing_feature_module("Auto dataset builder", e)

    # Reuse the dedicated CLI parser/logic.
    return build_main()


def run_search_training_sources(argv: list[str] | None = None):
    """Search curated training sample sources."""
    parser = argparse.ArgumentParser(
        description="Search curated training sample sources."
    )
    parser.add_argument("--query", default="", help="Search text, e.g. 'pe malware' or 'benign exe'")
    parser.add_argument(
        "--kind",
        default="both",
        choices=["safe", "encrypted", "both"],
        help="Filter by source kind",
    )
    parser.add_argument(
        "--pe-only",
        action="store_true",
        help="Only show sources suitable for PE-only workflow",
    )
    args = parser.parse_args(argv)

    try:
        from core.training_source_registry import render_training_sources
    except ModuleNotFoundError as e:
        return _handle_missing_feature_module("Training source search", e)

    print("=" * 65)
    print("  TRAINING SOURCE SEARCH")
    print("=" * 65)
    print(
        render_training_sources(
            query=args.query,
            kind=args.kind,
            pe_only=True if args.pe_only else None,
        )
    )
    return 0


def run_plan_training_source(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        description="Create a PE-only training source plan."
    )
    parser.add_argument("--kind", default="both", choices=["safe", "encrypted", "both"])
    parser.add_argument("--scale", default="pilot", choices=["smoke", "pilot", "production"])
    parser.add_argument("--pe-only", action="store_true", default=True)
    args = parser.parse_args(argv)

    try:
        from core.training_source_planner import build_training_source_plan, render_training_plan
    except ModuleNotFoundError as e:
        return _handle_missing_feature_module("Training source planner", e)

    plan = build_training_source_plan(kind=args.kind, pe_only=True, scale=args.scale)
    print("=" * 65)
    print("  TRAINING SOURCE PLAN")
    print("=" * 65)
    print(render_training_plan(plan))
    return 0


def run_training_progress(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        description="Show current progress toward PE-only training targets."
    )
    parser.add_argument("--scale", default="pilot", choices=["smoke", "pilot", "production"])
    args = parser.parse_args(argv)

    try:
        from core.training_progress import get_training_progress, render_training_progress
    except ModuleNotFoundError as e:
        return _handle_missing_feature_module("Training progress view", e)

    progress = get_training_progress(scale=args.scale)
    print("=" * 65)
    print("  TRAINING PROGRESS")
    print("=" * 65)
    print(render_training_progress(progress))
    return 0


def run_download_training_source(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        description="Create manifest and acquisition instructions for a curated training source."
    )
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--kind", required=True, choices=["safe", "encrypted"])
    parser.add_argument("--scale", default="pilot", choices=["smoke", "pilot", "production"])
    args = parser.parse_args(argv)

    try:
        from core.training_source_planner import download_training_source
    except ModuleNotFoundError as e:
        return _handle_missing_feature_module("Training source download", e)

    result = download_training_source(
        source_id=args.source_id,
        kind=args.kind,
        scale=args.scale,
    )
    print("=" * 65)
    print("  DOWNLOAD TRAINING SOURCE")
    print("=" * 65)
    print(f"Source           : {result['source']['name']}")
    print(f"Status           : {result['status']}")
    print(f"Manifest         : {result['manifest_path']}")
    print(f"Source dir       : {result['source_dir']}")
    print(f"Prepare dir      : {result['prepare_dir']}")
    print(f"Access mode      : {result['source']['access_mode']}")
    print(f"URL              : {result['source']['url']}")
    print(f"Next step        : {result['source']['next_step_template']}")
    return 2 if result["status"] == "manual-acquire-required" else 0


def run_prepare_external_pe(argv: list[str] | None = None):
    """Prepare a PE-only folder from a downloaded corpus."""
    parser = argparse.ArgumentParser(
        description="Prepare a PE-only sample folder from a downloaded corpus."
    )
    parser.add_argument("--input-dir", required=True, help="Source corpus directory")
    parser.add_argument("--output-dir", required=True, help="Prepared PE output directory")
    parser.add_argument("--max-files", type=int, default=None, help="Optional limit on copied files")
    parser.add_argument("--move", action="store_true", help="Move files instead of copying them")
    parser.add_argument("--no-recursive", action="store_true", help="Only inspect the top-level directory")
    args = parser.parse_args(argv)

    try:
        from core.pe_corpus_preparer import prepare_pe_samples
    except ModuleNotFoundError as e:
        return _handle_missing_feature_module("External PE preparation", e)

    result = prepare_pe_samples(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        recursive=not args.no_recursive,
        max_files=args.max_files,
        move=args.move,
    )

    print("=" * 65)
    print("  PREPARE EXTERNAL PE SAMPLES")
    print("=" * 65)
    print(f"Input dir        : {result['input_dir']}")
    print(f"Output dir       : {result['output_dir']}")
    print(f"Copied           : {result['copied']}")
    print(f"Non-PE skipped   : {result['non_pe_skipped']}")
    print(f"Duplicates       : {result['duplicate_skipped']}")
    print(f"Errors           : {result['errors']}")
    print(f"Manifest         : {result['manifest_path']}")
    return 0


def run_prepare_training_source(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        description="Prepare a curated PE-only training source into the default prepared layout."
    )
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--kind", required=True, choices=["safe", "encrypted"])
    parser.add_argument("--scale", default="pilot", choices=["smoke", "pilot", "production"])
    parser.add_argument("--move", action="store_true")
    parser.add_argument("--no-recursive", action="store_true")
    args = parser.parse_args(argv)

    try:
        from core.training_source_planner import prepare_training_source
    except ModuleNotFoundError as e:
        return _handle_missing_feature_module("Training source preparation", e)

    result = prepare_training_source(
        source_id=args.source_id,
        kind=args.kind,
        scale=args.scale,
        move=args.move,
        recursive=not args.no_recursive,
    )
    print("=" * 65)
    print("  PREPARE TRAINING SOURCE")
    print("=" * 65)
    if not result["success"]:
        print(f"Status           : {result['status']}")
        print(f"Manifest         : {result['manifest_path']}")
        print(f"Source dir       : {result['source_dir']}")
        print(f"Prepare dir      : {result['prepare_dir']}")
        print(f"Message          : {result['message']}")
        return 2 if result["status"] == "manual-acquire-required" else 1

    prep = result["prepare_result"]
    print(f"Source           : {result['source']['name']}")
    print(f"Prepared copied  : {prep['copied']}")
    print(f"Non-PE skipped   : {prep['non_pe_skipped']}")
    print(f"Duplicates       : {prep['duplicate_skipped']}")
    print(f"Errors           : {prep['errors']}")
    print(f"Manifest         : {result['manifest_path']}")
    return 0


def run_train_external(argv: list[str] | None = None):
    """Train model from external SAFE/ENCRYPTED directories."""
    parser = argparse.ArgumentParser(
        description="Train the model from user-provided SAFE and ENCRYPTED PE folders."
    )
    parser.add_argument("--safe-dir", required=True, help="Directory containing SAFE PE files")
    parser.add_argument("--encrypted-dir", required=True, help="Directory containing ENCRYPTED PE files")
    parser.add_argument(
        "--output-csv",
        default=os.path.join(BASE_DIR, "data", "external_dataset.csv"),
        help="CSV path for the extracted training dataset",
    )
    parser.add_argument(
        "--min-class-samples",
        type=int,
        default=1,
        help="Minimum usable samples required in each class before training (default: 1)",
    )
    parser.add_argument("--no-recursive", action="store_true", help="Only inspect the top-level directories")
    args = parser.parse_args(argv)

    safe_dir = args.safe_dir
    encrypted_dir = args.encrypted_dir

    if not os.path.isdir(safe_dir):
        print(f"SAFE directory not found: {safe_dir}")
        return 1
    if not os.path.isdir(encrypted_dir):
        print(f"ENCRYPTED directory not found: {encrypted_dir}")
        return 1

    output_csv = args.output_csv
    recursive = not args.no_recursive

    try:
        from core.external_dataset_builder import build_external_dataset
    except ModuleNotFoundError as e:
        return _handle_missing_feature_module("External dataset training", e)
    from core.ml_engine import get_engine, MODEL_PATH

    print("=" * 65)
    print("  EXTERNAL DATASET TRAINER")
    print("=" * 65)
    print(f"SAFE dir        : {safe_dir}")
    print(f"ENCRYPTED dir   : {encrypted_dir}")
    print(f"Output CSV      : {output_csv}")
    print(f"Recursive       : {recursive}")
    print("PE-only mode    : True (.exe/.dll/.sys/.msi)")

    dataset = build_external_dataset(
        safe_dir=safe_dir,
        encrypted_dir=encrypted_dir,
        output_csv=output_csv,
        recursive=recursive,
    )

    safe_stats = dataset["safe_stats"]
    enc_stats = dataset["encrypted_stats"]
    print(
        f"\nCollected SAFE       : {dataset['safe_count']} "
        f"(non-PE {safe_stats['non_pe_skipped']}, feature-fail {safe_stats['feature_skipped']}, dup {safe_stats['duplicate_skipped']})"
    )
    print(
        f"Collected ENCRYPTED  : {dataset['encrypted_count']} "
        f"(non-PE {enc_stats['non_pe_skipped']}, feature-fail {enc_stats['feature_skipped']}, dup {enc_stats['duplicate_skipped']})"
    )
    print(f"Conflicting hashes   : {dataset['conflicting_hashes']}")
    print(f"Total usable samples : {dataset['total']}")
    if dataset["skipped_ratio"] > 0.20:
        print(f"Warning: skipped ratio is high ({dataset['skipped_ratio']:.1%}); review source corpora quality.")

    min_class_samples = args.min_class_samples
    if dataset["safe_count"] < 1 or dataset["encrypted_count"] < 1:
        print(
            f"Need at least 1 SAFE and 1 ENCRYPTED sample to train. "
            f"Got: SAFE={dataset['safe_count']}, ENCRYPTED={dataset['encrypted_count']}"
        )
        return 1

    engine = get_engine()
    backup_version = engine._backup_current_model()
    metrics = engine.train(dataset["X"], dataset["y"], model_path=MODEL_PATH, verbose=False)

    print(f"\n✓ External dataset saved to: {output_csv}")
    if backup_version:
        print(f"✓ Previous model backed up as version: {backup_version}")
    print(f"✓ Model saved to: {MODEL_PATH}")
    print(f"  Accuracy:  {metrics['accuracy']*100:.2f}%")
    print(f"  Precision: {metrics['precision']*100:.2f}%")
    print(f"  Recall:    {metrics['recall']*100:.2f}%")
    return 0


def run_train_from_source_plan(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        description="Run prepare + train from the default curated source plan."
    )
    parser.add_argument("--kind", default="both", choices=["safe", "encrypted", "both"])
    parser.add_argument("--scale", default="pilot", choices=["smoke", "pilot", "production"])
    parser.add_argument("--min-class-samples", type=int, default=1)
    args = parser.parse_args(argv)

    try:
        from core.training_source_planner import train_from_source_plan
    except ModuleNotFoundError as e:
        return _handle_missing_feature_module("Training from source plan", e)

    result = train_from_source_plan(
        kind=args.kind,
        scale=args.scale,
        min_class_samples=args.min_class_samples,
    )
    print("=" * 65)
    print("  TRAIN FROM SOURCE PLAN")
    print("=" * 65)
    print(f"Status           : {result['status']}")
    if not result["success"]:
        print(f"Message          : {result['message']}")
        if result["status"] == "manual-acquire-required":
            for item in result["manual_required"]:
                print(f"Needs source     : {item['kind']}::{item['id']} -> {item['source_dir']}")
                print(f"Manifest         : {item['manifest_path']}")
            return 2
        if result.get("dataset"):
            dataset = result["dataset"]
            print(f"Usable SAFE      : {dataset['safe_count']}")
            print(f"Usable ENCRYPTED : {dataset['encrypted_count']}")
        return 1

    metrics = result["metrics"]
    dataset = result["dataset"]
    print(f"Dataset CSV      : {result['output_csv']}")
    print(f"SAFE usable      : {dataset['safe_count']}")
    print(f"ENCRYPTED usable : {dataset['encrypted_count']}")
    if result.get("backup_version"):
        print(f"Backup version   : {result['backup_version']}")
    print(f"Accuracy         : {metrics['accuracy']*100:.2f}%")
    print(f"Precision        : {metrics['precision']*100:.2f}%")
    print(f"Recall           : {metrics['recall']*100:.2f}%")
    return 0


if __name__ == "__main__":
    if "--train" in sys.argv:
        run_train()
    elif "--build-auto-dataset" in sys.argv:
        sys.argv = [sys.argv[0]] + [arg for arg in sys.argv[1:] if arg != "--build-auto-dataset"]
        sys.exit(run_build_auto_dataset())
    elif "--search-training-sources" in sys.argv:
        argv = [arg for arg in sys.argv[1:] if arg != "--search-training-sources"]
        sys.exit(run_search_training_sources(argv))
    elif "--plan-training-source" in sys.argv:
        argv = [arg for arg in sys.argv[1:] if arg != "--plan-training-source"]
        sys.exit(run_plan_training_source(argv))
    elif "--training-progress" in sys.argv:
        argv = [arg for arg in sys.argv[1:] if arg != "--training-progress"]
        sys.exit(run_training_progress(argv))
    elif "--download-training-source" in sys.argv:
        argv = [arg for arg in sys.argv[1:] if arg != "--download-training-source"]
        sys.exit(run_download_training_source(argv))
    elif "--prepare-external-pe" in sys.argv:
        argv = [arg for arg in sys.argv[1:] if arg != "--prepare-external-pe"]
        sys.exit(run_prepare_external_pe(argv))
    elif "--prepare-training-source" in sys.argv:
        argv = [arg for arg in sys.argv[1:] if arg != "--prepare-training-source"]
        sys.exit(run_prepare_training_source(argv))
    elif "--train-external" in sys.argv:
        argv = [arg for arg in sys.argv[1:] if arg != "--train-external"]
        sys.exit(run_train_external(argv))
    elif "--train-from-source-plan" in sys.argv:
        argv = [arg for arg in sys.argv[1:] if arg != "--train-from-source-plan"]
        sys.exit(run_train_from_source_plan(argv))
    elif "--scan" in sys.argv:
        idx = sys.argv.index("--scan")
        if idx + 1 < len(sys.argv):
            run_cli_scan(sys.argv[idx + 1])
        else:
            print("Usage: python main.py --scan PATH")
            sys.exit(1)
    else:
        run_gui()
