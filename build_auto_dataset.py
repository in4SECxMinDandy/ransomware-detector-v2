#!/usr/bin/env python3
"""
CLI for building an auto-labeled dataset and optionally retraining the model.
"""

import argparse
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build auto-labeled training dataset from local evidence."
    )
    parser.add_argument(
        "--min-confidence",
        default="high",
        choices=["high", "medium", "low"],
        help="Minimum confidence required to include samples.",
    )
    parser.add_argument(
        "--retrain",
        action="store_true",
        help="Retrain the active model after building the dataset.",
    )
    parser.add_argument(
        "--min-total-samples",
        type=int,
        default=1,
        help="Minimum auto-labeled samples required before retraining (default: 1).",
    )
    parser.add_argument(
        "--min-class-samples",
        type=int,
        default=1,
        help="Minimum SAFE and ENCRYPTED samples required before retraining (default: 1).",
    )
    args = parser.parse_args()

    from core.training_dataset_builder import AutoTrainingDatasetBuilder

    builder = AutoTrainingDatasetBuilder()
    result = builder.build_dataset(min_confidence=args.min_confidence)
    counts = result.get("class_counts", {})

    print("=" * 65)
    print("  AUTO-LABELED DATASET BUILDER")
    print("=" * 65)
    print(f"Output CSV         : {result.get('output_path')}")
    print(f"Collected samples  : {result.get('total_collected')}")
    print(f"Deduped samples    : {result.get('deduped_samples')}")
    print(f"Usable samples     : {result.get('usable_samples')}")
    print(f"SAFE samples       : {counts.get('SAFE', 0)}")
    print(f"ENCRYPTED samples  : {counts.get('ENCRYPTED', 0)}")

    if not args.retrain:
        print("\nDataset build complete. Use --retrain to train the model too.")
        return 0

    from core.ml_engine import get_engine

    engine = get_engine()
    retrain = engine.retrain_with_auto_dataset(
        min_confidence=args.min_confidence,
        min_total_samples=args.min_total_samples,
        min_class_samples=args.min_class_samples,
    )

    if not retrain.get("success"):
        print(f"\nRetrain skipped/failed: {retrain.get('error')}")
        return 1

    print("\nRetrain complete")
    print(f"New version        : {retrain.get('new_model_version')}")
    print(f"Auto samples used  : {retrain.get('auto_samples_used')}")
    print(f"Training samples   : {retrain.get('total_training_samples')}")
    print(f"New accuracy       : {retrain.get('new_accuracy', 0):.2%}")
    print(f"New precision      : {retrain.get('new_precision', 0):.2%}")
    print(f"New recall         : {retrain.get('new_recall', 0):.2%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
