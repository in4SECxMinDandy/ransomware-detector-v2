#!/usr/bin/env python3
"""
Ransomware Entropy Detector v1.0
=================================
Entry point - Khởi chạy ứng dụng Desktop.

Usage:
    python main.py              # Khởi chạy GUI
    python main.py --train      # Chỉ train model, không mở GUI
    python main.py --scan PATH  # CLI scan (không GUI)

Author: PTIT Security Research Lab
"""

import sys
import os

# Đảm bảo import path chính xác
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)


def run_gui():
    """Khởi chạy giao diện GUI."""
    from gui.main_window import launch
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


if __name__ == "__main__":
    if "--train" in sys.argv:
        run_train()
    elif "--scan" in sys.argv:
        idx = sys.argv.index("--scan")
        if idx + 1 < len(sys.argv):
            run_cli_scan(sys.argv[idx + 1])
        else:
            print("Usage: python main.py --scan PATH")
            sys.exit(1)
    else:
        run_gui()
