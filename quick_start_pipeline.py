#!/usr/bin/env python3
"""
Quick start script to run the MalwareBazaar pipeline.
Run this after activating the virtual environment.
"""
import subprocess
import sys

def main():
    print("=" * 60)
    print("  RANSOMWARE DETECTOR - Pipeline Quick Start")
    print("=" * 60)
    print()
    print("Options:")
    print("  1. Download 5GB + Train (Full)")
    print("  2. Download 1GB + Train (Test)")
    print("  3. Train with synthetic data only (No download)")
    print("  4. Skip download, train from existing files")
    print()
    
    choice = input("Select option (1-4): ").strip()
    
    if choice == "1":
        cmd = [
            sys.executable, "scripts/pipeline_download_and_train.py",
            "--total-size-gb", "5",
            "--pe-ratio", "0.7",
            "--rate-limit", "1.0"
        ]
    elif choice == "2":
        cmd = [
            sys.executable, "scripts/pipeline_download_and_train.py",
            "--total-size-gb", "1",
            "--pe-ratio", "0.7",
            "--rate-limit", "1.0"
        ]
    elif choice == "3":
        cmd = [
            sys.executable, "scripts/pipeline_download_and_train.py",
            "--train-synthetic"
        ]
    elif choice == "4":
        cmd = [
            sys.executable, "scripts/pipeline_download_and_train.py",
            "--skip-download"
        ]
    else:
        print("Invalid option. Exiting.")
        return
    
    print()
    print("Running:", " ".join(cmd))
    print("=" * 60)
    print()
    
    subprocess.run(cmd, cwd=".")

if __name__ == "__main__":
    main()
