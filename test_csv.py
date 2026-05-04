#!/usr/bin/env python3
"""Test CSV file exists and can be read."""

import csv
from pathlib import Path

csv_path = r"C:\Users\haqua\Documents\GitHub\ransomware-detector-v2\full.csv\full.csv"

print(f"Checking: {csv_path}")
print(f"Exists: {Path(csv_path).exists()}")
print(f"Size: {Path(csv_path).stat().st_size / 1e6:.1f} MB")

# Read first few lines
with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
    reader = csv.DictReader(f)
    for i, row in enumerate(reader):
        if i >= 3:
            break
        print(f"\nRow {i+1}:")
        print(f"  sha256: {row.get('sha256_hash', 'N/A')[:20]}...")
        print(f"  file_type: {row.get('file_type', 'N/A')}")
        print(f"  signature: {row.get('signature', 'N/A')[:50]}...")
        print(f"  tags: {row.get('tags', 'N/A')[:50]}...")
