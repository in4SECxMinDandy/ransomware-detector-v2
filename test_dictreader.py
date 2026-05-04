#!/usr/bin/env python3
"""Test DictReader với CSV có comment lines."""

import csv

csv_path = r"C:\Users\haqua\Documents\GitHub\ransomware-detector-v2\full.csv\full.csv"

print("=" * 60)
print("TEST DICTREADER")
print("=" * 60)

# Method 1: Đọc trực tiếp (có comment lines)
print("\n--- Method 1: Direct read ---")
with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    print(f"Fieldnames: {reader.fieldnames}")
    for i, row in enumerate(reader):
        if i >= 3:
            break
        print(f"\nRow {i}:")
        for k, v in row.items():
            print(f"  {k}: {v[:50] if v else 'EMPTY'}")

# Method 2: Skip comment lines trước
print("\n--- Method 2: Skip comments first ---")
with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
    # Skip all lines starting with #
    while True:
        pos = f.tell()
        line = f.readline()
        if not line.startswith('#'):
            f.seek(pos)
            break
    
    reader = csv.DictReader(f)
    print(f"Fieldnames: {reader.fieldnames}")
    for i, row in enumerate(reader):
        if i >= 3:
            break
        print(f"\nRow {i}:")
        sha = row.get("sha256_hash", "N/A")
        ftype = row.get("file_type_guess", "N/A")
        mime = row.get("mime_type", "N/A")
        sig = row.get("signature", "N/A")
        print(f"  sha256: {sha}")
        print(f"  file_type_guess: {ftype}")
        print(f"  mime_type: {mime}")
        print(f"  signature: {sig}")
