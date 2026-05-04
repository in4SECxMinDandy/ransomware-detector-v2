#!/usr/bin/env python3
"""Debug CSV parsing - chi tiết từng dòng."""

import csv

csv_path = r"C:\Users\haqua\Documents\GitHub\ransomware-detector-v2\full.csv\full.csv"

print("=" * 60)
print("DEBUG CSV PARSING")
print("=" * 60)

with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
    # Skip comment lines
    line_num = 0
    for line in f:
        line_num += 1
        if line_num <= 10:
            print(f"Line {line_num}: {line[:100]}...")
        if not line.startswith("#"):
            break
    
    # Now read as CSV
    f.seek(0)
    reader = csv.DictReader(f)
    
    print("\n--- Column names ---")
    print(reader.fieldnames)
    
    print("\n--- First 5 data rows ---")
    for i, row in enumerate(reader):
        if i >= 5:
            break
        
        sha = row.get("sha256_hash", "N/A")
        ftype = row.get("file_type_guess", "N/A")
        mime = row.get("mime_type", "N/A")
        sig = row.get("signature", "N/A")
        
        print(f"\nRow {i+1}:")
        print(f"  sha256_hash: {sha}")
        print(f"  file_type_guess: {ftype}")
        print(f"  mime_type: {mime}")
        print(f"  signature: {sig}")
        
        # Check conditions
        sha_clean = sha.strip().lower().replace('"', '').replace("'", '').strip()
        is_pe = ftype.lower() in ("exe", "dll", "sys", "msi") or "x-dosexec" in mime.lower()
        is_malware = sig and sig.strip() and sig.lower() not in ("n/a", "unknown", "")
        
        print(f"  -> sha_clean len={len(sha_clean)}, is_pe={is_pe}, is_malware={is_malware}")

print("\n--- Count check (first 1000 rows) ---")
with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    pe_total = 0
    pe_malware = 0
    
    for i, row in enumerate(reader):
        if i >= 1000:
            break
        
        sha = (row.get("sha256_hash") or "").strip().lower().replace('"', '').replace("'", '').strip()
        ftype = (row.get("file_type_guess") or "").strip().lower()
        mime = (row.get("mime_type") or "").strip().lower()
        sig = (row.get("signature") or "").strip()
        
        is_pe = ftype in ("exe", "dll", "sys", "msi") or "x-dosexec" in mime
        is_malware = sig and sig.lower() not in ("n/a", "unknown", "")
        
        if is_pe:
            pe_total += 1
            if is_malware:
                pe_malware += 1

print(f"Total PE rows: {pe_total}")
print(f"PE with malware signature: {pe_malware}")
