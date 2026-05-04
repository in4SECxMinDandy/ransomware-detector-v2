#!/usr/bin/env python3
"""Test fixed CSV reading."""

import csv

csv_path = r"C:\Users\haqua\Documents\GitHub\ransomware-detector-v2\full.csv\full.csv"

print("=" * 60)
print("TEST FIXED CSV READING")
print("=" * 60)

with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
    # Skip comment lines
    while True:
        pos = f.tell()
        line = f.readline()
        if not line or not line.startswith('#'):
            f.seek(pos)
            break
    
    reader = csv.DictReader(f, skipinitialspace=True)
    print(f"Fieldnames: {reader.fieldnames[:5]}...")  # Show first 5
    
    pe_count = 0
    for i, row in enumerate(reader):
        if i >= 1000:
            break
        
        sha_raw = row.get("sha256_hash") or ""
        sha = sha_raw.replace('"', '').replace("'", '').replace(' ', '').strip().lower()
        
        ftype = (row.get("file_type_guess") or "").strip().lower()
        ftype = ftype.replace('"', '').replace("'", '')
        
        mime = (row.get("mime_type") or "").strip().lower()
        mime = mime.replace('"', '').replace("'", '')
        
        sig_raw = row.get("signature") or ""
        sig = sig_raw.strip().replace('"', '')
        
        is_pe = ftype in ("exe", "dll", "sys", "msi") or "x-dosexec" in mime
        is_malware = sig and sig.lower() not in ("n/a", "unknown", "")
        
        if is_pe:
            pe_count += 1
            if pe_count <= 5:
                print(f"\nPE #{pe_count}:")
                print(f"  sha={sha[:20]}... len={len(sha)}")
                print(f"  ftype='{ftype}'")
                print(f"  mime='{mime[:40]}...'")
                print(f"  sig='{sig[:40]}...'")
                print(f"  is_malware={is_malware}")

print(f"\nTotal PE in first 1000 rows: {pe_count}")
