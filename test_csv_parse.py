#!/usr/bin/env python3
"""Test CSV parsing for MalwareBazaar full dump."""

import csv
from pathlib import Path

csv_path = r"C:\Users\haqua\Documents\GitHub\ransomware-detector-v2\full.csv\full.csv"

pe_count = 0
office_count = 0
malware_count = 0

with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    for i, row in enumerate(reader):
        if i >= 100000:  # Only check first 100k rows
            break
            
        sha = (row.get("sha256_hash") or "").strip().lower().replace('"', '').replace("'", '').strip()
        ftype = (row.get("file_type") or row.get("file_type_guess") or "").strip().lower()
        mime = (row.get("file_type_mime") or row.get("mime_type") or "").strip().lower()
        sig = (row.get("signature") or "").strip()
        
        is_pe = (
            ftype in ("exe", "dll", "sys", "msi")
            or "x-dosexec" in mime
        )
        is_office = ftype in ("doc", "docx", "docm", "xls", "xlsx", "xlsm")
        is_malware = sig and sig.lower() not in ("n/a", "unknown", "")
        
        if is_pe and is_malware:
            pe_count += 1
            if pe_count <= 5:
                print(f"PE Malware: {sha[:16]}... | Type: {ftype} | Sig: {sig}")
                
        if is_pe and not is_malware and pe_count <= 10:
            if i % 1000 == 0:  # Sample
                print(f"  (PE non-malware: {ftype} | Sig: {sig})")

print(f"\nFound {pe_count} PE malware in first 100k rows")
