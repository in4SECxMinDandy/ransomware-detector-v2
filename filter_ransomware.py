#!/usr/bin/env python3
"""
filter_ransomware.py
====================
Filter dataset để chỉ giữ lại confirmed ransomware samples.

Sử dụng danh sách ransomware_files.txt để xác định các files cần giữ.
"""

import sys
from pathlib import Path

# Fix Windows terminal encoding
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent
MALWARE_DIR = BASE_DIR / "datasets" / "prepared" / "external_pe" / "encrypted"
RANSOMWARE_LIST = BASE_DIR / "ransomware_files.txt"

def main():
    if not RANSOMWARE_LIST.exists():
        print(f"[ERROR] Không tìm thấy {RANSOMWARE_LIST}")
        return 1
    
    if not MALWARE_DIR.exists():
        print(f"[ERROR] Không tìm thấy {MALWARE_DIR}")
        return 1
    
    # Đọc danh sách ransomware hashes
    with open(RANSOMWARE_LIST, "r", encoding="utf-8") as f:
        ransomware_hashes = set()
        for line in f:
            line = line.strip()
            if line:
                # Remove .exe extension if present
                if line.endswith(".exe"):
                    line = line[:-4]
                ransomware_hashes.add(line)
    
    print(f"=" * 65)
    print(f"  RANSOMWARE DATASET FILTER")
    print(f"=" * 65)
    print(f"  Malware dir        : {MALWARE_DIR}")
    print(f"  Ransomware list    : {RANSOMWARE_LIST}")
    print(f"  Confirmed ransom   : {len(ransomware_hashes)}")
    print()
    
    # Lấy danh sách tất cả files
    all_files = list(MALWARE_DIR.glob("*.exe"))
    print(f"  Total files        : {len(all_files)}")
    print()
    
    # Filter
    kept_count = 0
    deleted_count = 0
    
    for file_path in all_files:
        sha256 = file_path.stem
        if sha256 in ransomware_hashes:
            kept_count += 1
            print(f"  KEEP  {sha256[:16]}... (ransomware)")
        else:
            file_path.unlink()
            deleted_count += 1
            print(f"  DEL   {sha256[:16]}... (non-ransomware)")
    
    print()
    print(f"=" * 65)
    print(f"  KẾT QUẢ")
    print(f"=" * 65)
    print(f"  Đã giữ lại        : {kept_count} ransomware samples")
    print(f"  Đã xóa            : {deleted_count} non-ransomware samples")
    print(f"  Còn lại           : {kept_count} files trong {MALWARE_DIR}")
    print()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
