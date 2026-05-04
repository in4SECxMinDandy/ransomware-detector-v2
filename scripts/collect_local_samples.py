#!/usr/bin/env python3
"""
collect_local_samples.py
=======================
Thu thập file PE thực tế từ hệ thống (System32, SysWOW64, Program Files)
để tạo dataset "SAFE" và dùng mã hóa AES tạo "ENCRYPTED".

An toàn - không tải malware từ internet.

Usage:
    python scripts/collect_local_samples.py --output datasets/sources/local_pe/ --limit 500
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
from pathlib import Path
from typing import List, Tuple

# Paths to scan for PE files
DEFAULT_SCAN_PATHS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\WinSxS",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]


def is_pe_file(path: Path) -> bool:
    """Check if file is a valid PE file by magic bytes."""
    try:
        with open(path, "rb") as f:
            magic = f.read(2)
        return magic == b"MZ"
    except Exception:
        return False


def collect_pe_files(
    scan_paths: List[str],
    limit: int = 500,
    max_size_mb: int = 50,
    min_size_kb: int = 10,
) -> List[Path]:
    """Collect PE files from system directories."""
    collected = []
    max_size = max_size_mb * 1024 * 1024
    min_size = min_size_kb * 1024
    
    print(f"[Scan] Searching PE files in {len(scan_paths)} directories...")
    
    for scan_path in scan_paths:
        if not os.path.exists(scan_path):
            print(f"  Skip (not found): {scan_path}")
            continue
            
        print(f"  Scanning: {scan_path}")
        
        for root, dirs, files in os.walk(scan_path):
            # Skip hidden/special dirs
            dirs[:] = [d for d in dirs if not d.startswith(".") and "$" not in d]
            
            for fname in files:
                if not fname.lower().endswith((".exe", ".dll", ".sys")):
                    continue
                    
                fpath = Path(root) / fname
                
                try:
                    size = fpath.stat().st_size
                    if size < min_size or size > max_size:
                        continue
                        
                    if not is_pe_file(fpath):
                        continue
                        
                    collected.append(fpath)
                    
                    if len(collected) >= limit:
                        break
                        
                except (PermissionError, OSError):
                    continue
                    
            if len(collected) >= limit:
                break
                
        if len(collected) >= limit:
            break
    
    return collected


def copy_samples(files: List[Path], output_dir: Path, prefix: str = "safe") -> Tuple[int, int]:
    """Copy samples to output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    copied = 0
    total_size = 0
    
    for i, src in enumerate(files, 1):
        try:
            content = src.read_bytes()
            file_hash = hashlib.sha256(content).hexdigest()[:16]
            ext = src.suffix
            dst = output_dir / f"{prefix}_{i:04d}_{file_hash}{ext}"
            dst.write_bytes(content)
            copied += 1
            total_size += len(content)
            print(f"  [{i}/{len(files)}] {src.name} -> {dst.name} ({len(content):,} bytes)")
        except Exception as e:
            print(f"  [{i}/{len(files)}] ERROR: {src.name} - {e}")
    
    return copied, total_size


def main():
    parser = argparse.ArgumentParser(description="Collect local PE files for training")
    parser.add_argument("--output", default="datasets/sources/local_pe", 
                        help="Output directory")
    parser.add_argument("--limit", type=int, default=500,
                        help="Max files to collect")
    parser.add_argument("--max-size-mb", type=int, default=50,
                        help="Max file size in MB")
    parser.add_argument("--min-size-kb", type=int, default=10,
                        help="Min file size in KB")
    parser.add_argument("--scan-paths", nargs="+", default=DEFAULT_SCAN_PATHS,
                        help="Directories to scan")
    
    args = parser.parse_args()
    
    output_dir = Path(args.output).absolute()
    
    print("=" * 60)
    print("  Local PE Sample Collector")
    print(f"  Output: {output_dir}")
    print(f"  Limit: {args.limit} files")
    print(f"  Size: {args.min_size_kb}KB - {args.max_size_mb}MB")
    print("=" * 60)
    
    files = collect_pe_files(
        args.scan_paths,
        limit=args.limit,
        max_size_mb=args.max_size_mb,
        min_size_kb=args.min_size_kb,
    )
    
    print(f"\n[Found] {len(files)} PE files")
    
    if not files:
        print("No files found!")
        sys.exit(1)
    
    copied, total_size = copy_samples(files, output_dir, prefix="safe")
    
    print(f"\n{'=' * 60}")
    print(f"  FINISHED")
    print(f"  Copied: {copied}/{len(files)}")
    print(f"  Total size: {total_size / 1e6:.2f} MB")
    print(f"  Output: {output_dir}")
    print(f"\n  Next step: Prepare encrypted versions")
    print(f"    python main.py --prepare-external-pe --input-dir {output_dir}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
