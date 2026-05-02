#!/usr/bin/env python3
"""
collect_safe_samples.py
=======================
Thu thập SAFE PE samples từ Windows system directories để training.

Nguồn dữ liệu thật (benign/safe):
  - C:\\Windows\\System32       (EXE, DLL, SYS)
  - C:\\Windows\\SysWOW64       (EXE, DLL, SYS)
  - C:\\Windows\\System32\\drivers (SYS drivers)
  - C:\\Program Files           (EXE, DLL — tùy chọn)
  - C:\\Program Files (x86)     (EXE, DLL — tùy chọn)

Output: datasets/prepared/external_pe/safe/<sha256>.<ext>

Chạy:
  python collect_safe_samples.py
  python collect_safe_samples.py --max 2000 --include-program-files
  python collect_safe_samples.py --output datasets/prepared/external_pe/safe
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

DEFAULT_OUTPUT = BASE_DIR / "datasets" / "prepared" / "external_pe" / "safe"

# Thư mục nguồn Windows — luôn an toàn, đã ký bởi Microsoft
WINDOWS_SAFE_DIRS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\System32\drivers",
    r"C:\Windows\WinSxS",
]

PROGRAM_FILES_DIRS = [
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]

PE_EXTENSIONS = {".exe", ".dll", ".sys"}


def compute_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect(
    source_dirs: list[str],
    output_dir: Path,
    max_files: int,
    min_size: int,
    max_size: int,
    verbose: bool,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    seen_hashes: set[str] = set()
    # Đọc hash đã tồn tại trong output_dir
    for f in output_dir.iterdir():
        if f.is_file():
            stem = f.stem
            if len(stem) == 64:
                seen_hashes.add(stem)

    copied = 0
    skipped_dup = 0
    skipped_ext = 0
    skipped_size = 0
    errors = 0

    for src_dir in source_dirs:
        if not os.path.isdir(src_dir):
            if verbose:
                print(f"  [skip] {src_dir} — không tồn tại")
            continue

        if verbose:
            print(f"  Scanning: {src_dir}")

        for root, dirs, files in os.walk(src_dir):
            # Bỏ qua WinSxS subdir quá sâu để tiết kiệm thời gian
            dirs[:] = [d for d in dirs if not d.startswith("x86_") and not d.startswith("amd64_")][:50]

            for name in files:
                if copied >= max_files:
                    break
                ext = os.path.splitext(name)[1].lower()
                if ext not in PE_EXTENSIONS:
                    skipped_ext += 1
                    continue

                full_path = os.path.join(root, name)
                try:
                    size = os.path.getsize(full_path)
                    if size < min_size or size > max_size:
                        skipped_size += 1
                        continue

                    sha256 = compute_sha256(full_path)
                    if sha256 in seen_hashes:
                        skipped_dup += 1
                        continue

                    dest = output_dir / f"{sha256}{ext}"
                    shutil.copy2(full_path, dest)
                    seen_hashes.add(sha256)
                    copied += 1

                    if verbose and copied % 100 == 0:
                        print(f"    [{copied}/{max_files}] copied {name}")

                except PermissionError:
                    skipped_ext += 1
                except Exception:
                    errors += 1

            if copied >= max_files:
                break

        if copied >= max_files:
            break

    return {
        "output_dir": str(output_dir),
        "copied": copied,
        "skipped_dup": skipped_dup,
        "skipped_ext": skipped_ext,
        "skipped_size": skipped_size,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Thu thập SAFE PE samples từ Windows system directories."
    )
    parser.add_argument(
        "--output", default=str(DEFAULT_OUTPUT),
        help=f"Thư mục output (default: {DEFAULT_OUTPUT})"
    )
    parser.add_argument(
        "--max", type=int, default=3000,
        help="Số lượng files tối đa cần thu thập (default: 3000)"
    )
    parser.add_argument(
        "--min-size", type=int, default=4096,
        help="Kích thước file tối thiểu bytes (default: 4096 = 4 KB)"
    )
    parser.add_argument(
        "--max-size", type=int, default=50 * 1024 * 1024,
        help="Kích thước file tối đa bytes (default: 50 MB)"
    )
    parser.add_argument(
        "--include-program-files", action="store_true",
        help="Bao gồm C:\\Program Files và C:\\Program Files (x86)"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Không in tiến trình"
    )
    args = parser.parse_args()

    verbose = not args.quiet
    output_dir = Path(args.output)

    source_dirs = list(WINDOWS_SAFE_DIRS)
    if args.include_program_files:
        source_dirs.extend(PROGRAM_FILES_DIRS)

    print("=" * 65)
    print("  SAFE SAMPLES COLLECTOR — Windows PE Files")
    print("=" * 65)
    print(f"  Output dir   : {output_dir}")
    print(f"  Max files    : {args.max}")
    print(f"  Size range   : {args.min_size // 1024} KB – {args.max_size // (1024*1024)} MB")
    print(f"  Sources      : {len(source_dirs)} dirs")
    for d in source_dirs:
        print(f"    - {d}")
    print()

    result = collect(
        source_dirs=source_dirs,
        output_dir=output_dir,
        max_files=args.max,
        min_size=args.min_size,
        max_size=args.max_size,
        verbose=verbose,
    )

    print()
    print("=" * 65)
    print("  KẾT QUẢ")
    print("=" * 65)
    print(f"  Copied       : {result['copied']} files  → {output_dir}")
    print(f"  Skipped dup  : {result['skipped_dup']}")
    print(f"  Skipped ext  : {result['skipped_ext']}")
    print(f"  Skipped size : {result['skipped_size']}")
    print(f"  Errors       : {result['errors']}")
    print()

    if result['copied'] == 0:
        print("  [WARN] Không có file nào được copy!")
        print("  Kiểm tra quyền truy cập vào C:\\Windows\\System32")
        return 1

    print(f"  [OK] {result['copied']} SAFE samples sẵn sàng để training.")
    print(f"  Tiếp theo: python collect_malware_samples.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
