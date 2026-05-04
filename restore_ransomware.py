#!/usr/bin/env python3
"""
restore_ransomware.py
=====================
Re-download specific ransomware samples from MalwareBazaar using known hashes.
"""

import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    print("[ERROR] Thiếu thư viện 'requests'. Chạy: pip install requests")
    sys.exit(1)

# Fix Windows terminal encoding
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent
MALWARE_DIR = BASE_DIR / "datasets" / "prepared" / "external_pe" / "encrypted"
RANSOMWARE_LIST = BASE_DIR / "ransomware_files.txt"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"

def download_sample(sha256: str, output_dir: Path, api_key: str) -> bool:
    """Download a single sample from MalwareBazaar."""
    payload = {"query": "get_file", "sha256_hash": sha256}
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Auth-Key": api_key
    }
    
    try:
        resp = requests.post(MALWAREBAZAAR_API, data=payload, headers=headers, timeout=60)
        resp.raise_for_status()
        
        raw = resp.content
        if len(raw) < 100:
            return False
        
        # Check if it's a ZIP file
        if raw[:4] != b"PK\x03\x04":
            return False
        
        # Try to unzip
        try:
            import pyzipper
            import io
            buf = io.BytesIO(raw)
            zf = pyzipper.AESZipFile(buf)
            zf.setpassword(b"infected")
            for name in zf.namelist():
                file_data = zf.read(name)
                if len(file_data) >= 64 and file_data[:2] == b"MZ":
                    actual_sha256 = sha256  # Trust the input hash
                    dest = output_dir / f"{actual_sha256}.exe"
                    with open(dest, "wb") as f:
                        f.write(file_data)
                    return True
        except Exception:
            pass
        
        # Fallback to standard zipfile
        try:
            import zipfile
            import io
            buf = io.BytesIO(raw)
            zf = zipfile.ZipFile(buf)
            for name in zf.namelist():
                try:
                    file_data = zf.read(name, pwd=b"infected")
                except:
                    file_data = zf.read(name)
                
                if len(file_data) >= 64 and file_data[:2] == b"MZ":
                    actual_sha256 = sha256
                    dest = output_dir / f"{actual_sha256}.exe"
                    with open(dest, "wb") as f:
                        f.write(file_data)
                    return True
        except Exception:
            pass
        
        return False
    except Exception as e:
        print(f"    [error] {sha256[:16]}... {e}")
        return False

def main():
    api_key = "2bab689e13c4f38ac848081d6848a9cf07eb4c824bcc2da5"
    
    if not RANSOMWARE_LIST.exists():
        print(f"[ERROR] Không tìm thấy {RANSOMWARE_LIST}")
        return 1
    
    MALWARE_DIR.mkdir(parents=True, exist_ok=True)
    
    # Read ransomware hashes
    with open(RANSOMWARE_LIST, "r", encoding="utf-8") as f:
        ransomware_hashes = []
        for line in f:
            line = line.strip()
            if line:
                # Remove .exe extension if present
                if line.endswith(".exe"):
                    line = line[:-4]
                ransomware_hashes.append(line)
    
    print(f"=" * 65)
    print(f"  RESTORE RANSOMWARE SAMPLES")
    print(f"=" * 65)
    print(f"  Output dir        : {MALWARE_DIR}")
    print(f"  Ransomware list   : {RANSOMWARE_LIST}")
    print(f"  Samples to restore: {len(ransomware_hashes)}")
    print()
    
    success_count = 0
    fail_count = 0
    
    for i, sha256 in enumerate(ransomware_hashes, 1):
        print(f"[{i}/{len(ransomware_hashes)}] Downloading {sha256[:16]}...", end=" ")
        
        if download_sample(sha256, MALWARE_DIR, api_key):
            print("✓ OK")
            success_count += 1
        else:
            print("✗ FAILED")
            fail_count += 1
        
        time.sleep(1)  # Rate limiting
    
    print()
    print(f"=" * 65)
    print(f"  KẾT QUẢ")
    print(f"=" * 65)
    print(f"  Thành công       : {success_count}")
    print(f"  Thất bại         : {fail_count}")
    print(f"  Tổng             : {len(ransomware_hashes)}")
    print()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
