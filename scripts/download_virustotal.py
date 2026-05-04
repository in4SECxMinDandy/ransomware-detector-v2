#!/usr/bin/env python3
"""
download_virustotal.py
======================
Tải malware samples từ VirusTotal API.
Cần API key trong data/config.json

Usage:
    python scripts/download_virustotal.py --limit 100 --output datasets/sources/encrypted/virustotal
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

import httpx

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.config_manager import config

VT_API_BASE = "https://www.virustotal.com/api/v3"
USER_AGENT = "RansomwareDetector/2.5"


def _get_vt_api_key() -> str:
    """Read VT API key from config."""
    return config.get("virustotal.api_key", "")


def _build_session() -> httpx.Client:
    api_key = _get_vt_api_key()
    if not api_key:
        raise ValueError("VirusTotal API key not found in config!")
    return httpx.Client(
        headers={
            "User-Agent": USER_AGENT,
            "x-apikey": api_key,
            "Accept": "application/json",
        },
        timeout=httpx.Timeout(60.0, connect=15.0),
    )


class VirusTotalDownloader:
    def __init__(self, output_dir: str, limit: int = 100, rate_limit: float = 4.0):
        self.output_dir = Path(output_dir).absolute()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.limit = limit
        self.rate_limit = rate_limit
        self._last_request_time = 0.0
        self.session = _build_session()
        
        self.progress_file = self.output_dir / "_vt_progress.json"
        self.progress = self._load_progress()
        
    def _load_progress(self) -> Dict:
        if self.progress_file.exists():
            try:
                return json.loads(self.progress_file.read_text())
            except Exception:
                pass
        return {"downloaded": [], "failed": [], "stats": {"pe": 0, "office": 0, "other": 0}}
    
    def _save_progress(self):
        self.progress_file.write_text(json.dumps(self.progress, indent=2))
    
    def _rate_limit_wait(self):
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()
    
    def search_ransomware_samples(self) -> List[str]:
        """Search for recent ransomware samples."""
        self._rate_limit_wait()
        
        # Search for ransomware detections
        search_terms = [
            "ransomware",
            "lockbit", 
            "blackcat",
            "trojan",
            "malware",
        ]
        
        hashes = []
        seen = set(self.progress.get("downloaded", [])) | set(self.progress.get("failed", []))
        
        for term in search_terms:
            if len(hashes) >= self.limit:
                break
                
            try:
                r = self.session.get(
                    f"{VT_API_BASE}/search",
                    params={
                        "query": f"type:pe32 detection:{term} positives:10+",
                        "limit": min(100, self.limit - len(hashes))
                    }
                )
                data = r.json()
                
                for item in data.get("data", []):
                    sha256 = item.get("attributes", {}).get("sha256", "")
                    if sha256 and sha256 not in seen:
                        hashes.append(sha256)
                        seen.add(sha256)
                        
                print(f"  [Search: {term}] Found {len(data.get('data', []))} samples")
                
            except Exception as e:
                print(f"  [!] Search error for '{term}': {e}")
                
            time.sleep(self.rate_limit)
        
        return hashes[:self.limit]
    
    def download_sample(self, sha256: str) -> bool:
        """Download a sample from VT."""
        if sha256 in self.progress.get("downloaded", []) or sha256 in self.progress.get("failed", []):
            return False
            
        self._rate_limit_wait()
        
        try:
            # Check file report first
            r = self.session.get(f"{VT_API_BASE}/files/{sha256}")
            if r.status_code != 200:
                self.progress.setdefault("failed", []).append(sha256)
                return False
            
            data = r.json()
            attrs = data.get("data", {}).get("attributes", {})
            file_type = attrs.get("type_description", "").lower()
            
            # Only download PE files
            if "pe" not in file_type and "win32" not in file_type:
                print(f"  Skipping {sha256[:16]} (not PE: {file_type})")
                return False
            
            # Download file
            self._rate_limit_wait()
            r = self.session.get(f"{VT_API_BASE}/files/{sha256}/download")
            if r.status_code != 200:
                self.progress.setdefault("failed", []).append(sha256)
                return False
            
            content = r.content
            ext = ".exe" if "exe" in file_type else ".dll" if "dll" in file_type else ".bin"
            file_hash = hashlib.sha256(content).hexdigest()
            out_path = self.output_dir / f"{file_hash}{ext}"
            
            out_path.write_bytes(content)
            self.progress.setdefault("downloaded", []).append(sha256)
            self.progress["stats"]["pe"] += 1
            self._save_progress()
            
            return True
            
        except Exception as e:
            print(f"  [!] Download error for {sha256[:16]}: {e}")
            self.progress.setdefault("failed", []).append(sha256)
            return False
    
    def run(self):
        print("=" * 60)
        print("  VirusTotal Malware Downloader")
        print(f"  Output: {self.output_dir}")
        print(f"  Limit: {self.limit} samples")
        print("=" * 60)
        
        print("\n[1/2] Searching for ransomware samples...")
        hashes = self.search_ransomware_samples()
        print(f"  Found {len(hashes)} unique hashes")
        
        if not hashes:
            print("  No samples found. Check API key or rate limits.")
            return
        
        print(f"\n[2/2] Downloading samples...")
        downloaded = 0
        for i, sha in enumerate(hashes, 1):
            if self.download_sample(sha):
                downloaded += 1
                print(f"  [{i}/{len(hashes)}] Downloaded {sha[:16]}...")
            else:
                print(f"  [{i}/{len(hashes)}] Skipped {sha[:16]}...")
        
        print(f"\n{'=' * 60}")
        print(f"  FINISHED")
        print(f"  Downloaded: {downloaded}/{len(hashes)}")
        print(f"  Failed: {len(self.progress.get('failed', []))}")
        print(f"  Output: {self.output_dir}")
        print(f"{'=' * 60}")
    
    def close(self):
        self.session.close()


def main():
    parser = argparse.ArgumentParser(description="Download malware from VirusTotal")
    parser.add_argument("--limit", type=int, default=50, help="Max samples to download")
    parser.add_argument("--output", default="datasets/sources/encrypted/virustotal", 
                        help="Output directory")
    parser.add_argument("--rate-limit", type=float, default=15.0,
                        help="Seconds between requests (VT free: 4 req/min = 15s)")
    
    args = parser.parse_args()
    
    downloader = VirusTotalDownloader(
        output_dir=args.output,
        limit=args.limit,
        rate_limit=args.rate_limit
    )
    
    try:
        downloader.run()
    except KeyboardInterrupt:
        print("\n\nInterrupted.")
    finally:
        downloader.close()


if __name__ == "__main__":
    main()
