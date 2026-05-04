#!/usr/bin/env python3
"""
pipeline_download_and_train.py
===============================
Tu dong tai malware samples + training ML model.

Pipeline:
  1. Query MalwareBazaar API theo tag ransomware (khong can Auth-Key)
  2. Loc hash PE (70%) + Office (30%)
  3. Tai samples qua MalwareBazaar API (download_file)
  4. Dung lai khi dat target GB
  5. Prepare PE features
  6. Train model

Usage:
  python scripts/pipeline_download_and_train.py --total-size-gb 5 --pe-ratio 0.7
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional, Set

# Fix sys.path ─ cho phep import core.* khi chay tu bat ky thu muc nao
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import httpx

try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False

MB_API_V1 = "https://mb-api.abuse.ch/api/v1/"
USER_AGENT = "RansomwareDetector/2.5 (research)"
ZIP_PASSWORD = b"infected"

def _get_mb_api_key() -> str:
    """Read MalwareBazaar API key from config."""
    try:
        from core.config_manager import config
        return config.get("threat_intel.malwarebazaar.api_key", "")
    except Exception:
        return ""

PE_EXT = {".exe", ".dll", ".sys", ".msi"}
OFFICE_EXT = {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm"}
OFFICE_FT = {"doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm"}
OFFICE_MIME = ["msword", "openxmlformats-officedocument", "ms-excel", "ms-powerpoint"]

# Ransomware tags & families
RANSOM_TAGS = [
    "ransomware", "lockbit", "blackcat", "conti", "revil", "ryuk", "wannacry",
    "dharma", "phobos", "stop", "makop", "maze", "clop", "darkside", "akira",
    "blackbasta", "hive", "royal", "medusa", "play", "bianlian", "cuba",
    "ragnar", "babuk", "avos", "trigona", "blackmatter", "alphv",
]

OFFICE_TAGS = [
    "emotet", "trickbot", "dridex", "agenttesla", "formbook", "remcos",
    "njrat", "asyncrat", "nanocore", "qbot", "icedid", "bumblebee",
]


def _file_category(ext: str) -> str:
    ext = ext.lower()
    if ext in PE_EXT:
        return "pe"
    if ext in OFFICE_EXT:
        return "office"
    return "other"


def _rate_limit(rate: float, last: float) -> float:
    elapsed = time.time() - last
    if elapsed < rate:
        time.sleep(rate - elapsed)
    return time.time()


def _extract_zip(zip_bytes: BytesIO, password: bytes) -> Optional[tuple]:
    """Giai nen ZIP voi AES support (pyzipper) va fallback zipfile.
    Tra ve (filename, content) hoac None."""
    # Thu pyzipper truoc (ho tro AES128/AES256)
    if HAS_PYZIPPER:
        try:
            with pyzipper.AESZipFile(zip_bytes) as zf:
                zf.setpassword(password)
                for name in zf.namelist():
                    info = zf.getinfo(name)
                    if info.is_dir():
                        continue
                    try:
                        content = zf.read(name)
                        return name, content
                    except Exception:
                        continue
        except Exception:
            pass

    # Fallback: standard zipfile
    zip_bytes.seek(0)
    try:
        with zipfile.ZipFile(zip_bytes) as zf:
            for name in zf.namelist():
                info = zf.getinfo(name)
                if info.is_dir():
                    continue
                try:
                    content = zf.read(name, pwd=password)
                    return name, content
                except Exception:
                    try:
                        content = zf.read(name)
                        return name, content
                    except Exception:
                        continue
    except Exception:
        pass

    return None


class Pipeline:
    def __init__(self, args: argparse.Namespace):
        self.total_bytes = int(args.total_size_gb * 1e9)
        self.pe_bytes = int(self.total_bytes * args.pe_ratio)
        self.of_bytes = self.total_bytes - self.pe_bytes
        self.rate = args.rate_limit
        self.data_dir = Path(args.output).absolute()
        self.pe_dir = self.data_dir / "pe"
        self.of_dir = self.data_dir / "office"
        self.progress_file = self.data_dir / "_pipeline_progress.json"
        self.pe_dir.mkdir(parents=True, exist_ok=True)
        self.of_dir.mkdir(parents=True, exist_ok=True)

        self.session = httpx.Client(
            headers={"User-Agent": USER_AGENT},
            timeout=httpx.Timeout(120.0, connect=20.0),
        )
        self._last = 0.0

        p = self._load_progress()
        self.pe_bytes_done = p.get("pe_bytes_done", 0)
        self.of_bytes_done = p.get("of_bytes_done", 0)
        self.downloaded: Set[str] = set(p.get("downloaded_hashes", []))
        self.failed: Set[str] = set(p.get("failed_hashes", []))
        self.tags_done: Set[str] = set(p.get("tags_done", []))

    def _load_progress(self) -> Dict:
        if self.progress_file.exists():
            try:
                return json.loads(self.progress_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {
            "pe_bytes_done": 0, "of_bytes_done": 0,
            "downloaded_hashes": [], "failed_hashes": [], "tags_done": [],
        }

    def _save(self):
        self.progress_file.write_text(json.dumps({
            "pe_bytes_done": self.pe_bytes_done,
            "of_bytes_done": self.of_bytes_done,
            "downloaded_hashes": list(self.downloaded),
            "failed_hashes": list(self.failed),
            "tags_done": list(self.tags_done),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2), encoding="utf-8")

    def _gb(self, b: int) -> str:
        return f"{b / 1e9:.2f} GB"

    def done(self) -> bool:
        return self.pe_bytes_done >= self.pe_bytes and self.of_bytes_done >= self.of_bytes

    def pe_done(self) -> bool:
        return self.pe_bytes_done >= self.pe_bytes

    def of_done(self) -> bool:
        return self.of_bytes_done >= self.of_bytes

    # ── Step 1: Query hashes theo tag ─────────────────────────

    def _query_tag(self, tag: str) -> List[str]:
        """Tra ve danh sach sha256 cho 1 tag (max 1000 per query)."""
        try:
            self._last = _rate_limit(self.rate, self._last)
            data = {"query": "get_taginfo", "tag": tag, "limit": 1000}
            api_key = _get_mb_api_key()
            if api_key:
                data["API-KEY"] = api_key
            r = self.session.post(MB_API_V1, data=data)
            data = r.json()
            if data.get("query_status") == "ok" and data.get("data"):
                return [e["sha256_hash"] for e in data["data"] if e.get("sha256_hash")]
        except Exception as e:
            print(f"    Tag query error ({tag}): {e}")
        return []

    def _query_filetype(self, filetype: str) -> List[str]:
        """Tra ve danh sach sha256 cho file_type (exe, dll...) co ransomware."""
        try:
            self._last = _rate_limit(self.rate, self._last)
            data = {"query": "get_filetype", "file_type": filetype, "limit": 1000}
            api_key = _get_mb_api_key()
            if api_key:
                data["API-KEY"] = api_key
            r = self.session.post(MB_API_V1, data=data)
            data = r.json()
            if data.get("query_status") == "ok" and data.get("data"):
                return [e["sha256_hash"] for e in data["data"]
                        if e.get("sha256_hash") and e.get("signature")]
        except Exception as e:
            print(f"    Filetype query error ({filetype}): {e}")
        return []

    def collect_hashes(self) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {"pe": [], "office": []}
        seen: Set[str] = self.downloaded | self.failed

        print(f"\n[Step 1/3] Collecting ransomware hashes from MalwareBazaar API...")

        # PE: query theo ransomware tags
        if not self.pe_done():
            print(f"  Querying ransomware tags for PE samples...")
            for tag in RANSOM_TAGS:
                if self.pe_done() or tag in self.tags_done:
                    continue
                hashes = self._query_tag(tag)
                new_h = [h for h in hashes if h not in seen]
                if new_h:
                    result["pe"].extend(new_h)
                    seen.update(new_h)
                # Chỉ đánh dấu done nếu query thành công (có hoặc không có hash)
                # để tránh query lại tag lỗi liên tục
                if hashes is not None:
                    self.tags_done.add(tag)
                print(f"    [{tag}] {len(new_h)} new hashes (total PE: {len(result['pe'])}, API returned {len(hashes) if hashes else 0})")
                if len(result["pe"]) >= 10000:
                    break

            # Them tu filetype queries neu chua du
            if len(result["pe"]) < 2000:
                for ft in ["exe", "dll"]:
                    if self.pe_done():
                        break
                    hashes = self._query_filetype(ft)
                    new_h = [h for h in hashes if h not in seen]
                    result["pe"].extend(new_h)
                    seen.update(new_h)
                    print(f"    [filetype:{ft}] {len(new_h)} new hashes (total PE: {len(result['pe'])})")

        # Office: query theo office malware tags
        if not self.of_done():
            print(f"  Querying malware tags for Office samples...")
            for tag in OFFICE_TAGS:
                if self.of_done() or tag in self.tags_done:
                    continue
                hashes = self._query_tag(tag)
                new_h = [h for h in hashes if h not in seen]
                if new_h:
                    result["office"].extend(new_h)
                    seen.update(new_h)
                if hashes is not None:
                    self.tags_done.add(tag)
                print(f"    [{tag}] {len(new_h)} new hashes (total Office: {len(result['office'])}, API returned {len(hashes) if hashes else 0})")
                if len(result["office"]) >= 5000:
                    break

        self._save()
        print(f"  Collected: PE={len(result['pe']):,} Office={len(result['office']):,} hashes")
        return result

    # ── Step 2: Download samples ───────────────────────────────

    def download_sample(self, sha256: str, prefer_cat: Optional[str] = None) -> Optional[Dict]:
        if sha256 in self.downloaded or sha256 in self.failed:
            return None

        self._last = _rate_limit(self.rate, self._last)
        try:
            data = {"query": "get_file", "sha256_hash": sha256}
            api_key = _get_mb_api_key()
            if api_key:
                data["API-KEY"] = api_key
            r = self.session.post(MB_API_V1, data=data)
            if r.status_code != 200:
                self.failed.add(sha256)
                return None

            # Response la file ZIP truc tiep (binary), khong phai JSON
            content_type = r.headers.get("content-type", "")
            if "application/json" in content_type or r.content[:1] == b"{":
                # JSON error response
                try:
                    data = r.json()
                    if data.get("query_status") != "ok":
                        self.failed.add(sha256)
                        return None
                except Exception:
                    self.failed.add(sha256)
                    return None

            zip_bytes = BytesIO(r.content)
        except Exception as e:
            self.failed.add(sha256)
            self._save()
            return None

        result = _extract_zip(zip_bytes, ZIP_PASSWORD)
        if not result:
            self.failed.add(sha256)
            self._save()
            return None

        name, content = result
        ext = os.path.splitext(name)[1].lower()
        if not ext:
            ext = ".bin"
        cat = _file_category(ext)

        # Skip "other" category
        if cat == "other":
            # Thu giai dinh category tu prefer_cat
            if prefer_cat == "pe":
                ext = ".exe"
                cat = "pe"
            elif prefer_cat == "office":
                ext = ".doc"
                cat = "office"
            else:
                self.failed.add(sha256)
                self._save()
                return None

        # Kiem tra quota
        if cat == "pe" and self.pe_done():
            return None
        if cat == "office" and self.of_done():
            return None

        fhash = hashlib.sha256(content).hexdigest()
        out_dir = self.pe_dir if cat == "pe" else self.of_dir
        out_path = out_dir / f"{fhash}{ext}"

        if not out_path.exists():
            out_path.write_bytes(content)

        self.downloaded.add(sha256)
        if cat == "pe":
            self.pe_bytes_done += len(content)
        else:
            self.of_bytes_done += len(content)
        self._save()
        return {"cat": cat, "size": len(content)}

    def download_all(self, hashes: Dict[str, List[str]]):
        print(f"\n[Step 2/3] Downloading samples (target: {self._gb(self.total_bytes)})...")
        all_pe = hashes.get("pe", [])
        all_of = hashes.get("office", [])

        total_downloaded = 0
        batch = 0

        # Download PE samples
        for sha in all_pe:
            if self.pe_done():
                break
            r = self.download_sample(sha, prefer_cat="pe")
            if r:
                total_downloaded += 1
                batch += 1
                if batch % 50 == 0:
                    print(f"  {total_downloaded} files | PE={self._gb(self.pe_bytes_done)}/{self._gb(self.pe_bytes)} | "
                          f"Office={self._gb(self.of_bytes_done)}/{self._gb(self.of_bytes)}")
                    batch = 0

        # Download Office samples
        for sha in all_of:
            if self.of_done():
                break
            r = self.download_sample(sha, prefer_cat="office")
            if r:
                total_downloaded += 1
                batch += 1
                if batch % 50 == 0:
                    print(f"  {total_downloaded} files | PE={self._gb(self.pe_bytes_done)}/{self._gb(self.pe_bytes)} | "
                          f"Office={self._gb(self.of_bytes_done)}/{self._gb(self.of_bytes)}")

        print(f"  Done: {total_downloaded} downloaded | PE={self._gb(self.pe_bytes_done)} "
              f"Office={self._gb(self.of_bytes_done)}")

    # ── Step 3: Prepare + Train ────────────────────────────────

    def prepare_and_train(self):
        print(f"\n[Step 3/3] Training ML model...")

        import numpy as np
        from core.feature_extractor import extract_features, N_FEATURES
        from core.ml_engine import get_engine, MODEL_PATH

        pe_files = list(self.pe_dir.glob("*"))
        print(f"  Found {len(pe_files)} PE files in {self.pe_dir}")

        if not pe_files:
            print("  No PE files found! Training with synthetic data instead.")
            from core.dataset_generator import generate_synthetic_dataset
            X, y = generate_synthetic_dataset(n_safe=5000, n_encrypted=5000, verbose=True)
            engine = get_engine()
            metrics = engine.train(X, y, model_path=MODEL_PATH, verbose=True)
            print_summary(metrics)
            return

        X_list, y_list = [], []
        errors = 0
        for i, f in enumerate(pe_files):
            try:
                feats = extract_features(str(f))
                if feats is not None and len(feats) == N_FEATURES:
                    X_list.append(feats)
                    y_list.append(1)
            except Exception:
                errors += 1
            if (i + 1) % 500 == 0:
                print(f"  Processed {i + 1}/{len(pe_files)} | Valid={len(X_list)} Errors={errors}")

        print(f"  Feature extraction: {len(X_list)} valid / {len(pe_files)} total ({errors} errors)")

        if not X_list:
            print("  No valid PE features! Training with synthetic data instead.")
            from core.dataset_generator import generate_synthetic_dataset
            X, y = generate_synthetic_dataset(n_safe=5000, n_encrypted=5000, verbose=True)
            engine = get_engine()
            metrics = engine.train(X, y, model_path=MODEL_PATH, verbose=True)
            print_summary(metrics)
            return

        X_enc = np.vstack([np.asarray(f, dtype=np.float32) for f in X_list])
        y_enc = np.ones(len(X_list), dtype=np.int32)

        # Them synthetic SAFE data
        from core.dataset_generator import generate_synthetic_dataset
        n_safe = max(len(X_enc), 5000)
        print(f"  Generating {n_safe} synthetic SAFE samples...")
        X_safe, y_safe = generate_synthetic_dataset(n_safe=n_safe, n_encrypted=0, verbose=False)

        X = np.vstack([X_safe, X_enc])
        y = np.hstack([y_safe, y_enc])

        print(f"  Training with {len(X_enc)} real PE + {X_safe.shape[0]} synthetic SAFE samples")
        engine = get_engine()
        metrics = engine.train(X, y, model_path=MODEL_PATH, verbose=True)
        print_summary(metrics)


def print_summary(metrics: Dict):
    print(f"\n{'=' * 50}")
    print(f"  TRAINING COMPLETE")
    print(f"  Accuracy:  {metrics.get('accuracy', 0) * 100:.2f}%")
    print(f"  Precision: {metrics.get('precision', 0) * 100:.2f}%")
    print(f"  Recall:    {metrics.get('recall', 0) * 100:.2f}%")
    print(f"  F1:        {metrics.get('f1', 0) * 100:.2f}%")
    print(f"  AUC-ROC:   {metrics.get('auc_roc', 0) * 100:.2f}%")
    fpr = metrics.get('false_positive_rate', metrics.get('fpr', 0))
    print(f"  FPR:       {fpr * 100:.2f}%  (target < 5%)")
    print(f"  CV 5-fold: {metrics.get('cv_mean', 0) * 100:.2f}% +/- {metrics.get('cv_std', 0) * 100:.2f}%")
    print(f"  Threshold: {metrics.get('optimal_threshold', 0.5):.4f}")
    print(f"{'=' * 50}")


def main():
    parser = argparse.ArgumentParser(description="MalwareBazaar download + train pipeline")
    parser.add_argument("--total-size-gb", type=float, default=5.0, help="Total target GB (default: 5)")
    parser.add_argument("--pe-ratio", type=float, default=0.7, help="PE ratio (default: 0.7 = 70%%)")
    parser.add_argument("--rate-limit", type=float, default=1.0, help="API rate limit seconds (default: 1.0)")
    parser.add_argument("--output", default="datasets/sources/encrypted/malwarebazaar", help="Output dir")
    parser.add_argument("--skip-download", action="store_true", help="Skip download, only train from existing files")
    parser.add_argument("--train-synthetic", action="store_true", help="Train with synthetic data only (no download)")
    parser.add_argument("--reset-tags", action="store_true", help="Reset tags_done to allow re-querying all tags")
    args = parser.parse_args()

    # Xử lý reset tags trước khi tạo Pipeline
    if args.reset_tags:
        progress_file = Path(args.output) / "_pipeline_progress.json"
        if progress_file.exists():
            print(f"[Reset] Clearing tags_done from {progress_file}")
            data = json.loads(progress_file.read_text(encoding="utf-8"))
            data["tags_done"] = []
            progress_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print("[Reset] tags_done cleared. Re-querying all tags...")

    p = Pipeline(args)

    api_key = _get_mb_api_key()
    api_status = f"configured ({api_key[:8]}...)" if api_key else "NOT configured"

    print("=" * 60)
    print("  RANSOMWARE DETECTOR - MalwareBazaar Download & Train")
    print(f"  Target: {p._gb(p.total_bytes)} ({args.pe_ratio*100:.0f}% PE / {(1-args.pe_ratio)*100:.0f}% Office)")
    print(f"  PE:     {p._gb(p.pe_bytes_done)} / {p._gb(p.pe_bytes)}")
    print(f"  Office: {p._gb(p.of_bytes_done)} / {p._gb(p.of_bytes)}")
    print(f"  Tags done: {len(p.tags_done)}/{len(RANSOM_TAGS) + len(OFFICE_TAGS)}")
    print(f"  pyzipper: {'available' if HAS_PYZIPPER else 'NOT installed (limited AES support)'}")
    print(f"  MB API Key: {api_status}")
    print("=" * 60)

    try:
        if args.train_synthetic:
            # Fast path: train ngay voi synthetic data
            print("\n[Train-Synthetic mode] Skipping download...")
            p.prepare_and_train()
            return

        if not args.skip_download:
            if p.done():
                print("\n  Download quota already met! Skipping to training...")
            else:
                hashes = p.collect_hashes()
                all_hashes_count = len(hashes.get("pe", [])) + len(hashes.get("office", []))
                if all_hashes_count == 0:
                    print("\n  No hashes collected from API.")
                    print("  This may be due to API rate limiting or temporary unavailability.")
                    print("  Falling back to synthetic training...")
                else:
                    p.download_all(hashes)

                if not p.done():
                    pe_left = max(0, p.pe_bytes - p.pe_bytes_done)
                    of_left = max(0, p.of_bytes - p.of_bytes_done)
                    print(f"\n  Quota not yet met (PE={p._gb(pe_left)}, Office={p._gb(of_left)} remaining)")
                    print("  Run again to continue downloading -- progress is saved.")
                    print("  MalwareBazaar API may have daily limits (~100 files/day for community users)")

        p.prepare_and_train()

    except KeyboardInterrupt:
        print("\n\nInterrupted. Progress saved. Run again to continue.")
        p._save()


if __name__ == "__main__":
    main()
