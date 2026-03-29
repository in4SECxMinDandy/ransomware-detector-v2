"""
virustotal_client.py
====================
VirusTotal API v3 Integration.

Features:
  - Query file hash (SHA256) against VirusTotal database
  - Upload and scan unknown files
  - Rate limiting (4 req/min for free tier)
  - Persistent cache (JSON) to avoid duplicate API calls
  - TTL-based cache expiration

Usage:
    vt = VirusTotalClient("YOUR_API_KEY")
    report = vt.get_file_report("abc123...")
    if report and report.malicious_count > 5:
        print("Malicious file detected!")
"""

import os
import json
import time
import hashlib
import logging
import requests
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from threading import Lock

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"

# ─── Rate Limiting ───────────────────────────────────────────────────────────

class RateLimiter:
    """Token bucket rate limiter: 4 requests per minute (free tier)."""

    def __init__(self, rpm: int = 4):
        self.rpm = rpm
        self.min_interval = 60.0 / rpm  # seconds between requests
        self._last_request_time = 0.0
        self._lock = Lock()

    def wait(self):
        """Block until a request can be made."""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_request_time
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                logger.debug(f"Rate limit: sleeping {sleep_time:.1f}s")
                time.sleep(sleep_time)
            self._last_request_time = time.time()

    def get_wait_time(self) -> float:
        """Return seconds until next request is allowed."""
        with self._lock:
            elapsed = time.time() - self._last_request_time
            return max(0.0, self.min_interval - elapsed)


# ─── Dataclasses ─────────────────────────────────────────────────────────────

@dataclass
class VTDetection:
    """Ket qua mot engine phat hien."""
    engine_name: str
    category: str  # "malicious", "suspicious", "undetected", "harmless"
    result: str
    method: str
    engine_version: str
    engine_update: str


@dataclass
class VTFileReport:
    """Ket qua phan tich VirusTotal cho mot file."""
    sha256: str
    md5: str
    sha1: str
    file_type: str
    file_size: int
    # Detection stats
    malicious_count: int = 0
    suspicious_count: int = 0
    undetected_count: int = 0
    harmless_count: int = 0
    # Misc
    total_engines: int = 0
    detection_ratio: str = "0/0"
    # Analysis
    scan_date: str = ""
    analysis_stats: Dict[str, int] = field(default_factory=dict)
    last_analysis_results: List[VTDetection] = field(default_factory=list)
    # Links
    permalink: str = ""
    # Metadata
    first_submission_date: str = ""
    last_submission_date: str = ""
    # Cache
    cached_at: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def is_malicious(self, threshold: int = 5) -> bool:
        """Neu so engine phat hien > threshold thi la malicious."""
        return self.malicious_count >= threshold

    def is_suspicious(self, threshold: int = 2) -> bool:
        """Neu suspicious_count > threshold thi la suspicious."""
        return self.suspicious_count >= threshold

    def get_summary(self) -> str:
        """Tao mot chuoi tom tat ket qua."""
        return f"VT: {self.malicious_count}/{self.total_engines} engines detected"

    def get_badge(self) -> str:
        """Tra ve badge string cho GUI."""
        return f"VT: {self.malicious_count}/{self.total_engines}"

    def get_risk_color(self) -> str:
        """Tra ve mau theo muc do nguy hiem."""
        if self.malicious_count >= 10:
            return "red"
        elif self.malicious_count >= 5:
            return "orange"
        elif self.malicious_count >= 2:
            return "yellow"
        elif self.suspicious_count > 0:
            return "yellow"
        return "green"


@dataclass
class CacheEntry:
    """Mot entry trong VT cache."""
    sha256: str
    report: Dict[str, Any]
    cached_at: str  # ISO timestamp
    expires_at: str  # ISO timestamp

    def is_expired(self) -> bool:
        """Kiem tra xem entry da het TTL chua."""
        try:
            expires = datetime.fromisoformat(self.expires_at)
            return datetime.now() >= expires
        except Exception:
            return True


# ─── VirusTotalClient ─────────────────────────────────────────────────────────

class VirusTotalClient:
    """
    VirusTotal API v3 client voi rate limiting va caching.

    Args:
        api_key: VirusTotal API key (public/tier-free)
        cache_path: Path to JSON cache file (default: data/vt_cache.json)
        cache_ttl_hours: Cache TTL in hours (default: 24)
        rate_limit_rpm: Requests per minute (default: 4 for free tier)
    """

    DEFAULT_CACHE_PATH = "data/vt_cache.json"
    DEFAULT_TTL_HOURS = 24

    def __init__(
        self,
        api_key: str,
        cache_path: Optional[str] = None,
        cache_ttl_hours: int = DEFAULT_TTL_HOURS,
        rate_limit_rpm: int = 4,
    ):
        self.api_key = api_key
        self.cache_path = cache_path or self._resolve_path(self.DEFAULT_CACHE_PATH)
        self.cache_ttl_hours = cache_ttl_hours
        self._rate_limiter = RateLimiter(rate_limit_rpm)
        self._lock = Lock()
        self._cache: Dict[str, CacheEntry] = {}
        self._session = requests.Session()
        self._session.headers.update({
            "x-apikey": self.api_key,
            "Accept": "application/json",
        })

        # Load cache from disk
        self._load_cache()

        # Stats
        self._stats = {
            "total_queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "api_requests": 0,
            "errors": 0,
        }

    # ─── Public API ─────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        """Kiem tra xem API key da duoc cau hinh chua."""
        return bool(self.api_key and len(self.api_key) > 10)

    def get_file_report(self, sha256: str) -> Optional[VTFileReport]:
        """
        Lay bao cao phan tich cho mot file (SHA256).

        Su dung cache neu co san, nguoc lai goi API.
        Returns None neu co loi.
        """
        self._stats["total_queries"] += 1

        # Check cache first
        cached = self._get_cached(sha256)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return cached

        self._stats["cache_misses"] += 1

        # Query API
        report = self._query_api(sha256)

        if report is not None:
            self._save_to_cache(sha256, report)

        return report

    def upload_and_scan(self, file_path: str,
                        wait_for_result: bool = True,
                        timeout_seconds: int = 300
                        ) -> Optional[VTFileReport]:
        """
        Upload file len VirusTotal de scan.

        Args:
            file_path: Duong dan file can upload
            wait_for_result: Co doi ket qua hay khong
            timeout_seconds: Thoi gian toi da doi ket qua

        Returns:
            VTFileReport neu thanh cong, None neu co loi
        """
        if not os.path.isfile(file_path):
            logger.error(f"File not found for upload: {file_path}")
            return None

        # Compute hash first
        sha256 = self._compute_sha256(file_path)
        if not sha256:
            return None

        # Check cache by hash
        cached = self._get_cached(sha256)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return cached

        self._stats["cache_misses"] += 1

        # Upload file
        url = f"{VT_API_BASE}/files"

        try:
            self._rate_limiter.wait()

            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                response = self._session.post(url, files=files, timeout=60)

            self._stats["api_requests"] += 1

            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get("data", {}).get("id", "")

                if wait_for_result:
                    return self._wait_for_analysis(analysis_id, timeout_seconds)
                else:
                    # Return immediately with analysis ID
                    return VTFileReport(
                        sha256=sha256,
                        md5="",
                        sha1="",
                        file_type="",
                        file_size=os.path.getsize(file_path),
                        permalink=f"https://www.virustotal.com/gui/file/{sha256}",
                    )
            elif response.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded")
                self._stats["errors"] += 1
                return None
            else:
                logger.error(f"VT upload failed: {response.status_code} {response.text[:200]}")
                self._stats["errors"] += 1
                return None

        except Exception as e:
            logger.error(f"VT upload error: {e}")
            self._stats["errors"] += 1
            return None

    def query_hash(self, sha256: str) -> Optional[VTFileReport]:
        """
        Alias cho get_file_report — query theo SHA256.
        """
        return self.get_file_report(sha256)

    def get_stats(self) -> Dict[str, Any]:
        """Tra ve thong ke su dung."""
        return {
            **self._stats,
            "cache_size": len(self._cache),
            "rate_limit_wait": round(self._rate_limiter.get_wait_time(), 1),
        }

    def clear_cache(self):
        """Xoa toan bo cache."""
        with self._lock:
            self._cache.clear()
            self._save_cache_to_disk()

    # ─── Private Methods ─────────────────────────────────────────────────────

    def _query_api(self, sha256: str) -> Optional[VTFileReport]:
        """Goi API de lay bao cao file."""
        url = f"{VT_API_BASE}/files/{sha256}"

        try:
            self._rate_limiter.wait()
            response = self._session.get(url, timeout=30)
            self._stats["api_requests"] += 1

            if response.status_code == 200:
                return self._parse_response(response.json(), sha256)
            elif response.status_code == 404:
                logger.info(f"File not found on VirusTotal: {sha256[:16]}...")
                return None
            elif response.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded")
                self._stats["errors"] += 1
                return None
            else:
                logger.error(f"VT API error: {response.status_code}")
                self._stats["errors"] += 1
                return None

        except requests.exceptions.Timeout:
            logger.error("VT API timeout")
            self._stats["errors"] += 1
            return None
        except Exception as e:
            logger.error(f"VT API error: {e}")
            self._stats["errors"] += 1
            return None

    def _parse_response(self, data: Dict, sha256: str) -> VTFileReport:
        """Parse JSON response tu API."""
        try:
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            # Parse detection results
            detections = []
            last_results = attributes.get("last_analysis_results", {})

            for engine_name, result_data in last_results.items():
                detections.append(VTDetection(
                    engine_name=engine_name,
                    category=result_data.get("category", "undetected"),
                    result=result_data.get("result", ""),
                    method=result_data.get("method", ""),
                    engine_version=result_data.get("engine_version", ""),
                    engine_update=result_data.get("engine_update", ""),
                ))

            # Compute totals — VT GUI displays ALL categories (incl. timeout/failure/type-unsupported)
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)
            # Match what VT GUI shows as the denominator (all analysis outcomes)
            total = sum(
                stats.get(k, 0)
                for k in ("malicious", "suspicious", "undetected", "harmless",
                          "timeout", "confirmed-timeout", "failure", "type-unsupported")
            )

            # Build permalink
            id_data = data.get("data", {}).get("id", sha256)
            permalink = f"https://www.virustotal.com/gui/file/{id_data}"

            return VTFileReport(
                sha256=sha256,
                md5=attributes.get("md5", ""),
                sha1=attributes.get("sha1", ""),
                file_type=attributes.get("type_description", ""),
                file_size=attributes.get("size", 0),
                malicious_count=malicious,
                suspicious_count=suspicious,
                undetected_count=undetected,
                harmless_count=harmless,
                total_engines=total,
                detection_ratio=f"{malicious}/{total}",
                scan_date=attributes.get("last_analysis_date", ""),
                analysis_stats=stats,
                last_analysis_results=detections,
                permalink=permalink,
                first_submission_date=attributes.get("first_submission_date", ""),
                last_submission_date=attributes.get("last_submission_date", ""),
            )

        except Exception as e:
            logger.error(f"Failed to parse VT response: {e}")
            return VTFileReport(
                sha256=sha256,
                md5="",
                sha1="",
                file_type="",
                file_size=0,
                error=f"Parse error: {e}",
            )

    def _wait_for_analysis(self, analysis_id: str, timeout_seconds: int) -> Optional[VTFileReport]:
        """Cho analysis hoan thanh va lay ket qua."""
        url = f"{VT_API_BASE}/analyses/{analysis_id}"
        start_time = time.time()

        while time.time() - start_time < timeout_seconds:
            try:
                self._rate_limiter.wait()
                response = self._session.get(url, timeout=30)
                self._stats["api_requests"] += 1

                if response.status_code == 200:
                    data = response.json()
                    status = data.get("data", {}).get("attributes", {}).get("status", "")

                    if status == "completed":
                        # Get SHA256 from analysis result
                        sha256 = data.get("meta", {}).get("file_info", {}).get("sha256", "")
                        if not sha256:
                            # Try to extract from the response
                            file_info = data.get("data", {}).get("meta", {}).get("file_info", {})
                            sha256 = file_info.get("sha256", analysis_id.split("-")[0] if "-" in analysis_id else analysis_id)
                        return self._parse_analysis_response(data, sha256)
                    elif status == "queued":
                        logger.debug(f"Analysis queued, waiting... ({int(time.time() - start_time)}s)")
                        time.sleep(10)
                    else:
                        logger.warning(f"Analysis status: {status}")
                        return None

                elif response.status_code == 429:
                    logger.warning("Rate limit while waiting for analysis")
                    time.sleep(30)
                else:
                    logger.error(f"Analysis query failed: {response.status_code}")
                    return None

            except Exception as e:
                logger.error(f"Analysis wait error: {e}")
                time.sleep(10)

        logger.warning(f"Analysis timeout after {timeout_seconds}s")
        return None

    def _parse_analysis_response(self, data: Dict, sha256: str) -> VTFileReport:
        """Parse analysis response (upload result)."""
        try:
            stats = data.get("data", {}).get("attributes", {}).get("stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)
            total = sum(
                stats.get(k, 0)
                for k in ("malicious", "suspicious", "undetected", "harmless",
                          "timeout", "confirmed-timeout", "failure", "type-unsupported")
            )

            permalink = f"https://www.virustotal.com/gui/file/{sha256}"

            return VTFileReport(
                sha256=sha256,
                md5="",
                sha1="",
                file_type="",
                file_size=0,
                malicious_count=malicious,
                suspicious_count=suspicious,
                undetected_count=undetected,
                harmless_count=harmless,
                total_engines=total,
                detection_ratio=f"{malicious}/{total}",
                permalink=permalink,
            )

        except Exception as e:
            logger.error(f"Failed to parse analysis response: {e}")
            return VTFileReport(
                sha256=sha256,
                md5="",
                sha1="",
                file_type="",
                file_size=0,
                error=f"Parse error: {e}",
            )

    # ─── Cache Management ───────────────────────────────────────────────────

    def _get_cached(self, sha256: str) -> Optional[VTFileReport]:
        """Lay ket qua tu cache neu chua het TTL."""
        with self._lock:
            entry = self._cache.get(sha256)
            if entry is None:
                return None
            if entry.is_expired():
                del self._cache[sha256]
                return None

            try:
                return VTFileReport(**entry.report)
            except Exception:
                return None

    def _save_to_cache(self, sha256: str, report: VTFileReport):
        """Luu ket qua vao cache."""
        now = datetime.now()
        expires = now + timedelta(hours=self.cache_ttl_hours)

        report.cached_at = now.isoformat()

        with self._lock:
            self._cache[sha256] = CacheEntry(
                sha256=sha256,
                report=report.to_dict(),
                cached_at=now.isoformat(),
                expires_at=expires.isoformat(),
            )
            self._save_cache_to_disk()

    def _load_cache(self):
        """Load cache tu disk vao memory."""
        cache_file = self._resolve_path(self.cache_path)
        if not os.path.isfile(cache_file):
            return

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            entries = data.get("entries", {})
            for sha256, entry_data in entries.items():
                try:
                    entry = CacheEntry(**entry_data)
                    if not entry.is_expired():
                        self._cache[sha256] = entry
                except Exception:
                    continue

            logger.info(f"Loaded {len(self._cache)} cached VT entries")

        except Exception as e:
            logger.warning(f"Failed to load VT cache: {e}")

    def _save_cache_to_disk(self):
        """Persist cache ra disk."""
        cache_file = self._resolve_path(self.cache_path)

        try:
            os.makedirs(os.path.dirname(cache_file), exist_ok=True)

            entries = {}
            for sha256, entry in self._cache.items():
                entries[sha256] = {
                    "sha256": entry.sha256,
                    "report": entry.report,
                    "cached_at": entry.cached_at,
                    "expires_at": entry.expires_at,
                }

            data = {
                "cache_version": "1.0",
                "last_updated": datetime.now().isoformat(),
                "entries": entries,
            }

            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.warning(f"Failed to save VT cache: {e}")

    # ─── Utilities ─────────────────────────────────────────────────────────

    @staticmethod
    def _compute_sha256(file_path: str) -> str:
        """Tinh SHA256 cua file."""
        try:
            with open(file_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""

    def _resolve_path(self, path: str) -> str:
        """Resolve relative path tu project root."""
        if os.path.isabs(path):
            return path
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, path)


# ─── Global client instance (lazy initialization) ───────────────────────────

_vt_client: Optional[VirusTotalClient] = None
_vt_api_key: Optional[str] = None


def get_vt_client(api_key: Optional[str] = None) -> VirusTotalClient:
    """
    Lay singleton VirusTotalClient.

    Su dung api_key tu tham so hoac tu config.
    """
    global _vt_client, _vt_api_key

    if api_key is not None:
        _vt_api_key = api_key

    if _vt_client is None or (_vt_api_key and _vt_client.api_key != _vt_api_key):
        if _vt_api_key:
            _vt_client = VirusTotalClient(_vt_api_key)
        else:
            # Return a dummy client with no API key
            _vt_client = VirusTotalClient("")

    return _vt_client


def configure_vt_client(api_key: str):
    """Cau hinh API key va reset client."""
    global _vt_client, _vt_api_key
    _vt_api_key = api_key
    _vt_client = None  # Will be recreated on next get_vt_client()
