"""
threat_intel_client.py
======================
Threat Intelligence correlation client cho Ransomware Detector v2.5.

Tích hợp 3 nguồn TI miễn phí:
  - MalwareBazaar (abuse.ch) — SHA256 hash lookup, malware family, tags
  - ThreatFox (abuse.ch)       — IOC database, malware family, confidence
  - AlienVault OTX             — Pulse info, analysis metadata

Features:
  - Singleton pattern (lazy init)
  - Persistent JSON cache (TTL-based)
  - Rate limiting per source
  - Graceful degradation khi source unavailable
  - Enriches scan results with TI context

Usage:
    ti = get_ti_client()
    result = ti.lookup_sha256("abc123...")
    if result and result.malwarebazaar.get("available"):
        print(f"Family: {result.malwarebazaar.get('family')}")
"""

import os
import json
import time
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from threading import Lock

import httpx

from core.config_manager import config

logger = logging.getLogger(__name__)

# ─── API Endpoints ────────────────────────────────────────────────────────────
MB_API_BASE  = "https://bazaar.abuse.ch/api/"
TF_API_BASE  = "https://threatfox.abuse.ch/api/"
OTX_API_BASE = "https://otx.alienvault.com/api/v3"

# ─── Rate Limiters ────────────────────────────────────────────────────────────

class RateLimiter:
    """Token bucket rate limiter per source."""

    def __init__(self, rpm: int = 30):
        self.rpm          = rpm
        self.min_interval = 60.0 / max(rpm, 1)
        self._last_time   = 0.0
        self._lock        = Lock()

    def wait(self):
        with self._lock:
            now     = time.time()
            elapsed = now - self._last_time
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self._last_time = time.time()

    def get_wait_time(self) -> float:
        with self._lock:
            return max(0.0, self.min_interval - (time.time() - self._last_time))


class CircuitBreaker:
    """Per-source circuit breaker for TI HTTP calls.

    Trips ``OPEN`` after ``failure_threshold`` consecutive failures and
    short-circuits subsequent requests for ``cooldown_seconds`` so a single
    flaky upstream cannot stall the scanner thread pool. The first request
    after the cooldown enters ``HALF_OPEN`` state and probes the upstream
    once — success closes the breaker, failure re-opens it for another
    cooldown window.

    Audit P4-10: replaces unconditional ``time.sleep`` waits that previously
    blocked scans for hours when MalwareBazaar / OTX were down.
    """

    STATE_CLOSED    = "closed"
    STATE_OPEN      = "open"
    STATE_HALF_OPEN = "half_open"

    def __init__(self, failure_threshold: int = 3, cooldown_seconds: float = 60.0):
        self.failure_threshold = max(1, failure_threshold)
        # Floor at 1 ms — high enough to keep the breaker meaningful, low
        # enough that unit tests can exercise the cooldown without sleeping
        # for whole seconds.
        self.cooldown_seconds  = max(0.001, float(cooldown_seconds))
        self._failures   = 0
        self._opened_at  = 0.0
        self._state      = self.STATE_CLOSED
        self._lock       = Lock()

    def allow(self) -> bool:
        """Return True if the caller should proceed with the request."""
        with self._lock:
            if self._state == self.STATE_CLOSED:
                return True
            if self._state == self.STATE_OPEN:
                if time.time() - self._opened_at >= self.cooldown_seconds:
                    # Probe the upstream once.
                    self._state = self.STATE_HALF_OPEN
                    return True
                return False
            # HALF_OPEN — only one probe is in flight; block the rest.
            return False

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._state    = self.STATE_CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._state == self.STATE_HALF_OPEN or \
               self._failures >= self.failure_threshold:
                self._state    = self.STATE_OPEN
                self._opened_at = time.time()

    @property
    def state(self) -> str:
        with self._lock:
            return self._state


# ─── Dataclasses ─────────────────────────────────────────────────────────────

@dataclass
class TIResult:
    """Kết quả Threat Intelligence cho một SHA256 hash."""

    sha256: str

    # MalwareBazaar (abuse.ch)
    mb_available: bool       = False
    mb_family: str           = ""
    mb_signature: str        = ""
    mb_first_seen: str       = ""
    mb_tags: list            = field(default_factory=list)
    mb_delivery_method: str  = ""
    mb_publication_time: str = ""

    # ThreatFox (abuse.ch)
    tf_available: bool       = False
    tf_threat_type: str      = ""
    tf_malware_family: str   = ""
    tf_confidence: int       = 0
    tf_tags: list            = field(default_factory=list)
    tf_ioc_type: str         = ""

    # AlienVault OTX
    otx_available: bool       = False
    otx_pulse_count: int     = 0
    otx_pulse_names: list    = field(default_factory=list)
    otx_analysis_metadata: dict = field(default_factory=dict)

    # Error tracking
    mb_error: str  = ""
    tf_error: str  = ""
    otx_error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def has_any_ti(self) -> bool:
        return self.mb_available or self.tf_available or self.otx_available

    def get_summary(self) -> str:
        parts = []
        if self.mb_available and self.mb_family:
            parts.append(f"MB:{self.mb_family}")
        if self.tf_available and self.tf_malware_family:
            parts.append(f"TF:{self.tf_malware_family}")
        if self.otx_available and self.otx_pulse_count > 0:
            parts.append(f"OTX:{self.otx_pulse_count} pulses")
        return ", ".join(parts) if parts else "No TI data"


@dataclass
class TICacheEntry:
    """Mot entry trong TI cache."""
    sha256: str
    result: Dict[str, Any]
    cached_at: str
    expires_at: str

    def is_expired(self) -> bool:
        try:
            expires = datetime.fromisoformat(self.expires_at)
            return datetime.now() >= expires
        except Exception:
            return True


# ─── ThreatIntelClient ─────────────────────────────────────────────────────────

class ThreatIntelClient:
    """
    Threat Intelligence correlation client.

    Lay thong tin TI tu MalwareBazaar, ThreatFox, AlienVault OTX de bo sung
    context cho ket qua quet. Khong thay the VirusTotal ma bo sung them nguon
    du lieu.

    Args:
        cache_path: Path to JSON cache file (default: data/ti_cache.json)
        cache_ttl_hours: Cache TTL in hours (default: 24)
        timeout_seconds: HTTP request timeout (default: 15)
    """

    DEFAULT_CACHE_PATH  = "data/ti_cache.json"
    DEFAULT_TTL_HOURS   = 24
    DEFAULT_TIMEOUT_SEC = 15

    def __init__(
        self,
        cache_path: Optional[str] = None,
        cache_ttl_hours: int = DEFAULT_TTL_HOURS,
        timeout_seconds: int = DEFAULT_TIMEOUT_SEC,
    ):
        self.cache_path      = cache_path or self._resolve_path(self.DEFAULT_CACHE_PATH)
        self.cache_ttl_hours = cache_ttl_hours
        self.timeout         = timeout_seconds

        # Rate limiters (MalwareBazaar ~60 req/min, ThreatFox ~10 req/min, OTX ~20 req/min)
        self._mb_limiter  = RateLimiter(rpm=60)
        self._tf_limiter = RateLimiter(rpm=10)
        self._otx_limiter = RateLimiter(rpm=20)

        # Per-source circuit breakers (audit P4-10). After 3 consecutive
        # network/HTTP failures we stop hitting that source for 60s so a
        # flaky upstream cannot block the whole scanner thread pool.
        self._mb_breaker  = CircuitBreaker(failure_threshold=3, cooldown_seconds=60.0)
        self._tf_breaker  = CircuitBreaker(failure_threshold=3, cooldown_seconds=60.0)
        self._otx_breaker = CircuitBreaker(failure_threshold=3, cooldown_seconds=60.0)

        self._lock   = Lock()
        self._cache: Dict[str, TICacheEntry] = {}

        # httpx client reuse
        self._session = httpx.Client(timeout=timeout_seconds)

        # Stats
        self._stats = {
            "total_queries":    0,
            "cache_hits":       0,
            "cache_misses":     0,
            "mb_requests":      0,
            "tf_requests":      0,
            "otx_requests":     0,
            "errors":           0,
        }

        # Load cache
        self._load_cache()

    # ─── Public API ─────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        """Kiem tra xem co nguon TI nao duoc cau hinh hay khong."""
        return (
            self._is_mb_enabled() or
            self._is_tf_enabled() or
            self._is_otx_enabled()
        )

    def lookup_sha256(self, sha256: str) -> TIResult:
        """
        Tra cuu Threat Intelligence cho mot SHA256 hash.

        Su dung cache neu co san, nguoc lai goi cac nguon TI song song.
        Chi goi nguon nao duoc bat trong config.

        Returns:
            TIResult voi tat ca nguon co the tra cuu duoc.
        """
        if not sha256 or len(sha256) != 64:
            return TIResult(sha256=sha256 or "")

        self._stats["total_queries"] += 1

        # Check cache
        cached = self._get_cached(sha256)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return cached

        self._stats["cache_misses"] += 1
        result = self._query_all_sources(sha256)
        self._save_to_cache(sha256, result)
        return result

    def get_stats(self) -> Dict[str, Any]:
        """Tra ve thong ke su dung."""
        return {
            **self._stats,
            "total_lookups": self._stats.get("total_queries", 0),
            "cache_size": len(self._cache),
            "mb_wait_time": round(self._mb_limiter.get_wait_time(), 1),
            "tf_wait_time": round(self._tf_limiter.get_wait_time(), 1),
            "otx_wait_time": round(self._otx_limiter.get_wait_time(), 1),
        }

    def _save_cache(self):
        """Alias for _save_cache_to_disk (compat)."""
        self._save_cache_to_disk()

    def clear_cache(self):
        """Xoa toan bo cache."""
        with self._lock:
            self._cache.clear()
            self._save_cache_to_disk()

    # ─── Source Configuration Helpers ──────────────────────────────────────

    def _is_mb_enabled(self) -> bool:
        return config.get("threat_intel.malwarebazaar.enabled", False)

    def _is_tf_enabled(self) -> bool:
        return config.get("threat_intel.threatfox.enabled", False) and \
               bool(config.get("threat_intel.threatfox.api_key", ""))

    def _is_otx_enabled(self) -> bool:
        return config.get("threat_intel.alienvault_otx.enabled", False) and \
               bool(config.get("threat_intel.alienvault_otx.api_key", ""))

    # ─── Core Query Logic ─────────────────────────────────────────────────

    def _query_all_sources(self, sha256: str) -> TIResult:
        """Goi tat ca nguon TI va tao TIResult."""
        result = TIResult(sha256=sha256)

        if self._is_mb_enabled():
            self._query_malwarebazaar(sha256, result)

        if self._is_tf_enabled():
            self._query_threatfox(sha256, result)

        if self._is_otx_enabled():
            self._query_alienvault_otx(sha256, result)

        return result

    # ─── MalwareBazaar ─────────────────────────────────────────────────────

    def _query_malwarebazaar(self, sha256: str, result: TIResult):
        """
        Tra cuu MalwareBazaar bang SHA256 hash.

        API: POST https://bazaar.abuse.ch/api/
        Payload: {"query": "get_info", "hash": "<sha256>"}
        Khong can API key cho basic hash lookup.
        """
        if not self._mb_breaker.allow():
            result.mb_error = "circuit_open"
            return
        try:
            self._mb_limiter.wait()
            payload = {"query": "get_info", "hash": sha256}

            response = self._session.post(
                MB_API_BASE,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            self._stats["mb_requests"] += 1

            if response.status_code == 200:
                data = response.json()
                self._parse_malwarebazaar_response(data, result)
                self._mb_breaker.record_success()
            else:
                result.mb_error = f"HTTP {response.status_code}"
                if response.status_code >= 500:
                    self._mb_breaker.record_failure()
                else:
                    # 4xx is a client/data issue, not an upstream outage.
                    self._mb_breaker.record_success()

        except httpx.TimeoutException:
            result.mb_error = "Timeout"
            self._stats["errors"] += 1
            self._mb_breaker.record_failure()
        except Exception as e:
            result.mb_error = str(e)[:100]
            self._stats["errors"] += 1
            self._mb_breaker.record_failure()

    def _parse_malwarebazaar_response(self, data: Dict, result: TIResult):
        """Parse response tu MalwareBazaar API."""
        try:
            # MalwareBazaar tra ve dict voi key la SHA256
            if isinstance(data, dict) and result.sha256 in data:
                info = data[result.sha256]
            elif isinstance(data, list) and len(data) > 0:
                info = data[0]
            else:
                info = data

            if not info or info.get("query_status") == "file_not_found":
                result.mb_available = False
                return

            result.mb_available      = True
            result.mb_family         = info.get("signature", "") or info.get("malware_family", "")
            result.mb_signature       = info.get("signature", "")
            result.mb_first_seen     = info.get("firstseen", "") or info.get("first_submission", "")
            result.mb_delivery_method = info.get("delivery_method", "")
            result.mb_publication_time = info.get("publication_time", "")
            result.mb_tags           = info.get("tags", []) or []

            # Neu khong co signature, thu lay tu truong khac
            if not result.mb_family and "intelligence" in info:
                result.mb_family = (
                    info.get("intelligence", {}).get("clamav", "") or
                    info.get("intelligence", {}).get("yara", [{}])[0].get("name", "")
                )

        except Exception as e:
            result.mb_error = f"Parse error: {e}"
            result.mb_available = False

    # ─── ThreatFox ─────────────────────────────────────────────────────────

    def _query_threatfox(self, sha256: str, result: TIResult):
        """
        Tra cuu ThreatFox bang SHA256 hash.

        API: POST https://threatfox.abuse.ch/api/
        Payload: {"query": "search_ioc", "hash": "<sha256>"}
        Can API key (free) tu auth.abuse.ch.
        """
        try:
            api_key = config.get("threat_intel.threatfox.api_key", "")
            if not api_key:
                result.tf_error = "No API key"
                return

            if not self._tf_breaker.allow():
                result.tf_error = "circuit_open"
                return

            self._tf_limiter.wait()
            payload = {"query": "search_ioc", "hash": sha256}

            response = self._session.post(
                TF_API_BASE,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "API-KEY": api_key,
                },
            )
            self._stats["tf_requests"] += 1

            if response.status_code == 200:
                data = response.json()
                self._parse_threatfox_response(data, result)
                self._tf_breaker.record_success()
            else:
                result.tf_error = f"HTTP {response.status_code}"
                if response.status_code >= 500:
                    self._tf_breaker.record_failure()
                else:
                    self._tf_breaker.record_success()

        except httpx.TimeoutException:
            result.tf_error = "Timeout"
            self._stats["errors"] += 1
            self._tf_breaker.record_failure()
        except Exception as e:
            result.tf_error = str(e)[:100]
            self._stats["errors"] += 1
            self._tf_breaker.record_failure()

    def _parse_threatfox_response(self, data: Dict, result: TIResult):
        """Parse response tu ThreatFox API."""
        try:
            if data.get("query_status") != "ok":
                result.tf_available = False
                return

            data_list = data.get("data", [])
            if not data_list or not isinstance(data_list, list):
                result.tf_available = False
                return

            # Lay item dau tien
            item = data_list[0]
            result.tf_available     = True
            result.tf_threat_type   = item.get("threat_type", "")
            result.tf_malware_family = item.get("malware_family", "")
            result.tf_confidence    = int(item.get("confidence_level", 0) or 0)
            result.tf_tags          = item.get("tags", [])
            result.tf_ioc_type      = item.get("ioc_type", "")

        except Exception as e:
            result.tf_error = f"Parse error: {e}"
            result.tf_available = False

    # ─── AlienVault OTX ────────────────────────────────────────────────────

    def _query_alienvault_otx(self, sha256: str, result: TIResult):
        """
        Tra cuu AlienVault OTX bang SHA256 hash.

        API: GET https://otx.alienvault.com/api/v1/indicators/file/sha256/<hash>
        Can API key (free) tu otx.alienvault.com.
        """
        try:
            api_key = config.get("threat_intel.alienvault_otx.api_key", "")
            if not api_key:
                result.otx_error = "No API key"
                return

            if not self._otx_breaker.allow():
                result.otx_error = "circuit_open"
                return

            self._otx_limiter.wait()
            url = f"{OTX_API_BASE}/indicators/file/sha256/{sha256}"

            response = self._session.get(
                url,
                headers={"X-OTX-API-KEY": api_key},
            )
            self._stats["otx_requests"] += 1

            if response.status_code == 200:
                data = response.json()
                self._parse_alienvault_response(data, result)
                self._otx_breaker.record_success()
            else:
                result.otx_error = f"HTTP {response.status_code}"
                if response.status_code >= 500:
                    self._otx_breaker.record_failure()
                else:
                    self._otx_breaker.record_success()

        except httpx.TimeoutException:
            result.otx_error = "Timeout"
            self._stats["errors"] += 1
            self._otx_breaker.record_failure()
        except Exception as e:
            result.otx_error = str(e)[:100]
            self._stats["errors"] += 1
            self._otx_breaker.record_failure()

    def _parse_alienvault_response(self, data: Dict, result: TIResult):
        """Parse response tu AlienVault OTX API."""
        try:
            if not data or data.get("pulse_info", {}).get("count", 0) == 0:
                result.otx_available = False
                return

            pulse_info = data.get("pulse_info", {})

            result.otx_available        = True
            result.otx_pulse_count       = pulse_info.get("count", 0)

            # Lay ten cac pulses
            pulses = pulse_info.get("pulses", [])
            result.otx_pulse_names       = [p.get("name", "") for p in pulses[:10]]

            # Lay analysis metadata
            general = data.get("general", {})
            result.otx_analysis_metadata = {
                "alc_score":     general.get("alc_score", 0),
                "score":         general.get("score", 0),
                "country_code":  general.get("country_code", ""),
                "verification":  general.get("verification", ""),
                "main_image":    general.get("main_image", ""),
            }

        except Exception as e:
            result.otx_error = f"Parse error: {e}"
            result.otx_available = False

    # ─── Cache Management ──────────────────────────────────────────────────

    def _get_cached(self, sha256: str) -> Optional[TIResult]:
        """Lay ket qua tu cache neu chua het TTL."""
        with self._lock:
            entry = self._cache.get(sha256)
            if entry is None:
                return None
            if entry.is_expired():
                del self._cache[sha256]
                return None

            try:
                return TIResult(**entry.result)
            except Exception:
                return None

    def _save_to_cache(self, sha256: str, result: TIResult):
        """Luu ket qua vao cache."""
        now    = datetime.now()
        expires = now + timedelta(hours=self.cache_ttl_hours)

        with self._lock:
            self._cache[sha256] = TICacheEntry(
                sha256=sha256,
                result=result.to_dict(),
                cached_at=now.isoformat(),
                expires_at=expires.isoformat(),
            )
            self._save_cache_to_disk()

    def _load_cache(self):
        """Load cache tu disk vao memory."""
        cache_file = self.cache_path
        if not os.path.isfile(cache_file):
            return

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            entries = data.get("entries", {})
            for sha256, entry_data in entries.items():
                try:
                    entry = TICacheEntry(**entry_data)
                    if not entry.is_expired():
                        self._cache[sha256] = entry
                except Exception:
                    continue

            logger.info(f"Loaded {len(self._cache)} cached TI entries")

        except Exception as e:
            logger.warning(f"Failed to load TI cache: {e}")

    def _save_cache_to_disk(self):
        """Persist cache ra disk."""
        cache_file = self.cache_path

        try:
            os.makedirs(os.path.dirname(cache_file), exist_ok=True)

            entries = {}
            for sha256, entry in self._cache.items():
                entries[sha256] = {
                    "sha256":    entry.sha256,
                    "result":     entry.result,
                    "cached_at":  entry.cached_at,
                    "expires_at": entry.expires_at,
                }

            data = {
                "cache_version": "1.0",
                "last_updated":  datetime.now().isoformat(),
                "entries":       entries,
            }

            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.warning(f"Failed to save TI cache: {e}")

    # ─── Utilities ─────────────────────────────────────────────────────────

    def _resolve_path(self, path: str) -> str:
        """Resolve relative path tu project root."""
        if os.path.isabs(path):
            return path
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, path)


# ─── Global Singleton ────────────────────────────────────────────────────────

_ti_client: Optional[ThreatIntelClient] = None


def get_ti_client() -> ThreatIntelClient:
    """
    Lay singleton ThreatIntelClient.

    Su dung config tu config_manager de lay settings.
    """
    global _ti_client

    if _ti_client is None:
        _ti_client = ThreatIntelClient()

    return _ti_client


def configure_ti_client(**kwargs):
    """Cau hinh TI client voi tham so tuy chon, reset singleton."""
    global _ti_client
    _ti_client = ThreatIntelClient(**kwargs)
    return _ti_client
