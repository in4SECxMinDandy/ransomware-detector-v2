"""Probe MalwareBazaar / ThreatFox / AlienVault OTX connectivity.

This module replaces the historical ``_api_test.py`` / ``_api_test2.py``
scripts at the repository root, which embedded **real API keys in
plaintext** — a credential leak. Keys are now loaded exclusively from
environment variables; the script will skip a probe with a warning when
the corresponding key is missing.

Usage::

    set THREATFOX_API_KEY=...
    set OTX_API_KEY=...
    python -m scripts.dev.probe_threat_intel
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

try:
    import httpx
except ImportError:  # pragma: no cover - dev tool
    print("httpx is not installed. Run: pip install -r requirements-dev.txt")
    sys.exit(1)


# A well-known benign hash used purely as a connectivity probe.
PROBE_HASH = "131f95c51cc819465fa1797f6cc461f85c4cfd8fee1b16b9c3a2995e5c4c3d9a"

USER_AGENT = "RansomwareDetector/2.5 (dev-probe)"


def _build_tests() -> List[Dict[str, Any]]:
    threatfox_key = os.environ.get("THREATFOX_API_KEY", "").strip()
    otx_key = os.environ.get("OTX_API_KEY", "").strip()

    tests: List[Dict[str, Any]] = [
        {
            "name": "MalwareBazaar",
            "method": "POST",
            "url": "https://bazaar.abuse.ch/api/",
            "json": {"query": "get_info", "hash": PROBE_HASH},
            "headers": {"Content-Type": "application/json", "User-Agent": USER_AGENT},
            "skip_reason": None,
        },
        {
            "name": "ThreatFox",
            "method": "POST",
            "url": "https://threatfox.abuse.ch/api/",
            "json": {"query": "search_ioc", "hash": PROBE_HASH},
            "headers": {
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
                "API-KEY": threatfox_key,
            },
            "skip_reason": None if threatfox_key else "THREATFOX_API_KEY not set",
        },
        {
            "name": "AlienVault OTX (v1)",
            "method": "GET",
            "url": (
                "https://otx.alienvault.com/api/v1/indicators/file/sha256/"
                + PROBE_HASH
            ),
            "headers": {"User-Agent": USER_AGENT, "X-OTX-API-KEY": otx_key},
            "skip_reason": None if otx_key else "OTX_API_KEY not set",
        },
    ]
    return tests


def _run_probe(t: Dict[str, Any]) -> None:
    print(f"\n=== {t['name']} ===")
    if t["skip_reason"]:
        print(f"SKIP: {t['skip_reason']}")
        return
    try:
        if t["method"] == "POST":
            r = httpx.post(t["url"], json=t["json"], headers=t["headers"], timeout=15)
        else:
            r = httpx.get(t["url"], headers=t.get("headers"), timeout=15)
        print(f"Status     : {r.status_code}")
        print(f"Content-Type: {r.headers.get('content-type', '')}")
        print(f"First 400  : {r.text[:400]}")
    except Exception as e:  # noqa: BLE001 - dev probe
        print(f"Error: {type(e).__name__}: {e}")


def _basic_connectivity() -> None:
    print("\n=== Basic connectivity ===")
    for url in ("https://httpbin.org/get", "https://www.google.com"):
        try:
            r = httpx.get(url, timeout=5)
            print(f"{url}: {r.status_code}")
        except Exception as e:  # noqa: BLE001 - dev probe
            print(f"{url}: FAILED - {type(e).__name__}: {e}")


def main(argv: Optional[List[str]] = None) -> int:
    _ = argv  # currently unused
    for t in _build_tests():
        _run_probe(t)
    _basic_connectivity()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
