"""DEPRECATED — moved to ``scripts/dev/probe_threat_intel.py``.

The original version of this file embedded real ThreatFox and OTX API
keys in plaintext. Those credentials must be considered LEAKED and
rotated. The functional replacement reads keys from environment
variables only; see ``scripts/dev/README.md``.

Delete this stub once your local workflows are updated.
"""
import sys

print(
    "_api_test2.py is deprecated. Use:\n"
    "    set THREATFOX_API_KEY=...\n"
    "    set OTX_API_KEY=...\n"
    "    python -m scripts.dev.probe_threat_intel",
    file=sys.stderr,
)
sys.exit(2)
