"""DEPRECATED — equivalent coverage now lives under ``tests/``.

This historical script was a manual smoke test for PE analyzer +
scanner integration. Pytest does not pick it up at the repository root
(it's outside ``testpaths``) and the same scenarios are covered by:

  * ``tests/test_pe_analyzer.py``     — PE parsing / RWX detection
  * ``tests/test_injection_detector.py`` — process injection signals
  * ``tests/test_scanner_vt_fusion.py`` — full scanner pipeline

Delete this stub once you've confirmed your local workflows use the
proper pytest tests.
"""
import sys

print(
    "test_injection.py at repo root is deprecated.\n"
    "Use the tests under ``tests/`` instead:\n"
    "    pytest tests/test_pe_analyzer.py tests/test_injection_detector.py",
    file=sys.stderr,
)
sys.exit(2)
