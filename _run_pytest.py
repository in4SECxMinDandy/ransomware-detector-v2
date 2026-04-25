"""DEPRECATED — moved to ``scripts/dev/run_pytest_capture.py``.

Run instead:

    python -m scripts.dev.run_pytest_capture [tests/...]
"""
import sys

print(
    "_run_pytest.py is deprecated. Use:\n"
    "    python -m scripts.dev.run_pytest_capture",
    file=sys.stderr,
)
sys.exit(2)
