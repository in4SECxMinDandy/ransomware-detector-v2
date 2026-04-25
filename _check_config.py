"""DEPRECATED — moved to ``scripts/dev/check_config.py``.

Run instead:

    python -m scripts.dev.check_config
"""
import sys

print(
    "_check_config.py is deprecated. Use:\n"
    "    python -m scripts.dev.check_config",
    file=sys.stderr,
)
sys.exit(2)
