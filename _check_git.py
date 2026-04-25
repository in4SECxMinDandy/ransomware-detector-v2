"""DEPRECATED — moved to ``scripts/dev/check_git_tracking.py``.

Run instead:

    python -m scripts.dev.check_git_tracking
"""
import sys

print(
    "_check_git.py is deprecated. Use:\n"
    "    python -m scripts.dev.check_git_tracking",
    file=sys.stderr,
)
sys.exit(2)
