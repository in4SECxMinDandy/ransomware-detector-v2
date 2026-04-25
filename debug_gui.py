"""DEPRECATED — moved to ``scripts/dev/gui_diagnostic.py``.

Run instead:

    python -m scripts.dev.gui_diagnostic
"""
import sys

print(
    "debug_gui.py is deprecated. Use:\n"
    "    python -m scripts.dev.gui_diagnostic",
    file=sys.stderr,
)
sys.exit(2)
