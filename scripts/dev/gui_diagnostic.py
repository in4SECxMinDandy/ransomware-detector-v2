"""Manual GUI smoke tests.

Stages:
1. Bare ``customtkinter`` window (verifies CTk + Tk are functional).
2. Import-only check for ``gui.main_window`` (catches lambda /
   syntax / module-import regressions).
3. Full ``launch()`` of the application window.

Run with::

    python -m scripts.dev.gui_diagnostic
"""

from __future__ import annotations

import os
import sys


# Allow direct ``python scripts/dev/gui_diagnostic.py`` invocation too.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    import customtkinter as ctk
except ImportError:  # pragma: no cover - dev tool
    print("customtkinter is not installed. Run: pip install -r requirements.txt")
    sys.exit(1)


def test_bare_window() -> None:
    print("[TEST 1] Bare CTk window...")
    root = ctk.CTk()
    root.title("TEST - Bare Window")
    root.geometry("400x300")
    ctk.CTkLabel(root, text="CTk renders OK").pack(pady=20)
    ctk.CTkButton(root, text="Close", command=root.destroy).pack()
    root.mainloop()
    print("[TEST 1] PASSED")


def test_import_main_window() -> bool:
    print("[TEST 2] Importing gui.main_window...")
    try:
        import gui.main_window  # noqa: F401
        print("[TEST 2] PASSED")
        return True
    except Exception as e:  # noqa: BLE001
        print(f"[TEST 2] FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_launch() -> None:
    print("[TEST 3] Running launch()...")
    try:
        from gui.main_window import launch
        launch()
        print("[TEST 3] PASSED")
    except Exception as e:  # noqa: BLE001
        print(f"[TEST 3] FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


def main() -> int:
    print("=" * 50)
    print("  GUI DIAGNOSTIC TOOL")
    print("=" * 50)

    test_bare_window()

    if test_import_main_window():
        test_launch()
    else:
        print("\nFix import errors above before testing launch()")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
