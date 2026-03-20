"""
debug_gui.py — Chạy file này để kiểm tra GUI độc lập
Usage: python debug_gui.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import customtkinter as ctk


def test_bare_window():
    """Test 1: Cửa sổ trống có hiện không?"""
    print("[TEST 1] Bare CTk window...")
    root = ctk.CTk()
    root.title("TEST - Bare Window")
    root.geometry("400x300")
    ctk.CTkLabel(root, text="CTk renders OK").pack(pady=20)
    ctk.CTkButton(root, text="Close", command=root.destroy).pack()
    root.mainloop()
    print("[TEST 1] PASSED")


def test_import_main_window():
    """Test 2: Import main_window.py có lỗi không?"""
    print("[TEST 2] Importing gui.main_window...")
    try:
        from gui.main_window import RansomwareDetectorApp, launch
        print("[TEST 2] PASSED — Import OK")
        return True
    except Exception as e:
        print(f"[TEST 2] FAILED — Import error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_launch():
    """Test 3: Chạy launch() trực tiếp"""
    print("[TEST 3] Running launch()...")
    try:
        from gui.main_window import launch
        launch()
        print("[TEST 3] PASSED")
    except Exception as e:
        print(f"[TEST 3] FAILED: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("=" * 50)
    print("  GUI DIAGNOSTIC TOOL")
    print("=" * 50)

    # Run diagnostics
    test_bare_window()

    if test_import_main_window():
        test_launch()
    else:
        print("\nFix import errors above before testing launch()")
