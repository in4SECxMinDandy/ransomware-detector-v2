"""
whitelist_editor.py — v2.1 (MỚI)
===================================
Whitelist Editor — Cửa sổ quản lý danh sách trắng.

Cho phép người dùng:
  - Xem toàn bộ whitelist hiện tại (extensions + paths + rules)
  - Thêm / xóa extension (ví dụ: .py, .docx)
  - Thêm / xóa path pattern (ví dụ: /home/user/safe_folder)
  - Lưu whitelist ra file JSON (persistent giữa các session)
  - Import/Export whitelist dạng JSON
  - Reset về whitelist mặc định

Tích hợp với fp_reducer.py:
  - Load/save từ data/whitelist.json
  - Khi thêm extension → ghi ngay vào EXTENSION_THRESHOLDS
  - Khi thêm path → ghi ngay vào ALWAYS_SAFE_PATH_KEYWORDS
"""

import os
import json
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from typing import Dict, Set, List, Optional
from datetime import datetime

import customtkinter as ctk

# ─── Color Palette (đồng bộ main_window) ───
C = {
    "bg_dark":  "#0D1117",
    "bg_panel": "#161B22",
    "bg_card":  "#1C2128",
    "border":   "#30363D",
    "text":     "#C9D1D9",
    "text_dim": "#8B949E",
    "green":    "#00FF88",
    "red":      "#FF2D2D",
    "orange":   "#FF8C00",
    "yellow":   "#FFD700",
    "blue":     "#58A6FF",
    "cyan":     "#00BFFF",
    "accent":   "#238636",
    "accent_h": "#2EA043",
    "danger":   "#DA3633",
    "purple":   "#BC8CFF",
}

# ─── Whitelist storage path ───
WHITELIST_DIR  = os.path.join(os.path.dirname(__file__), "..", "data")
WHITELIST_PATH = os.path.join(WHITELIST_DIR, "whitelist.json")

# ─── Default whitelist ───
DEFAULT_WHITELIST = {
    "extensions": [
        ".ttf", ".otf", ".woff", ".woff2", ".eot",
        ".ico", ".cur", ".ani",
        ".lnk", ".url",
        ".log", ".ini", ".cfg", ".conf",
        ".tmp", ".temp", ".cache", ".bak",
        ".idx", ".db-wal", ".db-shm",
        ".thm",
    ],
    "path_keywords": [
        "windows\\system32",
        "windows\\syswow64",
        "program files\\windows defender",
        "/proc/",
        "/sys/",
        "/dev/",
        "/__pycache__/",
        "/site-packages/",
        "/.git/",
        "/node_modules/",
    ],
    "custom_paths": [],    # user-defined safe paths
    "custom_extensions": [],  # user-defined safe extensions
    "last_modified": "",
    "version": "2.1",
}


def load_whitelist() -> Dict:
    """Load whitelist từ file JSON, fallback về default nếu không có."""
    os.makedirs(WHITELIST_DIR, exist_ok=True)
    if os.path.isfile(WHITELIST_PATH):
        try:
            with open(WHITELIST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Merge với default (đảm bảo có đủ keys)
            for key, val in DEFAULT_WHITELIST.items():
                if key not in data:
                    data[key] = val
            return data
        except Exception:
            pass
    return dict(DEFAULT_WHITELIST)


def save_whitelist(data: Dict) -> bool:
    """Lưu whitelist ra file JSON."""
    try:
        os.makedirs(WHITELIST_DIR, exist_ok=True)
        data["last_modified"] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        with open(WHITELIST_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[Whitelist] Save failed: {e}")
        return False


def apply_whitelist_to_fp_reducer(whitelist: Dict):
    """Áp dụng whitelist vào fp_reducer module (runtime update)."""
    try:
        from core.fp_reducer import (
            ALWAYS_SAFE_EXTENSIONS,
            ALWAYS_SAFE_PATH_KEYWORDS,
        )
        # Add custom extensions
        for ext in whitelist.get("custom_extensions", []):
            ext = ext.lower().strip()
            if ext and not ext.startswith("."):
                ext = "." + ext
            ALWAYS_SAFE_EXTENSIONS.add(ext)

        # Add custom paths
        for path in whitelist.get("custom_paths", []):
            path = path.lower().strip()
            if path:
                ALWAYS_SAFE_PATH_KEYWORDS.add(path)
    except Exception as e:
        print(f"[Whitelist] Apply to FP reducer failed: {e}")


class WhitelistEditorWindow(ctk.CTkToplevel):
    """
    Cửa sổ Whitelist Editor — hiện thị từ menu main_window.

    Tabs:
      1. Extensions     — danh sách extension luôn SAFE
      2. Path Keywords  — keyword trong path luôn SAFE
      3. Custom Paths   — paths do user thêm vào
    """

    def __init__(self, parent):
        super().__init__(parent)
        self.title("Whitelist Editor — Quản lý Danh sách Trắng")
        self.geometry("800x600")
        self.configure(fg_color=C["bg_dark"])
        self.resizable(True, True)
        self.attributes("-topmost", False)

        self._whitelist = load_whitelist()
        self._modified  = False

        self._build_ui()
        self._load_data()

    # ─────────────────────────── BUILD UI ───────────────────────────

    def _build_ui(self):
        # Header
        hdr = ctk.CTkFrame(self, fg_color=C["bg_panel"], height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        ctk.CTkLabel(
            hdr, text="◈  WHITELIST EDITOR",
            font=ctk.CTkFont(family="Consolas", size=15, weight="bold"),
            text_color=C["cyan"]
        ).pack(side="left", padx=15, pady=10)

        ctk.CTkLabel(
            hdr, text="Files trong whitelist sẽ không bao giờ bị cảnh báo",
            font=ctk.CTkFont(family="Consolas", size=8),
            text_color=C["text_dim"]
        ).pack(side="left", padx=5, pady=10)

        self._modified_lbl = ctk.CTkLabel(
            hdr, text="",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=C["orange"]
        )
        self._modified_lbl.pack(side="right", padx=15)

        # TabView
        tabs = ctk.CTkTabview(
            self,
            fg_color=C["bg_panel"],
            segmented_button_fg_color=C["bg_card"],
            segmented_button_selected_color=C["accent"],
            segmented_button_unselected_color=C["bg_card"],
            text_color=C["text"],
        )
        tabs.pack(fill="both", expand=True, padx=8, pady=8)

        tab1 = tabs.add("Extensions")
        tab2 = tabs.add("Path Keywords")
        tab3 = tabs.add("Custom Paths")
        tabs.set("Extensions")

        self._build_list_tab(
            tab1,
            list_key="extensions",
            title="Extensions luôn bỏ qua (fonts, icons, system files)",
            example=".ttf, .ico, .log, .tmp",
            placeholder=".myext",
        )
        self._build_list_tab(
            tab2,
            list_key="path_keywords",
            title="Từ khóa trong đường dẫn → bỏ qua (system paths)",
            example="windows\\system32, /proc/, /.git/",
            placeholder="/safe/folder",
        )
        self._build_list_tab(
            tab3,
            list_key="custom_paths",
            title="Đường dẫn cụ thể do bạn thêm vào",
            example="/home/user/documents, C:\\Users\\trusted",
            placeholder="C:\\Users\\myuser\\safe",
        )

        # Bottom buttons
        btn_frame = ctk.CTkFrame(self, fg_color=C["bg_panel"], height=55)
        btn_frame.pack(fill="x", padx=8, pady=(0, 8))
        btn_frame.pack_propagate(False)

        ctk.CTkButton(
            btn_frame, text="💾  Lưu Whitelist",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            fg_color=C["accent"], hover_color=C["accent_h"],
            text_color="#FFF", height=36, width=160, corner_radius=6,
            command=self._save
        ).pack(side="left", padx=(12, 6), pady=9)

        ctk.CTkButton(
            btn_frame, text="📤  Export JSON",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["bg_card"], hover_color=C["border"],
            text_color=C["text"], height=36, width=130, corner_radius=6,
            command=self._export
        ).pack(side="left", padx=4, pady=9)

        ctk.CTkButton(
            btn_frame, text="📥  Import JSON",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["bg_card"], hover_color=C["border"],
            text_color=C["text"], height=36, width=130, corner_radius=6,
            command=self._import
        ).pack(side="left", padx=4, pady=9)

        ctk.CTkButton(
            btn_frame, text="↺  Reset Default",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["bg_card"], hover_color=C["danger"],
            text_color=C["text_dim"], height=36, width=130, corner_radius=6,
            command=self._reset_default
        ).pack(side="left", padx=4, pady=9)

        self._status_lbl = ctk.CTkLabel(
            btn_frame, text="",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=C["green"]
        )
        self._status_lbl.pack(side="right", padx=15)

    def _build_list_tab(
        self,
        parent,
        list_key: str,
        title: str,
        example: str,
        placeholder: str,
    ):
        """Build một tab với listbox + add/remove controls."""
        ctk.CTkLabel(
            parent, text=title,
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=C["text_dim"],
            wraplength=700
        ).pack(anchor="w", padx=8, pady=(8, 2))

        ctk.CTkLabel(
            parent, text=f"Ví dụ: {example}",
            font=ctk.CTkFont(family="Consolas", size=8),
            text_color=C["text_dim"]
        ).pack(anchor="w", padx=8, pady=(0, 4))

        # Listbox
        list_frame = ctk.CTkFrame(parent, fg_color=C["bg_card"], corner_radius=6)
        list_frame.pack(fill="both", expand=True, padx=8, pady=(0, 4))

        lb = tk.Listbox(
            list_frame,
            bg=C["bg_dark"], fg=C["text"],
            selectbackground=C["accent"], selectforeground="#FFF",
            font=("Consolas", 9),
            relief="flat", bd=0,
            activestyle="none",
            height=12,
        )
        sb = tk.Scrollbar(list_frame, orient="vertical", command=lb.yview)
        lb.configure(yscrollcommand=sb.set)
        lb.pack(side="left", fill="both", expand=True, padx=(4, 0), pady=4)
        sb.pack(side="right", fill="y", pady=4)

        # Add/Remove row
        ctrl_frame = ctk.CTkFrame(parent, fg_color="transparent")
        ctrl_frame.pack(fill="x", padx=8, pady=4)

        entry_var = tk.StringVar()
        entry = ctk.CTkEntry(
            ctrl_frame, textvariable=entry_var,
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["bg_dark"], border_color=C["border"],
            text_color=C["text"],
            placeholder_text=placeholder,
            height=32, width=350
        )
        entry.pack(side="left", padx=(0, 6))
        entry.bind("<Return>", lambda e, lk=list_key, lb_w=lb, ev=entry_var:
                   self._add_item(lk, lb_w, ev))

        ctk.CTkButton(
            ctrl_frame, text="+ Thêm",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            fg_color=C["accent"], hover_color=C["accent_h"],
            text_color="#FFF", height=32, width=90, corner_radius=6,
            command=lambda lk=list_key, lb_w=lb, ev=entry_var:
                    self._add_item(lk, lb_w, ev)
        ).pack(side="left", padx=(0, 4))

        ctk.CTkButton(
            ctrl_frame, text="✕ Xóa",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["bg_card"], hover_color=C["danger"],
            text_color=C["text_dim"], height=32, width=90, corner_radius=6,
            command=lambda lk=list_key, lb_w=lb:
                    self._remove_item(lk, lb_w)
        ).pack(side="left", padx=(0, 4))

        # Browse button for paths
        if "path" in list_key or "custom" in list_key:
            ctk.CTkButton(
                ctrl_frame, text="📁 Browse",
                font=ctk.CTkFont(family="Consolas", size=9),
                fg_color=C["bg_card"], hover_color=C["border"],
                text_color=C["text_dim"], height=32, width=90, corner_radius=6,
                command=lambda ev=entry_var: self._browse_path(ev)
            ).pack(side="left")

        # Count label
        count_lbl = ctk.CTkLabel(
            ctrl_frame, text="0 entries",
            font=ctk.CTkFont(family="Consolas", size=8),
            text_color=C["text_dim"]
        )
        count_lbl.pack(side="right")

        # Store references
        setattr(self, f"_lb_{list_key}", lb)
        setattr(self, f"_count_lbl_{list_key}", count_lbl)

    # ─────────────────────────── DATA ───────────────────────────

    def _load_data(self):
        """Load whitelist data vào các listbox."""
        for key in ["extensions", "path_keywords", "custom_paths"]:
            lb = getattr(self, f"_lb_{key}")
            lb.delete(0, tk.END)
            items = self._whitelist.get(key, [])
            for item in sorted(items):
                lb.insert(tk.END, item)
            self._update_count(key)

    def _update_count(self, list_key: str):
        lb  = getattr(self, f"_lb_{list_key}")
        lbl = getattr(self, f"_count_lbl_{list_key}")
        n   = lb.size()
        lbl.configure(text=f"{n} entries")

    def _add_item(self, list_key: str, lb: tk.Listbox, entry_var: tk.StringVar):
        """Thêm một entry vào listbox và whitelist."""
        value = entry_var.get().strip()
        if not value:
            return

        # Normalize extensions
        if list_key == "extensions":
            if not value.startswith("."):
                value = "." + value
            value = value.lower()

        # Check trùng
        current = list(lb.get(0, tk.END))
        if value in current:
            self._status("⚠ Đã có trong danh sách", C["orange"])
            return

        lb.insert(tk.END, value)
        if value not in self._whitelist.get(list_key, []):
            self._whitelist.setdefault(list_key, []).append(value)
        entry_var.set("")
        self._update_count(list_key)
        self._mark_modified()

    def _remove_item(self, list_key: str, lb: tk.Listbox):
        """Xóa entry đã chọn."""
        sel = lb.curselection()
        if not sel:
            self._status("⚠ Chọn một dòng để xóa", C["orange"])
            return
        value = lb.get(sel[0])
        lb.delete(sel[0])
        items = self._whitelist.get(list_key, [])
        if value in items:
            items.remove(value)
        self._update_count(list_key)
        self._mark_modified()

    def _browse_path(self, entry_var: tk.StringVar):
        """Mở dialog chọn thư mục."""
        path = filedialog.askdirectory(title="Chọn thư mục an toàn")
        if path:
            entry_var.set(path)

    def _mark_modified(self):
        self._modified = True
        self._modified_lbl.configure(text="● Chưa lưu")

    def _status(self, msg: str, color: str = None):
        self._status_lbl.configure(
            text=msg,
            text_color=color or C["green"]
        )
        self.after(3000, lambda: self._status_lbl.configure(text=""))

    # ─────────────────────────── ACTIONS ───────────────────────────

    def _save(self):
        """Lưu whitelist ra file."""
        # Đồng bộ từ listbox vào whitelist dict
        for key in ["extensions", "path_keywords", "custom_paths"]:
            lb = getattr(self, f"_lb_{key}")
            self._whitelist[key] = list(lb.get(0, tk.END))

        if save_whitelist(self._whitelist):
            apply_whitelist_to_fp_reducer(self._whitelist)
            self._modified = False
            self._modified_lbl.configure(text="")
            self._status(
                f"✓ Đã lưu whitelist ({sum(len(self._whitelist.get(k,[])) for k in ['extensions','path_keywords','custom_paths'])} entries)",
                C["green"]
            )
        else:
            self._status("❌ Lưu thất bại", C["red"])

    def _export(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile="ransomware_detector_whitelist.json",
            title="Export Whitelist"
        )
        if path:
            for key in ["extensions", "path_keywords", "custom_paths"]:
                lb = getattr(self, f"_lb_{key}")
                self._whitelist[key] = list(lb.get(0, tk.END))
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self._whitelist, f, indent=2, ensure_ascii=False)
                self._status(f"✓ Exported: {os.path.basename(path)}", C["green"])
            except Exception as e:
                self._status(f"❌ Export thất bại: {e}", C["red"])

    def _import(self):
        path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json")],
            title="Import Whitelist"
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for key, val in DEFAULT_WHITELIST.items():
                    if key not in data:
                        data[key] = val
                self._whitelist = data
                self._load_data()
                self._mark_modified()
                self._status("✓ Import thành công", C["green"])
            except Exception as e:
                self._status(f"❌ Import thất bại: {e}", C["red"])

    def _reset_default(self):
        if messagebox.askyesno(
            "Reset Whitelist",
            "Reset về whitelist mặc định?\nMọi thay đổi sẽ bị mất.",
            parent=self
        ):
            self._whitelist = dict(DEFAULT_WHITELIST)
            self._load_data()
            self._mark_modified()
            self._status("↺ Đã reset về mặc định", C["orange"])

    def on_closing(self):
        if self._modified:
            if messagebox.askyesno(
                "Chưa lưu",
                "Bạn có thay đổi chưa lưu. Lưu trước khi đóng?",
                parent=self
            ):
                self._save()
        self.destroy()
