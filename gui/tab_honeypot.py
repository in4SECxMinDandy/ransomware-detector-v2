"""
gui/tab_honeypot.py
===================
Honeypot Management tab — CustomTkinter.

Features:
  - Deploy/Remove honeypot files
  - Active honeypots table with status
  - Access history timeline
  - 24h trigger counter badge
"""

import threading
from typing import List, Optional

import customtkinter as ctk
from tkinter import filedialog, messagebox


C = {
    "bg_dark":  "#0B0F14",
    "bg_panel": "#121821",
    "bg_card":  "#161E29",
    "border":   "#263042",
    "text":     "#E6EAF0",
    "text_dim": "#A3ADBD",
    "green":    "#22C55E",
    "red":      "#EF4444",
    "orange":   "#F59E0B",
    "yellow":   "#FACC15",
    "blue":     "#60A5FA",
    "accent":   "#3B82F6",
    "purple":   "#A78BFA",
}


class HoneypotTab(ctk.CTkFrame):
    """
    Tab for managing honeypot decoy files.
    Designed to be embedded inside MainWindow._build_page_container().
    """

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=C["bg_dark"], **kwargs)

        self._honeypot_manager = None
        self._refresh_job: Optional[str] = None
        self._setup_ui()
        self._start_refresh()

    def _setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # ── Title ───────────────────────────────────────────────────────────────
        title = ctk.CTkLabel(
            self, text="Giám sát tệp Honeypot",
            font=("Consolas", 14, "bold"), text_color=C["accent"]
        )
        title.grid(row=0, column=0, sticky="w", padx=12, pady=(12, 4))

        subtitle = ctk.CTkLabel(
            self,
            text="Triển khai tệp mồi để phát hiện hoạt động do thám và mã hóa của ransomware",
            font=("Consolas", 8), text_color=C["text_dim"], wraplength=700
        )
        subtitle.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 8))

        # ── Control bar ────────────────────────────────────────────────────────
        control_card = ctk.CTkFrame(self, fg_color=C["bg_card"], corner_radius=8,
                                    border_width=1, border_color=C["border"])
        control_card.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))
        control_card.grid_columnconfigure(5, weight=1)

        self._btn_deploy = ctk.CTkButton(
            control_card, text="Triển khai Honeypot", height=36,
            font=("Consolas", 10, "bold"), fg_color=C["green"],
            hover_color="#1EA34A", text_color=C["bg_dark"],
            command=self._on_deploy
        )
        self._btn_deploy.grid(row=0, column=0, padx=8, pady=8, sticky="w")

        self._btn_remove = ctk.CTkButton(
            control_card, text="Gỡ tất cả", height=36,
            font=("Consolas", 10), fg_color=C["bg_card"],
            hover_color=C["border"], text_color=C["text"],
            command=self._on_remove_all
        )
        self._btn_remove.grid(row=0, column=1, padx=(0, 8), pady=8, sticky="w")

        self._btn_refresh = ctk.CTkButton(
            control_card, text="Làm mới", height=36,
            font=("Consolas", 10), fg_color=C["bg_card"],
            hover_color=C["border"], text_color=C["text"],
            command=self._on_refresh
        )
        self._btn_refresh.grid(row=0, column=2, padx=(0, 8), pady=8, sticky="w")

        # Auto-deploy toggle
        self._auto_toggle = ctk.CTkSwitch(
            control_card, text="Tự deploy khi khởi động",
            font=("Consolas", 9), text_color=C["text_dim"],
            progress_color=C["accent"], fg_color=C["border"],
            command=self._on_auto_toggle
        )
        self._auto_toggle.grid(row=0, column=3, padx=(0, 8), pady=8, sticky="w")

        # 24h badge
        self._badge_lbl = ctk.CTkLabel(
            control_card, text="Trigger 24h: 0",
            font=("Consolas", 10, "bold"),
            text_color=C["bg_dark"],
            width=140, corner_radius=12
        )
        self._badge_lbl.configure(fg_color=C["green"])
        self._badge_lbl.grid(row=0, column=4, padx=(0, 8), pady=8, sticky="e")

        # ── Active honeypots table ─────────────────────────────────────────────
        hp_card = ctk.CTkFrame(self, fg_color=C["bg_card"], corner_radius=8,
                               border_width=1, border_color=C["border"])
        hp_card.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 4))
        hp_card.grid_columnconfigure(0, weight=1)
        hp_card.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(
            hp_card, text="Các tệp Honeypot đang hoạt động",
            font=("Consolas", 11, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        # Header
        header = ctk.CTkFrame(hp_card, fg_color=C["bg_panel"], height=28)
        header.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 1))
        header.pack_propagate(False)

        col_widths = [140, 300, 80, 120, 80, 80]
        col_labels = ["Tên", "Đường dẫn", "Trạng thái", "Lần truy cập cuối", "Số lượt truy cập", "Triggered"]
        for i, (w, lbl) in enumerate(zip(col_widths, col_labels)):
            f = ctk.CTkFrame(header, width=w, fg_color="transparent")
            f.pack(side="left", padx=2, fill="y", expand=True)
            f.pack_propagate(False)
            ctk.CTkLabel(f, text=lbl, font=("Consolas", 8, "bold"),
                        text_color=C["text_dim"]).pack(pady=4)

        self._hp_container = ctk.CTkScrollableFrame(
            hp_card, fg_color="transparent",
            scrollbar_button_color=C["border"],
            height=120
        )
        self._hp_container.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))

        ctk.CTkLabel(
            self._hp_container, text="Chưa triển khai Honeypot nào",
            font=("Consolas", 9), text_color=C["text_dim"]
        ).grid(row=0, column=0, pady=10)

        self._hp_rows: List[ctk.CTkFrame] = []

        # ── Access history table ───────────────────────────────────────────────
        history_card = ctk.CTkFrame(self, fg_color=C["bg_card"], corner_radius=8,
                                    border_width=1, border_color=C["border"])
        history_card.grid(row=4, column=0, sticky="nsew", padx=12, pady=(0, 4))
        history_card.grid_columnconfigure(0, weight=1)
        history_card.grid_rowconfigure(2, weight=1)
        self.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(
            history_card, text="Lịch sử truy cập",
            font=("Consolas", 11, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        # Header
        h_header = ctk.CTkFrame(history_card, fg_color=C["bg_panel"], height=28)
        h_header.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 1))
        h_header.pack_propagate(False)

        h_col_widths = [120, 140, 140, 60, 80, 80]
        h_col_labels = ["Thời gian", "Honeypot", "Process", "PID", "Sự kiện", "Mức độ"]
        for i, (w, lbl) in enumerate(zip(h_col_widths, h_col_labels)):
            f = ctk.CTkFrame(h_header, width=w, fg_color="transparent")
            f.pack(side="left", padx=2, fill="y", expand=True)
            f.pack_propagate(False)
            ctk.CTkLabel(f, text=lbl, font=("Consolas", 8, "bold"),
                        text_color=C["text_dim"]).pack(pady=4)

        self._history_container = ctk.CTkScrollableFrame(
            history_card, fg_color="transparent",
            scrollbar_button_color=C["border"],
            height=150
        )
        self._history_container.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))

        ctk.CTkLabel(
            self._history_container, text="Chưa có sự kiện truy cập",
            font=("Consolas", 9), text_color=C["text_dim"]
        ).grid(row=0, column=0, pady=10)

        self._history_rows: List[ctk.CTkFrame] = []

        # ── Status bar ────────────────────────────────────────────────────────
        self._status_lbl = ctk.CTkLabel(
            self, text="Chưa triển khai Honeypot nào",
            font=("Consolas", 9), text_color=C["text_dim"]
        )
        self._status_lbl.grid(row=5, column=0, sticky="ew", padx=12, pady=(0, 8))

    def set_honeypot_manager(self, manager):
        """Inject HoneypotManager from main window."""
        self._honeypot_manager = manager
        self._on_refresh()

    def _start_refresh(self):
        """Auto-refresh every 5 seconds."""
        self._refresh_job = self.after(5000, self._refresh_loop)

    def _refresh_loop(self):
        self._on_refresh()
        self._refresh_job = self.after(5000, self._refresh_loop)

    # ─── Actions ───────────────────────────────────────────────────────────────

    def _on_deploy(self):
        if not self._honeypot_manager:
            messagebox.showwarning("Lỗi", "Honeypot manager chưa được khởi tạo")
            return

        folder = filedialog.askdirectory(title="Chọn thư mục để triển khai Honeypot")
        if not folder:
            return

        self._btn_deploy.configure(state="disabled", text="Đang triển khai...")
        self._btn_remove.configure(state="disabled")

        def deploy_worker():
            try:
                deployed = self._honeypot_manager.deploy(folder, max_per_location=5)
                self.after(0, lambda: self._on_deploy_done(deployed))
            except Exception as e:
                self.after(0, lambda: self._on_deploy_error(str(e)))

        threading.Thread(target=deploy_worker, daemon=True).start()

    def _on_deploy_done(self, deployed):
        self._btn_deploy.configure(state="normal", text="Triển khai Honeypot")
        self._btn_remove.configure(state="normal")
        self._on_refresh()
        messagebox.showinfo("Triển khai", f"Đã triển khai {len(deployed)} tệp Honeypot")

    def _on_deploy_error(self, err):
        self._btn_deploy.configure(state="normal", text="Triển khai Honeypot")
        self._btn_remove.configure(state="normal")
        messagebox.showerror("Lỗi triển khai", str(err))

    def _on_remove_all(self):
        reply = messagebox.askyesno(
            "Gỡ Honeypot",
            "Gỡ tất cả tệp Honeypot đang hoạt động?"
        )
        if not reply or not self._honeypot_manager:
            return

        self._btn_deploy.configure(state="disabled")
        self._btn_remove.configure(state="disabled", text="Đang gỡ...")

        def remove_worker():
            try:
                removed = self._honeypot_manager.remove_all()
                self.after(0, lambda: self._on_remove_done(removed))
            except Exception as e:
                self.after(0, lambda: self._on_remove_error(str(e)))

        threading.Thread(target=remove_worker, daemon=True).start()

    def _on_remove_done(self, removed):
        self._btn_deploy.configure(state="normal")
        self._btn_remove.configure(state="normal", text="Gỡ tất cả")
        self._on_refresh()
        messagebox.showinfo("Gỡ", f"Đã gỡ {removed} tệp Honeypot")

    def _on_remove_error(self, err):
        self._btn_deploy.configure(state="normal")
        self._btn_remove.configure(state="normal", text="Gỡ tất cả")
        messagebox.showerror("Lỗi gỡ", str(err))

    def _on_refresh(self):
        if not self._honeypot_manager:
            return
        try:
            self._refresh_honeypots()
            self._refresh_history()
        except Exception as e:
            self._status_lbl.configure(text=f"Lỗi làm mới: {e}")

    def _refresh_honeypots(self):
        # Clear rows
        for row in self._hp_rows:
            row.destroy()
        self._hp_rows.clear()
        for w in self._hp_container.grid_slaves():
            if isinstance(w, ctk.CTkLabel) and "Chưa triển khai Honeypot" in w.cget("text"):
                w.destroy()

        honeypots = self._honeypot_manager.get_status()

        if not honeypots:
            ctk.CTkLabel(
                self._hp_container, text="Chưa triển khai Honeypot nào",
                font=("Consolas", 9), text_color=C["text_dim"]
            ).grid(row=0, column=0, pady=10)
            self._status_lbl.configure(text="Chưa triển khai Honeypot nào")
            return

        for row_idx, hp in enumerate(honeypots):
            row = ctk.CTkFrame(self._hp_container, fg_color=C["bg_card"],
                              border_width=1, border_color=C["border"],
                              height=28)
            row.pack(fill="x", padx=4, pady=1)
            row.pack_propagate(False)
            row.grid_columnconfigure(0, weight=0)
            row.grid_columnconfigure(1, weight=1)
            row.grid_columnconfigure(2, weight=0)
            row.grid_columnconfigure(3, weight=0)
            row.grid_columnconfigure(4, weight=0)
            row.grid_columnconfigure(5, weight=0)

            last_access = hp.last_accessed or "-"
            if last_access != "-" and "T" in str(last_access):
                last_access = str(last_access).split("T")[1][:8]

            status = "TRIGGERED" if hp.is_triggered else "Hoạt động"
            status_color = C["red"] if hp.is_triggered else C["green"]

            ctk.CTkLabel(row, text=hp.name[:20], font=("Consolas", 8),
                        text_color=C["text"]).grid(row=0, column=0, sticky="w", padx=6, pady=3)
            ctk.CTkLabel(row, text=hp.path[:45], font=("Consolas", 8),
                        text_color=C["text_dim"], anchor="w"
                        ).grid(row=0, column=1, sticky="w", padx=6, pady=3)

            st = ctk.CTkLabel(row, text=status, font=("Consolas", 8, "bold"),
                             text_color=C["bg_dark"], width=70)
            st.configure(fg_color=status_color, corner_radius=4)
            st.grid(row=0, column=2, padx=4, pady=3)

            ctk.CTkLabel(row, text=str(last_access), font=("Consolas", 8),
                        text_color=C["text_dim"]).grid(row=0, column=3, sticky="w", padx=6, pady=3)
            ctk.CTkLabel(row, text=str(hp.access_count), font=("Consolas", 8),
                        text_color=C["text_dim"]).grid(row=0, column=4, sticky="w", padx=6, pady=3)

            trig_text = "Có" if hp.is_triggered else "Không"
            trig_color = C["red"] if hp.is_triggered else C["green"]
            ctk.CTkLabel(row, text=trig_text, font=("Consolas", 8, "bold"),
                        text_color=trig_color).grid(row=0, column=5, sticky="w", padx=(6, 8), pady=3)

            self._hp_rows.append(row)

        # 24h badge
        try:
            triggered_24h = self._honeypot_manager.get_triggered_count(hours=24)
        except Exception:
            triggered_24h = 0

        self._badge_lbl.configure(
            text=f"Trigger 24h: {triggered_24h}",
            text_color=C["bg_dark"],
            fg_color=C["red"] if triggered_24h > 0 else C["green"]
        )
        self._status_lbl.configure(
            text=f"{len(honeypots)} Honeypot đang hoạt động",
            text_color=C["text_dim"]
        )

    def _refresh_history(self):
        for row in self._history_rows:
            row.destroy()
        self._history_rows.clear()
        for w in self._history_container.grid_slaves():
            if isinstance(w, ctk.CTkLabel) and "Chưa có sự kiện truy cập" in w.cget("text"):
                w.destroy()

        if not self._honeypot_manager:
            return

        try:
            history = self._honeypot_manager.get_access_history(limit=50)
        except Exception:
            history = []

        if not history:
            ctk.CTkLabel(
                self._history_container, text="Chưa có sự kiện truy cập",
                font=("Consolas", 9), text_color=C["text_dim"]
            ).grid(row=0, column=0, pady=10)
            return

        sev_color_map = {"CRITICAL": C["red"], "HIGH": C["orange"],
                        "MEDIUM": C["yellow"], "LOW": C["blue"]}

        for row_idx, event in enumerate(history):
            row = ctk.CTkFrame(self._history_container, fg_color=C["bg_card"],
                              border_width=1, border_color=C["border"],
                              height=28)
            row.pack(fill="x", padx=4, pady=1)
            row.pack_propagate(False)
            row.grid_columnconfigure(0, weight=0)
            row.grid_columnconfigure(1, weight=1)
            row.grid_columnconfigure(2, weight=1)
            row.grid_columnconfigure(3, weight=0)
            row.grid_columnconfigure(4, weight=0)
            row.grid_columnconfigure(5, weight=0)

            ts = event.timestamp.split("T")[1][:8] if "T" in event.timestamp else event.timestamp
            sev_color = sev_color_map.get(event.severity, C["text_dim"])

            ctk.CTkLabel(row, text=ts, font=("Consolas", 8),
                        text_color=C["text_dim"]).grid(row=0, column=0, sticky="w", padx=6, pady=3)
            ctk.CTkLabel(row, text=event.honeypot_name[:22], font=("Consolas", 8),
                        text_color=C["text"]).grid(row=0, column=1, sticky="w", padx=6, pady=3)
            ctk.CTkLabel(row, text=(event.process_name or "-")[:22], font=("Consolas", 8),
                        text_color=C["text_dim"]).grid(row=0, column=2, sticky="w", padx=6, pady=3)
            ctk.CTkLabel(row, text=str(event.pid) if event.pid else "-",
                        font=("Consolas", 8), text_color=C["text_dim"]
                        ).grid(row=0, column=3, sticky="w", padx=6, pady=3)
            ctk.CTkLabel(row, text=event.event_type, font=("Consolas", 8),
                        text_color=C["text"]).grid(row=0, column=4, sticky="w", padx=6, pady=3)
            ctk.CTkLabel(row, text=event.severity, font=("Consolas", 8, "bold"),
                        text_color=sev_color).grid(row=0, column=5, sticky="w", padx=(6, 8), pady=3)

            self._history_rows.append(row)

        total = len(history)
        self._status_lbl.configure(
            text=f"{total} sự kiện truy cập",
            text_color=C["text_dim"]
        )

    def _on_auto_toggle(self):
        try:
            from core.config_manager import config
            enabled = self._auto_toggle.get() == 1
            config.set("honeypot.auto_deploy", enabled)
        except Exception:
            pass
