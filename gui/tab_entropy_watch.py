"""
gui/tab_entropy_watch.py
=========================
Real-time Entropy Watch tab — CustomTkinter.

Features:
  - Enable/disable entropy monitoring toggle
  - Real-time line chart of Shannon entropy values
  - Danger level indicator (0-10 scale with color gradient)
  - Recent files list with entropy values
"""

import os
from datetime import datetime
from typing import List, Dict, Any, Optional

import customtkinter as ctk
from tkinter import messagebox


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


class EntropyWatchTab(ctk.CTkFrame):
    """
    Tab for real-time entropy monitoring and burst detection.
    Designed to be embedded inside MainWindow._build_page_container().
    """

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=C["bg_dark"], **kwargs)

        self._entropy_data: List[float] = []
        self._entropy_timestamps: List[str] = []
        self._recent_files: List[Dict[str, Any]] = []
        self._is_enabled = False
        self._update_job: Optional[str] = None
        self._current_consecutive = 0
        self._danger_score = 0

        self._setup_ui()

    def _setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # ── Title ───────────────────────────────────────────────────────────────
        title = ctk.CTkLabel(
            self, text="Theo dõi Entropy thời gian thực",
            font=("Consolas", 14, "bold"), text_color=C["accent"]
        )
        title.grid(row=0, column=0, sticky="w", padx=12, pady=(12, 4))

        subtitle = ctk.CTkLabel(
            self,
            text="Giám sát Shannon entropy của các tệp bị sửa đổi - phát hiện mẫu mã hóa ransomware",
            font=("Consolas", 8), text_color=C["text_dim"], wraplength=700
        )
        subtitle.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 8))

        # ── Control bar ────────────────────────────────────────────────────────
        control_card = ctk.CTkFrame(self, fg_color=C["bg_card"], corner_radius=8,
                                    border_width=1, border_color=C["border"])
        control_card.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))
        control_card.grid_columnconfigure(1, weight=1)

        # Enable toggle
        self._enable_toggle = ctk.CTkSwitch(
            control_card, text="Bật giám sát Entropy",
            font=("Consolas", 10, "bold"), text_color=C["text"],
            progress_color=C["accent"], fg_color=C["border"],
            button_color=C["border"], button_hover_color=C["accent"],
            command=self._on_enable_changed
        )
        self._enable_toggle.grid(row=0, column=0, sticky="w", padx=12, pady=8)

        self._threshold_lbl = ctk.CTkLabel(
            control_card, text="Threshold: 7.5",
            font=("Consolas", 9), text_color=C["text_dim"]
        )
        self._threshold_lbl.grid(row=0, column=2, padx=8, pady=8)

        self._fps_lbl = ctk.CTkLabel(
            control_card, text="Tệp/s: 0",
            font=("Consolas", 9), text_color=C["text_dim"]
        )
        self._fps_lbl.grid(row=0, column=3, padx=8, pady=8)

        self._consecutive_lbl = ctk.CTkLabel(
            control_card, text="Liên tiếp: 0 / 5",
            font=("Consolas", 9), text_color=C["text_dim"]
        )
        self._consecutive_lbl.grid(row=0, column=4, padx=(8, 12), pady=8)

        # ── Charts row ─────────────────────────────────────────────────────────
        charts_row = ctk.CTkFrame(self, fg_color="transparent")
        charts_row.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 8))
        charts_row.grid_columnconfigure(0, weight=3)
        charts_row.grid_columnconfigure(1, weight=1)

        # Entropy chart
        chart_card = ctk.CTkFrame(charts_row, fg_color=C["bg_card"], corner_radius=8,
                                  border_width=1, border_color=C["border"])
        chart_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        chart_card.grid_rowconfigure(0, weight=1)
        chart_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            chart_card, text="Shannon Entropy theo thời gian",
            font=("Consolas", 10, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="nw", padx=12, pady=(8, 0))

        from gui.components.plot_frame import PlotFrame
        self._entropy_chart = PlotFrame(chart_card, figsize=(8, 3.5))
        self._entropy_chart.plot_entropy_realtime([], [], threshold=7.5)
        self._entropy_chart.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)

        # Danger gauge
        gauge_card = ctk.CTkFrame(charts_row, fg_color=C["bg_card"], corner_radius=8,
                                  border_width=1, border_color=C["border"])
        gauge_card.grid(row=0, column=1, sticky="nsew")
        gauge_card.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            gauge_card, text="Mức độ nguy hiểm",
            font=("Consolas", 10, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="nw", padx=12, pady=(8, 4))

        self._danger_gauge = PlotFrame(gauge_card, figsize=(3, 3.5))
        self._danger_gauge.signal_gauge(0.0, "Điểm đe dọa")
        self._danger_gauge.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))

        self._danger_score_lbl = ctk.CTkLabel(
            gauge_card, text="0 / 10",
            font=("Consolas", 14, "bold"), text_color=C["green"],
            justify="center"
        )
        self._danger_score_lbl.grid(row=2, column=0, pady=(0, 4))

        # Consecutive progress bar
        ctk.CTkLabel(
            gauge_card, text="Số tệp Entropy cao liên tiếp:",
            font=("Consolas", 8), text_color=C["text_dim"]
        ).grid(row=3, column=0, sticky="w", padx=12, pady=(4, 0))

        self._consecutive_bar = ctk.CTkProgressBar(
            gauge_card, height=10,
            progress_color=C["orange"], fg_color=C["border"]
        )
        self._consecutive_bar.grid(row=4, column=0, sticky="ew", padx=12, pady=(4, 8))
        self._consecutive_bar.set(0)

        # ── Recent files table ─────────────────────────────────────────────────
        table_card = ctk.CTkFrame(self, fg_color=C["bg_card"], corner_radius=8,
                                  border_width=1, border_color=C["border"])
        table_card.grid(row=4, column=0, sticky="nsew", padx=12, pady=(0, 8))
        table_card.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(
            table_card, text="Các thay đổi tệp gần đây",
            font=("Consolas", 10, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        # Header row
        header_row = ctk.CTkFrame(table_card, fg_color=C["bg_panel"], height=28)
        header_row.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 1))
        header_row.pack_propagate(False)

        col_widths = [80, 280, 80, 80]
        col_labels = ["Thời gian", "Tệp", "Entropy", "Rủi ro"]
        for i, (w, lbl) in enumerate(zip(col_widths, col_labels)):
            f = ctk.CTkFrame(header_row, width=w, fg_color="transparent")
            f.pack(side="left", padx=2, fill="y", expand=True)
            f.pack_propagate(False)
            ctk.CTkLabel(f, text=lbl, font=("Consolas", 8, "bold"),
                        text_color=C["text_dim"]).pack(pady=4)

        self._recent_container = ctk.CTkScrollableFrame(
            table_card, fg_color="transparent",
            scrollbar_button_color=C["border"],
            height=150
        )
        self._recent_container.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self._recent_container.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self._recent_container, text="Chưa có tệp nào được giám sát",
            font=("Consolas", 9), text_color=C["text_dim"]
        ).grid(row=0, column=0, pady=10)

        self._recent_rows: List[ctk.CTkFrame] = []

        # ── Status bar ────────────────────────────────────────────────────────
        self._status_lbl = ctk.CTkLabel(
            self, text="Giám sát Entropy đang tắt",
            font=("Consolas", 9), text_color=C["text_dim"]
        )
        self._status_lbl.grid(row=5, column=0, sticky="ew", padx=12, pady=(0, 8))

    def _on_enable_changed(self):
        self._is_enabled = self._enable_toggle.get() == 1
        if self._is_enabled:
            self._status_lbl.configure(text="Giám sát Entropy đang hoạt động", text_color=C["green"])
            self._schedule_update()
        else:
            self._status_lbl.configure(text="Giám sát Entropy đang tắt", text_color=C["text_dim"])
            if self._update_job:
                self.after_cancel(self._update_job)
                self._update_job = None

    def _schedule_update(self):
        if not self._is_enabled:
            return
        self._update_display()
        self._update_job = self.after(2000, self._schedule_update)

    def _update_display(self):
        # Update chart
        if self._entropy_timestamps:
            self._entropy_chart.plot_entropy_realtime(
                self._entropy_timestamps[-50:],
                self._entropy_data[-50:],
                threshold=7.5
            )

        # Update danger gauge
        danger = self._danger_score / 10.0
        self._danger_gauge.signal_gauge(danger, "Điểm đe dọa")

        score_color = C["red"] if self._danger_score >= 7 else C["orange"] if self._danger_score >= 4 else C["green"]
        self._danger_score_lbl.configure(text=f"{self._danger_score} / 10", text_color=score_color)

        # Update consecutive bar
        self._consecutive_bar.set(self._current_consecutive / 5.0)
        self._consecutive_lbl.configure(
            text=f"Liên tiếp: {self._current_consecutive} / 5",
            text_color=C["red"] if self._current_consecutive >= 3 else C["text_dim"]
        )

    def add_entropy_entry(self, file_path: str, entropy: float, timestamp: Optional[str] = None):
        """Add an entropy reading from RealTimeMonitor. Called by main window.

        Audit note: pre-fix the body of this method had been corrupted by
        a partially-applied refactor — duplicated state-update blocks were
        left at class-body indentation and a UI-row-building block
        referenced an undefined ``row`` symbol. The whole method has been
        restructured so it (a) updates internal state, (b) creates a row
        in the "recent files" table, and (c) refreshes the burst alert
        without ever raising NameError.
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%H:%M:%S")

        # ── State update ────────────────────────────────────────────────────
        self._entropy_data.append(entropy)
        self._entropy_timestamps.append(timestamp)

        if len(self._entropy_data) > 200:
            self._entropy_data = self._entropy_data[-200:]
            self._entropy_timestamps = self._entropy_timestamps[-200:]

        # Update danger score
        if entropy > 7.5:
            self._current_consecutive = min(5, self._current_consecutive + 1)
            self._danger_score = min(10, self._danger_score + 2)
        else:
            self._current_consecutive = max(0, self._current_consecutive - 1)
            self._danger_score = max(0, self._danger_score - 1)

        # Append to the recent-files history buffer.
        self._recent_files.insert(0, {
            "time": timestamp,
            "file": os.path.basename(file_path),
            "path": file_path,
            "entropy": entropy,
        })
        if len(self._recent_files) > 100:
            self._recent_files = self._recent_files[:100]

        # ── Build a row in the "recent files" table ─────────────────────────
        # Drop the placeholder label the first time we actually have data.
        for w in self._recent_container.grid_slaves():
            if isinstance(w, ctk.CTkLabel) and "Chưa có tệp" in w.cget("text"):
                w.destroy()

        risk = "HIGH" if entropy > 7.5 else "MEDIUM" if entropy > 6.0 else "LOW"
        risk_color_map = {"HIGH": C["red"], "MEDIUM": C["orange"], "LOW": C["green"]}
        risk_color = risk_color_map.get(risk, C["text_dim"])

        row = ctk.CTkFrame(
            self._recent_container,
            fg_color=C["bg_card"],
            border_width=1,
            border_color=C["border"],
            height=28,
        )
        row.pack(fill="x", padx=4, pady=1)
        row.pack_propagate(False)

        ctk.CTkLabel(
            row, text=timestamp, font=("Consolas", 8),
            text_color=C["text_dim"], width=80,
        ).pack(side="left", padx=6, pady=3)
        ctk.CTkLabel(
            row, text=os.path.basename(file_path)[:40],
            font=("Consolas", 8), text_color=C["text"],
            anchor="w", width=280,
        ).pack(side="left", padx=6, pady=3, fill="x", expand=True)
        ctk.CTkLabel(
            row, text=f"{entropy:.3f}",
            font=("Consolas", 8, "bold"),
            text_color=risk_color, width=80,
        ).pack(side="left", padx=6, pady=3)
        ctk.CTkLabel(
            row, text=risk, font=("Consolas", 8, "bold"),
            text_color=risk_color, width=80,
        ).pack(side="left", padx=(6, 8), pady=3)

        self._recent_rows.insert(0, row)
        if len(self._recent_rows) > 100:
            old = self._recent_rows.pop()
            old.destroy()

        # ── Live status updates ─────────────────────────────────────────────
        # Approximate "files/sec" using the last 10 timestamps.
        recent_count = len([t for t in self._entropy_timestamps[-10:] if t])
        self._fps_lbl.configure(text=f"Tệp/s: {recent_count}")

        # Burst alert when 5+ high-entropy events arrive in a row.
        if self._current_consecutive >= 5:
            self._show_burst_alert()

    def _show_burst_alert(self):
        if not hasattr(self, "_burst_shown") or not self._burst_shown:
            self._burst_shown = True
            messagebox.showerror(
                "PHAT HIEN BURST ENTROPY!",
                f"Nghi ngờ có mã hóa ransomware!\n\n"
                f"Số tệp entropy cao liên tiếp: {self._current_consecutive}\n"
                f"Tệp đang bị sửa rất nhanh - khuyến nghị xử lý ngay."
            )
            self.after(30000, lambda: setattr(self, "_burst_shown", False))
