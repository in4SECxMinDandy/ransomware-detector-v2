"""
main_window.py — v2.0 (Anti-FP Edition)
==========================================
Main GUI - Ransomware Entropy Detector

Nâng cấp v2:
  - Threshold Slider: điều chỉnh detection threshold 0.3–0.95 từ GUI
  - FP Settings Panel: hiển thị per-extension threshold info
  - Hiển thị Precision/Recall/FP Rate trong ML Engine section
  - Version badge cập nhật: v2.0 + Anti-FP Edition
  - Thêm cột "Raw Prob" và "Adjusted" trong results table
  - FP Stats: số file được giảm threshold

Layout:
  ┌─────────────────────────────────────────────────────────────┐
  │  HEADER: Logo + Title + Version + Status badge              │
  ├──────────────┬──────────────────────────────────────────────┤
  │  LEFT PANEL  │  RIGHT: Results Table                        │
  │  - Directory │                                              │
  │  - Scan mode │  - Status | File | Path | Risk | Prob | H   │
  │  - Threshold │                                              │
  │    Slider    │                                              │
  │  - Start btn │                                              │
  │  - Stats     │                                              │
  │  - Watchdog  │                                              │
  │  - FP Info   │                                              │
  │  - Export    │                                              │
  │  - ML Engine │                                              │
  ├──────────────┴──────────────────────────────────────────────┤
  │  BOTTOM: Log console (real-time events)                     │
  └─────────────────────────────────────────────────────────────┘
"""

import os
import time
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional
from datetime import datetime

import customtkinter as ctk

from core.scanner import Scanner, ScanResult
from core.ml_engine import get_engine
from core.watchdog_monitor import RealTimeMonitor, ThreatEvent
from core.process_monitor import BehaviorAlert
from core.report_generator import export_csv, export_report_png
from core.fp_reducer import (
    EXTENSION_THRESHOLDS,
    DEFAULT_EXTENSION_THRESHOLD,
    get_extension_threshold,
)
from core.pdf_reporter import export_model_report_pdf
from gui.whitelist_editor import WhitelistEditorWindow, load_whitelist, apply_whitelist_to_fp_reducer

# ─── CustomTkinter appearance ───
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ─── Color Palette ───
C = {
    "bg_dark":   "#0B0F14",
    "bg_panel":  "#121821",
    "bg_card":   "#161E29",
    "border":    "#263042",
    "text":      "#E6EAF0",
    "text_dim":  "#A3ADBD",
    "green":     "#22C55E",
    "red":       "#EF4444",
    "orange":    "#F59E0B",
    "yellow":    "#FACC15",
    "blue":      "#60A5FA",
    "cyan":      "#22D3EE",
    "accent":    "#3B82F6",
    "accent_h":  "#2563EB",
    "danger":    "#B91C1C",
    "warning":   "#D97706",
    "purple":    "#A78BFA",
}

RISK_COLORS = {
    "CRITICAL": C["red"],
    "HIGH":     C["orange"],
    "MEDIUM":   C["yellow"],
    "LOW":      C["cyan"],
    "SAFE":     C["green"],
    "UNKNOWN":  C["text_dim"],
}


class AlertWindow(ctk.CTkToplevel):
    """Cửa sổ cảnh báo threat Real-time."""

    def __init__(self, parent, threat: ThreatEvent):
        super().__init__(parent)
        self.title("⚠ RANSOMWARE THREAT DETECTED")
        self.geometry("520x320")
        self.configure(fg_color=C["bg_dark"])
        self.attributes("-topmost", True)
        self.resizable(False, False)

        risk_color = RISK_COLORS.get(threat.result.risk_level, C["red"])

        ctk.CTkLabel(
            self, text="⚠  THREAT DETECTED",
            font=ctk.CTkFont(family="Consolas", size=22, weight="bold"),
            text_color=C["red"]
        ).pack(pady=(20, 5))

        ctk.CTkLabel(
            self, text=threat.result.risk_level,
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=risk_color
        ).pack(pady=(0, 15))

        frame = ctk.CTkFrame(self, fg_color=C["bg_panel"], corner_radius=8)
        frame.pack(fill="x", padx=20, pady=5)

        info_items = [
            ("File",        threat.result.filename),
            ("Path",        threat.result.path[:60] + "..." if len(threat.result.path) > 60 else threat.result.path),
            ("Probability", f"{threat.result.probability*100:.1f}%"),
            ("Entropy",     f"{threat.result.entropy:.4f} bits/byte"),
            ("Detected",    threat.timestamp),
            ("Event",       threat.event_type.upper()),
        ]

        for key, val in info_items:
            row = ctk.CTkFrame(frame, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=2)
            ctk.CTkLabel(row, text=f"{key}:", font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=C["text_dim"], width=90, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=val, font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=C["text"], anchor="w").pack(side="left")

        ctk.CTkButton(
            self, text="DISMISS", command=self.destroy,
            fg_color=C["danger"], hover_color="#B22222",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            width=120, height=35, corner_radius=6
        ).pack(pady=15)


class BehaviorAlertWindow(ctk.CTkToplevel):
    """Cửa sổ cảnh báo behavior (Process Monitor) - v2.2"""

    def __init__(self, parent, alert: BehaviorAlert):
        super().__init__(parent)
        self.title(f"⚠ {alert.behavior_type.value.upper()} DETECTED")
        self.geometry("600x400")
        self.configure(fg_color=C["bg_dark"])
        self.attributes("-topmost", True)
        self.resizable(True, True)

        # Severity color
        severity_colors = {
            "low": C["blue"],
            "medium": C["yellow"],
            "high": C["orange"],
            "critical": C["red"],
        }
        severity_color = severity_colors.get(alert.severity, C["red"])

        # Header
        ctk.CTkLabel(
            self, text=f"⚠  {alert.behavior_type.value.upper()}",
            font=ctk.CTkFont(family="Consolas", size=20, weight="bold"),
            text_color=severity_color
        ).pack(pady=(15, 5))

        ctk.CTkLabel(
            self, text=f"Severity: {alert.severity.upper()}",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=severity_color
        ).pack(pady=(0, 10))

        # Process Info Frame
        proc_frame = ctk.CTkFrame(self, fg_color=C["bg_panel"], corner_radius=8)
        proc_frame.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(
            proc_frame, text="PROCESS INFORMATION",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=C["accent"]
        ).pack(pady=(8, 5))

        proc_info = [
            ("Process Name", alert.process.name),
            ("PID", str(alert.process.pid)),
            ("Path", alert.process.path[:50] + "..." if len(alert.process.path) > 50 else alert.process.path),
            ("Benign", "Yes" if alert.process.is_benign else "No"),
            ("System", "Yes" if alert.process.is_system else "No"),
        ]

        for key, val in proc_info:
            row = ctk.CTkFrame(proc_frame, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=2)
            ctk.CTkLabel(row, text=f"{key}:", font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=C["text_dim"], width=100, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=val, font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=C["text"], anchor="w").pack(side="left")

        # Description
        desc_frame = ctk.CTkFrame(self, fg_color=C["bg_panel"], corner_radius=8)
        desc_frame.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(
            desc_frame, text="DESCRIPTION",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=C["accent"]
        ).pack(pady=(8, 5))

        ctk.CTkLabel(
            desc_frame, text=alert.description,
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=C["text"], wraplength=550
        ).pack(pady=(0, 8))

        # Affected Files
        files_frame = ctk.CTkFrame(self, fg_color=C["bg_panel"], corner_radius=8)
        files_frame.pack(fill="both", expand=True, padx=20, pady=5)

        ctk.CTkLabel(
            files_frame, text=f"AFFECTED FILES ({len(alert.files)})",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=C["accent"]
        ).pack(pady=(8, 5))

        # Scrollable files list
        files_scroll = ctk.CTkScrollableFrame(files_frame, fg_color="transparent", height=120)
        files_scroll.pack(fill="both", expand=True, padx=10, pady=5)

        for i, fpath in enumerate(alert.files[:20]):  # Show max 20 files
            short_path = fpath[:70] + "..." if len(fpath) > 70 else fpath
            ctk.CTkLabel(
                files_scroll, text=f"{i+1}. {short_path}",
                font=ctk.CTkFont(family="Consolas", size=9),
                text_color=C["text_dim"], anchor="w"
            ).pack(fill="x", pady=1)

        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=10)

        ctk.CTkButton(
            btn_frame, text="DISMISS", command=self.destroy,
            fg_color=C["danger"], hover_color="#B22222",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            width=120, height=35, corner_radius=6
        ).pack(side="left", padx=5)


class RansomwareDetectorApp(ctk.CTk):
    """Main Application Window — v2.0 Anti-FP Edition."""

    def __init__(self):
        super().__init__()

        self.title("Ransomware Entropy Detector v2.1  |  Premium Defense")
        self.geometry("1500x940")
        self.minsize(1200, 760)
        self.configure(fg_color=C["bg_dark"])

        # State
        self._scanner      = Scanner()
        self._monitor      = RealTimeMonitor()
        self._ui_queue     = queue.Queue()
        self._scan_start   = 0.0
        self._scan_dir     = tk.StringVar(value="")
        self._watch_dir    = tk.StringVar(value="")
        self._scan_mode    = tk.StringVar(value="Full Scan")
        self._status_var   = tk.StringVar(value="IDLE")
        self._results: List[ScanResult] = []
        self._alert_shown  = set()

        # v2: Threshold slider state
        self._threshold_var = tk.DoubleVar(value=0.65)

        self._build_ui()
        self._ensure_model_loaded()
        self._ensure_threat_intel_loaded()
        self._poll_ui_queue()
        # v2.1: Load whitelist khi khởi động
        try:
            wl = load_whitelist()
            apply_whitelist_to_fp_reducer(wl)
        except Exception:
            pass

    # ─────────────────────────── BUILD UI ───────────────────────────

    def _build_ui(self):
        self._build_header()

        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=10, pady=(0, 5))
        main.columnconfigure(1, weight=1)
        main.rowconfigure(0, weight=1)

        self._build_left_panel(main)
        self._build_results_panel(main)

        self._build_log_console()

    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=C["bg_panel"], corner_radius=0, height=65)
        hdr.pack(fill="x", padx=0, pady=0)
        hdr.pack_propagate(False)

        title_block = ctk.CTkFrame(hdr, fg_color="transparent")
        title_block.pack(side="left", padx=20, pady=10)

        ctk.CTkLabel(
            title_block,
            text="RANSOMWARE ENTROPY DETECTOR",
            font=ctk.CTkFont(family="Consolas", size=21, weight="bold"),
            text_color=C["blue"]
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_block,
            text="Premium Defense Suite — Behavioral + YARA + ML",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=C["text_dim"]
        ).pack(anchor="w")

        # v2.1 badge
        ctk.CTkLabel(
            hdr,
            text="v2.1  Premium",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color=C["bg_dark"],
            fg_color=C["purple"],
            corner_radius=6,
            width=90, height=22
        ).pack(side="left", padx=(0, 10), pady=15)

        self._status_badge = ctk.CTkLabel(
            hdr,
            textvariable=self._status_var,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=C["bg_dark"],
            fg_color=C["green"],
            corner_radius=8,
            width=130, height=30
        )
        self._status_badge.pack(side="right", padx=20, pady=15)

        ctk.CTkLabel(
            hdr,
            text="Calibrated RF  |  Cost-Aware  |  16 Features  |  YARA Fusion",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=C["text_dim"]
        ).pack(side="right", padx=10, pady=15)

    def _build_left_panel(self, parent):
        panel = ctk.CTkFrame(parent, fg_color=C["bg_panel"], corner_radius=8, width=300)
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=5)
        panel.pack_propagate(False)

        scroll = ctk.CTkScrollableFrame(panel, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=5, pady=5)

        # ── Section: Static Scan ──
        self._section_label(scroll, "◈ STATIC SCAN")

        dir_frame = ctk.CTkFrame(scroll, fg_color=C["bg_card"], corner_radius=6)
        dir_frame.pack(fill="x", pady=(3, 5))

        ctk.CTkLabel(dir_frame, text="Target Directory",
                     font=ctk.CTkFont(family="Consolas", size=9),
                     text_color=C["text_dim"]).pack(anchor="w", padx=8, pady=(6, 0))

        dir_row = ctk.CTkFrame(dir_frame, fg_color="transparent")
        dir_row.pack(fill="x", padx=6, pady=(2, 6))

        self._dir_entry = ctk.CTkEntry(
            dir_row, textvariable=self._scan_dir,
            font=ctk.CTkFont(family="Consolas", size=9),
            fg_color=C["bg_dark"], border_color=C["border"],
            text_color=C["text"], placeholder_text="Select folder...",
            height=30
        )
        self._dir_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        ctk.CTkButton(
            dir_row, text="...", width=32, height=30,
            fg_color=C["bg_dark"], hover_color=C["border"],
            font=ctk.CTkFont(size=12), text_color=C["text"],
            command=self._browse_scan_dir
        ).pack(side="right")

        # Scan mode
        mode_frame = ctk.CTkFrame(scroll, fg_color=C["bg_card"], corner_radius=6)
        mode_frame.pack(fill="x", pady=(0, 5))
        ctk.CTkLabel(mode_frame, text="Scan Mode",
                     font=ctk.CTkFont(family="Consolas", size=9),
                     text_color=C["text_dim"]).pack(anchor="w", padx=8, pady=(6, 2))
        ctk.CTkSegmentedButton(
            mode_frame,
            values=["Full Scan", "Quick Scan"],
            variable=self._scan_mode,
            font=ctk.CTkFont(family="Consolas", size=9),
            fg_color=C["bg_dark"],
            selected_color=C["accent"],
            selected_hover_color=C["accent_h"],
            unselected_color=C["bg_dark"],
            height=30
        ).pack(fill="x", padx=6, pady=(0, 6))

        # ── v2: Threshold Slider Panel ──
        self._section_label(scroll, "◈ THREAT SENSITIVITY")
        self._build_threshold_panel(scroll)

        # ── Threat Intelligence (new) ──
        self._section_label(scroll, "◈ THREAT INTELLIGENCE")
        intel_frame = ctk.CTkFrame(scroll, fg_color=C["bg_card"], corner_radius=8)
        intel_frame.pack(fill="x", pady=(3, 8))

        self._yara_info_lbl = ctk.CTkLabel(
            intel_frame,
            text="YARA: initializing…\nHeuristic: armed",
            font=ctk.CTkFont(family="Consolas", size=8),
            text_color=C["text_dim"],
            justify="left"
        )
        self._yara_info_lbl.pack(anchor="w", padx=8, pady=6)

        # Scan button
        self._scan_btn = ctk.CTkButton(
            scroll, text="▶  START SCAN",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            fg_color=C["accent"], hover_color=C["accent_h"],
            text_color="#FFFFFF", height=42, corner_radius=10,
            command=self._start_scan
        )
        self._scan_btn.pack(fill="x", pady=(0, 4))

        self._cancel_btn = ctk.CTkButton(
            scroll, text="◼  CANCEL",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["bg_card"], hover_color=C["danger"],
            text_color=C["text_dim"], height=30, corner_radius=8,
            command=self._cancel_scan, state="disabled"
        )
        self._cancel_btn.pack(fill="x", pady=(0, 8))

        # Progress
        self._progress_label = ctk.CTkLabel(
            scroll, text="Ready to scan",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=C["text_dim"]
        )
        self._progress_label.pack(anchor="w", pady=(0, 3))

        self._progress_bar = ctk.CTkProgressBar(
            scroll, height=10, corner_radius=8,
            fg_color=C["bg_dark"], progress_color=C["green"]
        )
        self._progress_bar.set(0)
        self._progress_bar.pack(fill="x", pady=(0, 8))

        # ── Stats ──
        self._section_label(scroll, "◈ SCAN STATISTICS")

        stats_grid = ctk.CTkFrame(scroll, fg_color="transparent")
        stats_grid.pack(fill="x", pady=(3, 8))
        stats_grid.columnconfigure((0, 1), weight=1)

        self._stat_total   = self._stat_card(stats_grid, "TOTAL",    "0",   C["blue"],   0, 0)
        self._stat_safe    = self._stat_card(stats_grid, "SAFE",     "0",   C["green"],  0, 1)
        self._stat_threat  = self._stat_card(stats_grid, "THREATS",  "0",   C["red"],    1, 0)
        self._stat_crit    = self._stat_card(stats_grid, "CRITICAL", "0",   C["red"],    1, 1)
        self._stat_fp_adj  = self._stat_card(stats_grid, "FP ADJ",   "0",   C["purple"], 2, 0)
        self._stat_entropy = self._stat_card(stats_grid, "AVG H",    "0.0", C["cyan"],   2, 1)
        self._stat_time    = self._stat_card(stats_grid, "TIME",     "0s",  C["yellow"], 3, 0)

        # ── Real-time Protection ──
        self._section_label(scroll, "◈ REAL-TIME PROTECTION")

        watch_frame = ctk.CTkFrame(scroll, fg_color=C["bg_card"], corner_radius=6)
        watch_frame.pack(fill="x", pady=(3, 5))
        ctk.CTkLabel(watch_frame, text="Watch Directory",
                     font=ctk.CTkFont(family="Consolas", size=9),
                     text_color=C["text_dim"]).pack(anchor="w", padx=8, pady=(6, 0))

        watch_row = ctk.CTkFrame(watch_frame, fg_color="transparent")
        watch_row.pack(fill="x", padx=6, pady=(2, 6))
        ctk.CTkEntry(
            watch_row, textvariable=self._watch_dir,
            font=ctk.CTkFont(family="Consolas", size=9),
            fg_color=C["bg_dark"], border_color=C["border"],
            text_color=C["text"], placeholder_text="Select folder...",
            height=30
        ).pack(side="left", fill="x", expand=True, padx=(0, 4))
        ctk.CTkButton(
            watch_row, text="...", width=32, height=30,
            fg_color=C["bg_dark"], hover_color=C["border"],
            font=ctk.CTkFont(size=12), text_color=C["text"],
            command=self._browse_watch_dir
        ).pack(side="right")

        self._watch_status_lbl = ctk.CTkLabel(
            scroll, text="● PROTECTION OFF",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=C["text_dim"]
        )
        self._watch_status_lbl.pack(anchor="w", pady=(2, 3))

        btn_row = ctk.CTkFrame(scroll, fg_color="transparent")
        btn_row.pack(fill="x", pady=(0, 8))
        btn_row.columnconfigure((0, 1), weight=1)

        self._watch_start_btn = ctk.CTkButton(
            btn_row, text="▶ ENABLE",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            fg_color=C["accent"], hover_color=C["accent_h"],
            text_color="#FFF", height=34, corner_radius=6,
            command=self._start_watch
        )
        self._watch_start_btn.grid(row=0, column=0, padx=(0, 3), sticky="ew")

        self._watch_stop_btn = ctk.CTkButton(
            btn_row, text="◼ DISABLE",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["bg_card"], hover_color=C["danger"],
            text_color=C["text_dim"], height=34, corner_radius=6,
            command=self._stop_watch, state="disabled"
        )
        self._watch_stop_btn.grid(row=0, column=1, padx=(3, 0), sticky="ew")

        self._watch_stats_lbl = ctk.CTkLabel(
            scroll, text="Analyzed: 0  |  Threats: 0",
            font=ctk.CTkFont(family="Consolas", size=8),
            text_color=C["text_dim"]
        )
        self._watch_stats_lbl.pack(anchor="w", pady=(0, 8))

        # ── Export ──
        self._section_label(scroll, "◈ EXPORT REPORT")

        self._export_csv_btn = ctk.CTkButton(
            scroll, text="⬇  Export CSV",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["bg_card"], hover_color=C["border"],
            text_color=C["text"], height=34, corner_radius=6,
            command=self._export_csv
        )
        self._export_csv_btn.pack(fill="x", pady=(3, 4))

        self._export_png_btn = ctk.CTkButton(
            scroll, text="🖼  Export PNG Report",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["bg_card"], hover_color=C["border"],
            text_color=C["text"], height=34, corner_radius=6,
            command=self._export_png
        )
        self._export_png_btn.pack(fill="x", pady=(0, 4))

        # v2.1: Export PDF Report
        self._export_pdf_btn = ctk.CTkButton(
            scroll, text="📄  Export PDF Report",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["bg_card"], hover_color=C["border"],
            text_color=C["text"], height=34, corner_radius=6,
            command=self._export_pdf
        )
        self._export_pdf_btn.pack(fill="x", pady=(0, 4))

        # v2.1: Whitelist Editor
        ctk.CTkButton(
            scroll, text="📋  Whitelist Editor",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["purple"], hover_color="#9A6FD0",
            text_color="#FFF", height=34, corner_radius=6,
            command=self._open_whitelist_editor
        ).pack(fill="x", pady=(0, 8))

        # ── ML Engine Info ──
        self._section_label(scroll, "◈ ML ENGINE  (v2.1)")
        self._ml_info_lbl = ctk.CTkLabel(
            scroll, text="Loading model...",
            font=ctk.CTkFont(family="Consolas", size=8),
            text_color=C["text_dim"], wraplength=260, justify="left"
        )
        self._ml_info_lbl.pack(anchor="w", padx=5, pady=(0, 10))

    def _build_threshold_panel(self, parent):
        """
        Panel điều chỉnh Detection Threshold — tính năng mới v2.
        Slider 0.30 → 0.95, default 0.65 (optimal từ PR curve)
        """
        thresh_frame = ctk.CTkFrame(parent, fg_color=C["bg_card"], corner_radius=6)
        thresh_frame.pack(fill="x", pady=(3, 8))

        # Header row
        hdr_row = ctk.CTkFrame(thresh_frame, fg_color="transparent")
        hdr_row.pack(fill="x", padx=8, pady=(8, 2))

        ctk.CTkLabel(
            hdr_row, text="Detection Threshold",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=C["text_dim"]
        ).pack(side="left")

        self._threshold_value_lbl = ctk.CTkLabel(
            hdr_row, text="0.65",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=C["yellow"]
        )
        self._threshold_value_lbl.pack(side="right")

        # Slider
        self._threshold_slider = ctk.CTkSlider(
            thresh_frame,
            from_=0.30, to=0.95,
            variable=self._threshold_var,
            number_of_steps=65,
            fg_color=C["bg_dark"],
            progress_color=C["accent"],
            button_color=C["yellow"],
            button_hover_color=C["orange"],
            command=self._on_threshold_change,
            height=18
        )
        self._threshold_slider.pack(fill="x", padx=8, pady=(2, 4))

        # Labels: Low FP ← → High Recall
        label_row = ctk.CTkFrame(thresh_frame, fg_color="transparent")
        label_row.pack(fill="x", padx=8, pady=(0, 4))
        ctk.CTkLabel(
            label_row, text="◀ Ít FP hơn",
            font=ctk.CTkFont(family="Consolas", size=7),
            text_color=C["green"]
        ).pack(side="left")
        ctk.CTkLabel(
            label_row, text="Nhạy hơn ▶",
            font=ctk.CTkFont(family="Consolas", size=7),
            text_color=C["orange"]
        ).pack(side="right")

        # Mode hints
        self._threshold_hint_lbl = ctk.CTkLabel(
            thresh_frame, text="Optimal (Auto-tuned)",
            font=ctk.CTkFont(family="Consolas", size=8),
            text_color=C["cyan"]
        )
        self._threshold_hint_lbl.pack(pady=(0, 4))

        # Reset button
        ctk.CTkButton(
            thresh_frame, text="↺ Reset to Optimal",
            font=ctk.CTkFont(family="Consolas", size=8),
            fg_color=C["bg_dark"], hover_color=C["border"],
            text_color=C["text_dim"], height=24, corner_radius=4,
            command=self._reset_threshold
        ).pack(fill="x", padx=8, pady=(0, 8))

        # Per-extension info (collapsible hint)
        ext_info = ctk.CTkFrame(thresh_frame, fg_color=C["bg_dark"], corner_radius=4)
        ext_info.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkLabel(
            ext_info,
            text="PNG/ZIP/MP4/EXE: threshold cao hơn tự động\n(magic bytes hợp lệ → prob giảm 30%)",
            font=ctk.CTkFont(family="Consolas", size=7),
            text_color=C["text_dim"],
            justify="left"
        ).pack(anchor="w", padx=6, pady=4)

    def _section_label(self, parent, text: str):
        ctk.CTkLabel(
            parent, text=text,
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color=C["green"]
        ).pack(anchor="w", padx=4, pady=(10, 2))
        ctk.CTkFrame(parent, height=1, fg_color=C["border"]).pack(fill="x", pady=(0, 3))

    def _stat_card(self, parent, label: str, value: str, color: str, row: int, col: int):
        card = ctk.CTkFrame(parent, fg_color=C["bg_card"], corner_radius=6)
        card.grid(row=row, column=col, padx=2, pady=2, sticky="ew")
        ctk.CTkLabel(card, text=label,
                     font=ctk.CTkFont(family="Consolas", size=7),
                     text_color=C["text_dim"]).pack(pady=(5, 0))
        lbl = ctk.CTkLabel(card, text=value,
                           font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
                           text_color=color)
        lbl.pack(pady=(0, 5))
        return lbl

    def _build_results_panel(self, parent):
        panel = ctk.CTkFrame(parent, fg_color=C["bg_panel"], corner_radius=8)
        panel.grid(row=0, column=1, sticky="nsew", padx=(5, 0), pady=5)

        tab_hdr = ctk.CTkFrame(panel, fg_color=C["bg_card"], corner_radius=8, height=38)
        tab_hdr.pack(fill="x", padx=8, pady=(8, 4))
        tab_hdr.pack_propagate(False)
        ctk.CTkLabel(
            tab_hdr, text="◈  SCAN RESULTS  —  Premium Defense",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=C["accent"]
        ).pack(side="left", padx=12, pady=6)

        # Filter bar
        filter_frame = ctk.CTkFrame(panel, fg_color="transparent")
        filter_frame.pack(fill="x", padx=8, pady=(0, 4))

        self._filter_var = tk.StringVar(value="ALL")
        for txt, val in [("All", "ALL"), ("Threats", "THREATS"),
                         ("Critical", "CRITICAL"), ("Safe", "SAFE"),
                         ("FP Adj.", "FP_ADJ")]:  # v2: thêm filter FP Adjusted
            ctk.CTkButton(
                filter_frame, text=txt, width=75, height=25,
                font=ctk.CTkFont(family="Consolas", size=9),
                fg_color=C["bg_card"], hover_color=C["border"],
                text_color=C["text"], corner_radius=4,
                command=lambda v=val: self._apply_filter(v)
            ).pack(side="left", padx=2)

        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._apply_filter(self._filter_var.get()))
        ctk.CTkEntry(
            filter_frame, textvariable=self._search_var,
            placeholder_text="Search filename...",
            font=ctk.CTkFont(family="Consolas", size=9),
            fg_color=C["bg_dark"], border_color=C["border"],
            text_color=C["text"], height=25, width=180
        ).pack(side="right", padx=2)

        # ── Treeview table ──
        tree_frame = ctk.CTkFrame(panel, fg_color=C["bg_dark"], corner_radius=6)
        tree_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Cyber.Treeview",
                        background=C["bg_dark"],
                        foreground=C["text"],
                        rowheight=26,
                        fieldbackground=C["bg_dark"],
                        borderwidth=0,
                        font=("Consolas", 9))
        style.configure("Cyber.Treeview.Heading",
                        background=C["bg_card"],
                        foreground=C["accent"],
                        borderwidth=0,
                        font=("Consolas", 9, "bold"),
                        relief="flat")
        style.map("Cyber.Treeview",
                  background=[("selected", C["bg_card"])],
                  foreground=[("selected", C["green"])])

        # v2: thêm cột "Adj." (FP adjusted indicator) và "Threshold"
        columns = ("status", "filename", "path", "risk", "probability", "raw_prob", "adj", "entropy", "size")
        self._tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings",
            style="Cyber.Treeview", selectmode="browse"
        )

        col_config = [
            ("status",      "◉",         40,  False),
            ("filename",    "Filename",   190, False),
            ("path",        "Path",       290, False),
            ("risk",        "Risk Level", 85,  False),
            ("probability", "Adj. Prob",  75,  False),
            ("raw_prob",    "Raw Prob",   70,  False),
            ("adj",         "FP↓",        40,  False),  # indicator nếu prob đã được điều chỉnh
            ("entropy",     "Entropy",    72,  False),
            ("size",        "Size",       65,  False),
        ]
        for col, heading, width, stretch in col_config:
            self._tree.heading(col, text=heading, command=lambda c=col: self._sort_tree(c))
            self._tree.column(col, width=width, minwidth=35, stretch=stretch)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        for risk, color in RISK_COLORS.items():
            self._tree.tag_configure(risk, foreground=color)
        self._tree.tag_configure("UNKNOWN", foreground=C["text_dim"])
        self._tree.tag_configure("FP_ADJ",  foreground=C["purple"])  # v2: màu riêng cho FP adjusted

    def _build_log_console(self):
        console_frame = ctk.CTkFrame(self, fg_color=C["bg_panel"], corner_radius=10, height=140)
        console_frame.pack(fill="x", padx=10, pady=(0, 8))
        console_frame.pack_propagate(False)

        hdr = ctk.CTkFrame(console_frame, fg_color="transparent", height=25)
        hdr.pack(fill="x", padx=8, pady=(4, 0))
        ctk.CTkLabel(hdr, text="◈ EVENT LOG",
                     font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                     text_color=C["green"]).pack(side="left")
        ctk.CTkButton(hdr, text="CLEAR", width=50, height=20,
                      font=ctk.CTkFont(family="Consolas", size=8),
                      fg_color=C["bg_card"], hover_color=C["border"],
                      text_color=C["text_dim"], corner_radius=4,
                      command=self._clear_log).pack(side="right")

        self._log_text = tk.Text(
            console_frame,
            bg=C["bg_dark"], fg=C["text"],
            font=("Consolas", 8),
            insertbackground=C["green"],
            relief="flat", bd=0,
            state="disabled",
            height=5
        )
        self._log_text.pack(fill="both", expand=True, padx=8, pady=(2, 6))

        self._log_text.tag_configure("info",    foreground=C["text_dim"])
        self._log_text.tag_configure("success", foreground=C["green"])
        self._log_text.tag_configure("warning", foreground=C["orange"])
        self._log_text.tag_configure("danger",  foreground=C["red"])
        self._log_text.tag_configure("system",  foreground=C["blue"])
        self._log_text.tag_configure("fp",      foreground=C["purple"])

    # ─────────────────────────── THRESHOLD ACTIONS ───────────────────────────

    def _on_threshold_change(self, value: float):
        """Callback khi threshold slider thay đổi."""
        t = round(float(value), 2)
        self._threshold_value_lbl.configure(text=f"{t:.2f}")

        # Update hint
        if t < 0.45:
            hint = "Rất nhạy (nhiều FP)"
            color = C["red"]
        elif t < 0.55:
            hint = "Nhạy (cân bằng)"
            color = C["orange"]
        elif t < 0.70:
            hint = "Optimal (Auto-tuned)"
            color = C["purple"]
        elif t < 0.80:
            hint = "An toàn (ít FP)"
            color = C["cyan"]
        else:
            hint = "Rất an toàn (bỏ sót nhiều)"
            color = C["yellow"]

        self._threshold_hint_lbl.configure(text=hint, text_color=color)

        # Áp dụng vào engine
        engine = get_engine()
        if engine.is_loaded():
            engine.set_threshold(t)

    def _reset_threshold(self):
        """Reset threshold về giá trị optimal từ model."""
        engine = get_engine()
        if engine.is_loaded():
            opt = engine.get_model_info().get("optimal_threshold", 0.65)
            self._threshold_var.set(opt)
            self._on_threshold_change(opt)
            self._log("fp", f"Threshold reset về optimal: {opt:.4f}")
        else:
            self._threshold_var.set(0.65)
            self._on_threshold_change(0.65)

    # ─────────────────────────── ACTIONS ───────────────────────────

    def _browse_scan_dir(self):
        d = filedialog.askdirectory(title="Select directory to scan")
        if d:
            self._scan_dir.set(d)
            self._log("info", f"Target directory: {d}")

    def _browse_watch_dir(self):
        d = filedialog.askdirectory(title="Select directory to watch")
        if d:
            self._watch_dir.set(d)
            self._log("info", f"Watch directory: {d}")

    def _ensure_model_loaded(self):
        """Load hoặc train ML model trong background."""
        def _bg():
            engine = get_engine()
            from core.ml_engine import MODEL_PATH
            if engine.load_model(MODEL_PATH):
                meta = engine.get_model_info()
                acc  = meta.get("accuracy", 0) * 100
                prec = meta.get("precision", 0) * 100
                rec  = meta.get("recall", 0) * 100
                fpr  = meta.get("false_positive_rate", 0) * 100
                opt_t = meta.get("optimal_threshold", 0.65)

                self._ui_queue.put(("log", "success",
                    f"ML Engine loaded  |  Accuracy: {acc:.1f}%  |  "
                    f"Precision: {prec:.1f}%  |  FP Rate: {fpr:.1f}%"))
                self._ui_queue.put(("ml_info",
                    f"✓ Model v2.1 loaded\n"
                    f"Accuracy:   {acc:.2f}%\n"
                    f"Precision:  {prec:.2f}%  (target ≥95%)\n"
                    f"Recall:     {rec:.2f}%\n"
                    f"FP Rate:    {fpr:.2f}%  (target <5%)\n"
                    f"Threshold:  {opt_t:.4f} (auto-tuned)"))
                self._ui_queue.put(("set_threshold", opt_t))

            else:
                self._ui_queue.put(("log", "warning",
                    "Model v2 not found. Training từ dataset v2 (16 features)..."))
                from core.dataset_generator import generate_synthetic_dataset
                X, y = generate_synthetic_dataset(n_safe=2000, n_encrypted=2000)
                metrics = engine.train(X, y, verbose=False)
                acc  = metrics["accuracy"] * 100
                prec = metrics["precision"] * 100
                fpr  = metrics.get("false_positive_rate", 0) * 100
                opt_t = metrics.get("optimal_threshold", 0.65)
                self._ui_queue.put(("log", "success",
                    f"Model trained  |  Accuracy: {acc:.1f}%  |  "
                    f"Precision: {prec:.1f}%  |  FP Rate: {fpr:.1f}%"))
                self._ui_queue.put(("ml_info",
                    f"✓ Model v2.1 trained\n"
                    f"Accuracy:  {acc:.2f}%\n"
                    f"Precision: {prec:.2f}%\n"
                    f"FP Rate:   {fpr:.2f}%\n"
                    f"Threshold: {opt_t:.4f}"))
                self._ui_queue.put(("set_threshold", opt_t))

        t = threading.Thread(target=_bg, daemon=True)
        t.start()

    def _ensure_threat_intel_loaded(self):
        """Load YARA info + update status label."""
        def _bg():
            try:
                yara_engine = get_yara_engine()
                engine_type = yara_engine.get_engine_type()
                rules_count = yara_engine.get_rules_count()
                self._ui_queue.put((
                    "intel",
                    f"YARA: {engine_type} ({rules_count} rules)\nHeuristic: armed",
                ))
            except Exception:
                self._ui_queue.put((
                    "intel",
                    "YARA: unavailable\nHeuristic: armed",
                ))

        threading.Thread(target=_bg, daemon=True).start()

    def _start_scan(self):
        scan_dir = self._scan_dir.get().strip()
        if not scan_dir or not os.path.isdir(scan_dir):
            messagebox.showerror("Error", "Please select a valid directory to scan.")
            return
        engine = get_engine()
        if not engine.is_loaded():
            messagebox.showwarning("Warning", "ML Engine is still loading. Please wait.")
            return

        # Đồng bộ threshold từ slider vào engine
        t = self._threshold_var.get()
        engine.set_threshold(t)

        # Reset UI
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._results.clear()
        self._set_status("SCANNING", C["yellow"])
        self._scan_btn.configure(state="disabled")
        self._cancel_btn.configure(state="normal")
        self._progress_bar.set(0)
        self._scan_start = time.time()

        self._log("system",
            f"Starting {self._scan_mode.get()} on: {scan_dir}  "
            f"[threshold={t:.2f}]")

        recursive = self._scan_mode.get() == "Full Scan"
        self._scanner.scan(
            directory=scan_dir,
            recursive=recursive,
            on_progress=self._on_scan_progress,
            on_complete=self._on_scan_complete,
            on_error=self._on_scan_error,
        )

    def _cancel_scan(self):
        self._scanner.cancel()
        self._log("warning", "Scan cancelled by user")
        self._set_status("CANCELLED", C["orange"])
        self._scan_btn.configure(state="normal")
        self._cancel_btn.configure(state="disabled")

    def _on_scan_progress(self, done: int, total: int, result: ScanResult):
        self._ui_queue.put(("progress", done, total, result))

    def _on_scan_complete(self, results):
        self._ui_queue.put(("complete", results))

    def _on_scan_error(self, error: str):
        self._ui_queue.put(("error", error))

    def _start_watch(self):
        watch_dir = self._watch_dir.get().strip()
        if not watch_dir or not os.path.isdir(watch_dir):
            messagebox.showerror("Error", "Please select a valid watch directory.")
            return
        engine = get_engine()
        if not engine.is_loaded():
            messagebox.showwarning("Warning", "ML Engine is still loading.")
            return

        self._monitor.on_threat   = self._on_realtime_threat
        self._monitor.on_analyzed = self._on_realtime_analyzed
        self._monitor.on_behavior = self._on_behavior_alert
        ok = self._monitor.start(watch_dir)
        if ok:
            self._watch_status_lbl.configure(text="● PROTECTION ON", text_color=C["green"])
            self._watch_start_btn.configure(state="disabled")
            self._watch_stop_btn.configure(state="normal")
            self._set_status("WATCHING", C["green"])
            self._log("success", f"Real-time protection enabled: {watch_dir}")
        else:
            messagebox.showerror("Error", "Failed to start real-time monitor.")

    def _stop_watch(self):
        self._monitor.stop()
        self._watch_status_lbl.configure(text="● PROTECTION OFF", text_color=C["text_dim"])
        self._watch_start_btn.configure(state="normal")
        self._watch_stop_btn.configure(state="disabled")
        self._set_status("IDLE", C["green"])
        self._log("warning", "Real-time protection disabled")

    def _on_realtime_threat(self, threat: ThreatEvent):
        self._ui_queue.put(("threat", threat))

    def _on_realtime_analyzed(self, result: ScanResult, event_type: str):
        self._ui_queue.put(("watch_update",))

    def _on_behavior_alert(self, alert: BehaviorAlert):
        """Xử lý behavior alert từ Process Monitor."""
        self._ui_queue.put(("behavior_alert", alert))
        # Also log to console
        self._log(f"[BEHAVIOR] {alert.severity.upper()}: {alert.description}")

    def _export_csv(self):
        if not self._results:
            messagebox.showinfo("Info", "No scan results to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        if path:
            export_csv(self._results, path)
            self._log("success", f"CSV exported: {path}")
            messagebox.showinfo("Export Complete", f"CSV saved to:\n{path}")

    def _export_pdf(self):
        """v2.1: Export Model Analysis Report PDF."""
        engine = get_engine()
        if not engine.is_loaded():
            messagebox.showinfo("Info", "ML Engine chưa load xong.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile=f"ransomware_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        if path:
            self._log("info", "Generating PDF report...")
            def _gen():
                ok = export_model_report_pdf(
                    output_path=path,
                    model_metadata=engine.metadata,
                    scan_results=self._results if self._results else None,
                    scan_directory=self._scan_dir.get(),
                    scan_duration=time.time() - self._scan_start if self._scan_start > 0 else 0.0,
                )
                if ok:
                    self._ui_queue.put(("log", "success", f"PDF report saved: {path}"))
                    self._ui_queue.put(("msgbox", "Export Complete",
                                        f"PDF report đã lưu:\n{path}"))
                else:
                    self._ui_queue.put(("log", "danger", "PDF export thất bại"))
            threading.Thread(target=_gen, daemon=True).start()

    def _open_whitelist_editor(self):
        """v2.1: Mở Whitelist Editor."""
        editor = WhitelistEditorWindow(self)
        editor.protocol("WM_DELETE_WINDOW", editor.on_closing)

    def _export_png(self):
        if not self._results:
            messagebox.showinfo("Info", "No scan results to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")],
            initialfile=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        )
        if path:
            dur = time.time() - self._scan_start if self._scan_start > 0 else 0
            self._log("info", "Generating PNG report...")
            def _gen():
                export_report_png(
                    self._results, path,
                    scan_directory=self._scan_dir.get(),
                    scan_mode=self._scan_mode.get(),
                    scan_duration=dur
                )
                self._ui_queue.put(("log", "success", f"PNG report saved: {path}"))
                self._ui_queue.put(("msgbox", "Export Complete", f"Report saved:\n{path}"))
            threading.Thread(target=_gen, daemon=True).start()

    # ─────────────────────────── UI UPDATE ───────────────────────────

    def _poll_ui_queue(self):
        """Poll UI queue từ main thread để update giao diện an toàn."""
        try:
            while not self._ui_queue.empty():
                msg = self._ui_queue.get_nowait()
                mtype = msg[0]

                if mtype == "progress":
                    _, done, total, result = msg
                    self._results.append(result)
                    pct = done / total if total > 0 else 0
                    self._progress_bar.set(pct)
                    self._progress_label.configure(
                        text=f"Scanning... {done}/{total} ({pct*100:.0f}%)")
                    self._add_tree_row(result)
                    self._update_stats()

                elif mtype == "complete":
                    _, results = msg
                    self._results = list(results)
                    elapsed = time.time() - self._scan_start
                    self._progress_bar.set(1.0)
                    threats  = sum(1 for r in results if r.label == 1)
                    fp_adj   = sum(1 for r in results if getattr(r, "fp_adjusted", False))
                    self._progress_label.configure(
                        text=f"✓ Scan complete: {len(results)} files in {elapsed:.1f}s")
                    status_color = C["red"] if threats > 0 else C["green"]
                    self._set_status("THREATS FOUND" if threats > 0 else "ALL CLEAR", status_color)
                    self._scan_btn.configure(state="normal")
                    self._cancel_btn.configure(state="disabled")
                    self._update_stats(elapsed)
                    self._log(
                        "success" if threats == 0 else "danger",
                        f"Scan complete: {len(results)} files | {threats} threats | "
                        f"{fp_adj} FP-adjusted | {elapsed:.1f}s"
                    )

                elif mtype == "error":
                    _, error = msg
                    self._log("danger", f"Scan error: {error}")
                    self._set_status("ERROR", C["red"])
                    self._scan_btn.configure(state="normal")
                    self._cancel_btn.configure(state="disabled")

                elif mtype == "log":
                    _, level, text = msg
                    self._log(level, text)

                elif mtype == "ml_info":
                    self._ml_info_lbl.configure(text=msg[1])

                elif mtype == "intel":
                    if hasattr(self, "_yara_info_lbl"):
                        self._yara_info_lbl.configure(text=msg[1])

                elif mtype == "set_threshold":
                    # v2: auto-set threshold slider sau khi model load
                    opt_t = float(msg[1])
                    self._threshold_var.set(opt_t)
                    self._on_threshold_change(opt_t)

                elif mtype == "threat":
                    _, threat = msg
                    key = f"{threat.result.path}_{threat.timestamp}"
                    if key not in self._alert_shown:
                        self._alert_shown.add(key)
                        self._log("danger",
                            f"⚠ THREAT: {threat.result.filename} | "
                            f"{threat.result.risk_level} | {threat.result.probability*100:.1f}%")
                        AlertWindow(self, threat)

                elif mtype == "watch_update":
                    stats = self._monitor.get_stats()
                    self._watch_stats_lbl.configure(
                        text=f"Analyzed: {stats['total_analyzed']}  |  Threats: {stats['total_threats']}")

                elif mtype == "behavior_alert":
                    _, alert = msg
                    # Show behavior alert window
                    BehaviorAlertWindow(self, alert)

                elif mtype == "msgbox":
                    _, title, body = msg
                    messagebox.showinfo(title, body)

        except Exception:
            pass

        self.after(150, self._poll_ui_queue)

    def _add_tree_row(self, result: ScanResult):
        """Thêm một hàng vào bảng kết quả — v2 thêm FP columns."""
        risk = result.risk_level or "UNKNOWN"
        icon = {
            "CRITICAL": "⬛", "HIGH": "🔴", "MEDIUM": "🟡",
            "LOW": "🔵", "SAFE": "🟢", "UNKNOWN": "⚪"
        }.get(risk, "⚪")

        size_str = (f"{result.size/1024:.0f}K" if result.size < 1024*1024
                    else f"{result.size/1024/1024:.1f}M")

        raw_proba = getattr(result, "raw_probability", result.probability)
        fp_adj    = getattr(result, "fp_adjusted", False)
        adj_icon  = "↓" if fp_adj else ""  # indicator FP adjustment

        # Tag: dùng FP_ADJ tag nếu file được điều chỉnh VÀ safe
        tag = risk
        if fp_adj and result.label == 0:
            tag = "FP_ADJ"

        self._tree.insert("", "end",
            values=(
                icon,
                result.filename,
                result.path,
                risk,
                f"{result.probability*100:.1f}%",
                f"{raw_proba*100:.1f}%",
                adj_icon,
                f"{result.entropy:.3f}",
                size_str,
            ),
            tags=(tag,)
        )

    def _apply_filter(self, filter_val: str):
        self._filter_var.set(filter_val)
        search = self._search_var.get().lower()
        for item in self._tree.get_children():
            self._tree.delete(item)
        for r in self._results:
            if filter_val == "THREATS" and r.label == 0:
                continue
            if filter_val == "CRITICAL" and r.risk_level != "CRITICAL":
                continue
            if filter_val == "SAFE" and r.label != 0:
                continue
            if filter_val == "FP_ADJ" and not getattr(r, "fp_adjusted", False):
                continue
            if search and search not in r.filename.lower():
                continue
            self._add_tree_row(r)

    def _sort_tree(self, col: str):
        items = [(self._tree.set(k, col), k) for k in self._tree.get_children("")]
        try:
            items.sort(key=lambda x: float(x[0].replace("%", "").replace("↓", "0")), reverse=True)
        except ValueError:
            items.sort(key=lambda x: x[0], reverse=False)
        for idx, (_, k) in enumerate(items):
            self._tree.move(k, "", idx)

    def _update_stats(self, elapsed: float = None):
        total   = len(self._results)
        safe    = sum(1 for r in self._results if r.label == 0)
        threats = sum(1 for r in self._results if r.label == 1)
        crit    = sum(1 for r in self._results if r.risk_level == "CRITICAL")
        fp_adj  = sum(1 for r in self._results if getattr(r, "fp_adjusted", False))
        avg_h   = (sum(r.entropy for r in self._results) / total) if total > 0 else 0

        self._stat_total.configure(text=str(total))
        self._stat_safe.configure(text=str(safe))
        self._stat_threat.configure(text=str(threats),
            text_color=C["red"] if threats > 0 else C["green"])
        self._stat_crit.configure(text=str(crit),
            text_color=C["red"] if crit > 0 else C["green"])
        self._stat_fp_adj.configure(text=str(fp_adj),
            text_color=C["purple"] if fp_adj > 0 else C["text_dim"])
        self._stat_entropy.configure(text=f"{avg_h:.2f}")
        if elapsed is not None:
            self._stat_time.configure(text=f"{elapsed:.1f}s")

    def _set_status(self, text: str, color: str):
        self._status_var.set(text)
        self._status_badge.configure(fg_color=color,
            text_color=C["bg_dark"] if color != C["text_dim"] else C["text"])

    def _log(self, level: str, text: str):
        ts     = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": "[INFO]", "success": "[OK]  ",
            "warning": "[WARN]", "danger": "[ALERT]",
            "system": "[SYS] ", "fp": "[FP↓] "
        }.get(level, "[LOG] ")
        line = f"{ts}  {prefix}  {text}\n"
        self._log_text.configure(state="normal")
        self._log_text.insert("end", line, level)
        self._log_text.see("end")
        self._log_text.configure(state="disabled")

    def _clear_log(self):
        self._log_text.configure(state="normal")
        self._log_text.delete("1.0", "end")
        self._log_text.configure(state="disabled")

    def on_closing(self):
        if self._monitor.is_running:
            self._monitor.stop()
        if self._scanner.is_scanning:
            self._scanner.cancel()
        self.destroy()


def launch():
    app = RansomwareDetectorApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
