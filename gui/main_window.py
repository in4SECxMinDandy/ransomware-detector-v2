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
from datetime import datetime, timedelta

import customtkinter as ctk
import matplotlib
matplotlib.use('TkAgg')
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from core.scanner import Scanner, ScanResult
from core.ml_engine import get_engine
from core.watchdog_monitor import RealTimeMonitor, ThreatEvent
from core.process_monitor import BehaviorAlert, DynamicSignalAggregator, get_process_monitor
from core.report_generator import export_csv, export_report_png
from core.fp_reducer import (
    EXTENSION_THRESHOLDS,
    DEFAULT_EXTENSION_THRESHOLD,
    get_extension_threshold,
)
from core.pdf_reporter import export_model_report_pdf
from core.forensic_exporter import ForensicBundleExporter
from core.rule_updater import YARARuleUpdater
from core.auto_responder import AutoResponder, get_auto_responder
from core.network_monitor import NetworkAnalyzer
from core.config_manager import ConfigManager, get_config
from core.yara_engine import get_yara_engine
from gui.whitelist_editor import WhitelistEditorWindow, load_whitelist, apply_whitelist_to_fp_reducer
from gui.tray_manager import TrayManager, get_tray_manager

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


class PEAnalysisWindow(ctk.CTkToplevel):
    """v2.5: Hiển thị chi tiết PE Analysis khi double-click trên PE file."""

    def __init__(self, parent, result):
        super().__init__(parent)
        self.title(f"PE Analysis: {result.filename}")
        self.geometry("580x420")
        self.configure(fg_color=C["bg_dark"])
        self.resizable(True, True)

        hdr = ctk.CTkFrame(self, fg_color=C["bg_panel"], corner_radius=8)
        hdr.pack(fill="x", padx=12, pady=(12, 0))
        ctk.CTkLabel(
            hdr, text=f"PE ANALYSIS: {result.filename}",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=C["cyan"]
        ).pack(padx=12, pady=8)

        content = ctk.CTkScrollableFrame(self, fg_color=C["bg_dark"])
        content.pack(fill="both", expand=True, padx=12, pady=(8, 12))

        # File info
        info_frame = ctk.CTkFrame(content, fg_color=C["bg_panel"], corner_radius=6)
        info_frame.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(info_frame, text="FILE INFO",
                     font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                     text_color=C["accent"]).pack(padx=10, pady=(8, 4))
        for key, val in [
            ("Path", result.path),
            ("Size", f"{result.size/1024:.1f} KB"),
            ("Entropy", f"{result.entropy:.4f}"),
            ("Risk", result.risk_level),
            ("Probability", f"{result.probability*100:.1f}%"),
        ]:
            row = ctk.CTkFrame(info_frame, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=1)
            ctk.CTkLabel(row, text=f"{key}:", font=ctk.CTkFont(family="Consolas", size=9),
                         text_color=C["text_dim"], width=90, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=str(val), font=ctk.CTkFont(family="Consolas", size=9),
                         text_color=C["text"]).pack(side="left")

        # PE info
        pe_info = getattr(result, "pe_info", {}) or {}
        if pe_info:
            pe_frame = ctk.CTkFrame(content, fg_color=C["bg_panel"], corner_radius=6)
            pe_frame.pack(fill="x", pady=(0, 8))
            ctk.CTkLabel(pe_frame, text="PE STRUCTURE",
                         font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                         text_color=C["orange"]).pack(padx=10, pady=(8, 4))

            for key in ["is_pe", "is_packed", "is_suspicious"]:
                val = pe_info.get(key, False)
                color = C["red"] if val else C["green"]
                row = ctk.CTkFrame(pe_frame, fg_color="transparent")
                row.pack(fill="x", padx=10, pady=1)
                ctk.CTkLabel(row, text=f"{key}:", font=ctk.CTkFont(family="Consolas", size=9),
                             text_color=C["text_dim"], width=120, anchor="w").pack(side="left")
                ctk.CTkLabel(row, text=str(val), font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                             text_color=color).pack(side="left")

            rwx = pe_info.get("rwx_sections", [])
            if rwx:
                row = ctk.CTkFrame(pe_frame, fg_color="transparent")
                row.pack(fill="x", padx=10, pady=1)
                ctk.CTkLabel(row, text="RWX Sections:", font=ctk.CTkFont(family="Consolas", size=9),
                             text_color=C["text_dim"], width=120, anchor="w").pack(side="left")
                ctk.CTkLabel(row, text=", ".join(rwx), font=ctk.CTkFont(family="Consolas", size=9),
                             text_color=C["red"]).pack(side="left")

            susp = pe_info.get("suspicious_sections", [])
            if susp:
                row = ctk.CTkFrame(pe_frame, fg_color="transparent")
                row.pack(fill="x", padx=10, pady=1)
                ctk.CTkLabel(row, text="Suspicious Sections:", font=ctk.CTkFont(family="Consolas", size=9),
                             text_color=C["text_dim"], width=120, anchor="w").pack(side="left")
                ctk.CTkLabel(row, text=", ".join(susp), font=ctk.CTkFont(family="Consolas", size=9),
                             text_color=C["orange"]).pack(side="left")

        # YARA info
        yara_matches = getattr(result, "yara_matches", []) or []
        if yara_matches:
            yara_frame = ctk.CTkFrame(content, fg_color=C["bg_panel"], corner_radius=6)
            yara_frame.pack(fill="x", pady=(0, 8))
            ctk.CTkLabel(yara_frame, text=f"YARA MATCHES ({len(yara_matches)})",
                         font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                         text_color=C["purple"]).pack(padx=10, pady=(8, 4))
            for m in yara_matches:
                row = ctk.CTkFrame(yara_frame, fg_color="transparent")
                row.pack(fill="x", padx=10, pady=1)
                sev_color = {"CRITICAL": C["red"], "HIGH": C["orange"], "MEDIUM": C["yellow"]}.get(m.severity, C["text"])
                ctk.CTkLabel(row, text=f"[{m.severity}]", font=ctk.CTkFont(family="Consolas", size=9),
                             text_color=sev_color, width=75, anchor="w").pack(side="left")
                ctk.CTkLabel(row, text=m.rule_name, font=ctk.CTkFont(family="Consolas", size=9),
                             text_color=C["text"]).pack(side="left")

        # FP reason
        fp_reason = getattr(result, "fp_reason", "") or ""
        if fp_reason:
            reason_frame = ctk.CTkFrame(content, fg_color=C["bg_panel"], corner_radius=6)
            reason_frame.pack(fill="x", pady=(0, 8))
            ctk.CTkLabel(reason_frame, text="FP ANALYSIS",
                         font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                         text_color=C["purple"]).pack(padx=10, pady=(8, 4))
            ctk.CTkLabel(reason_frame, text=fp_reason.strip(" |"),
                         font=ctk.CTkFont(family="Consolas", size=8),
                         text_color=C["text_dim"], wraplength=520).pack(padx=10, pady=(0, 8))

        ctk.CTkButton(
            self, text="CLOSE", command=self.destroy,
            fg_color=C["bg_card"], hover_color=C["border"],
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=C["text_dim"], height=32, corner_radius=6,
            width=120
        ).pack(pady=(0, 12))


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


class AutoResponseWindow(ctk.CTkToplevel):
    """
    Task 5: Auto-Response dialog for HIGH severity threats.
    Shows countdown and action buttons.
    """

    def __init__(self, parent, alert: BehaviorAlert, responder):
        super().__init__(parent)
        self.title("⚠ HIGH THREAT DETECTED")
        self.geometry("580x420")
        self.configure(fg_color=C["bg_dark"])
        self.attributes("-topmost", True)
        self.resizable(False, False)

        self._alert = alert
        self._responder = responder
        self._countdown = 30  # seconds
        self._action_taken = False

        # Severity color
        ctk.CTkLabel(
            self, text="⚠  HIGH THREAT DETECTED",
            font=ctk.CTkFont(family="Consolas", size=20, weight="bold"),
            text_color=C["orange"]
        ).pack(pady=(15, 5))

        # File info
        info_frame = ctk.CTkFrame(self, fg_color=C["bg_panel"], corner_radius=8)
        info_frame.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(
            info_frame, text="THREAT DETAILS",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=C["accent"]
        ).pack(pady=(8, 5))

        file_path = alert.files[0] if alert.files else "Unknown"
        info_items = [
            ("File", file_path[:50] + "..." if len(file_path) > 50 else file_path),
            ("Score", f"{alert.severity.upper()}"),
            ("YARA", alert.behavior_type.value),
            ("Description", alert.description[:60] + "..." if len(alert.description) > 60 else alert.description),
        ]

        for key, val in info_items:
            row = ctk.CTkFrame(info_frame, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=2)
            ctk.CTkLabel(row, text=f"{key}:", font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=C["text_dim"], width=100, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=val, font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=C["text"], anchor="w").pack(side="left")

        # Countdown label
        self._countdown_lbl = ctk.CTkLabel(
            self, text=f"Auto-action in: {self._countdown}s",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=C["yellow"]
        )
        self._countdown_lbl.pack(pady=10)

        # Buttons frame
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=10)

        ctk.CTkButton(
            btn_frame, text="Quarantine",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            fg_color=C["danger"], hover_color="#B22222",
            text_color="#FFF", width=110, height=35, corner_radius=6,
            command=self._on_quarantine
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame, text="Kill Process",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            fg_color=C["orange"], hover_color="#B25900",
            text_color="#FFF", width=110, height=35, corner_radius=6,
            command=self._on_kill_process
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame, text="Block Network",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            fg_color=C["yellow"], hover_color="#C4A000",
            text_color="#000", width=110, height=35, corner_radius=6,
            command=self._on_block_network
        ).pack(side="left", padx=5)

        # Secondary buttons
        btn_frame2 = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame2.pack(pady=5)

        ctk.CTkButton(
            btn_frame2, text="View Details",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["bg_card"], hover_color=C["border"],
            text_color=C["text"], width=110, height=30, corner_radius=6,
            command=self._on_view_details
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame2, text="Ignore",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["bg_card"], hover_color=C["border"],
            text_color=C["text"], width=110, height=30, corner_radius=6,
            command=self.destroy
        ).pack(side="left", padx=5)

        # Start countdown
        self._update_countdown()

    def _update_countdown(self):
        """Update countdown timer."""
        if self._action_taken or not self.winfo_exists():
            return

        self._countdown -= 1
        if self._countdown <= 0:
            # Auto quarantine
            self._on_quarantine()
            return

        self._countdown_lbl.configure(text=f"Auto-action in: {self._countdown}s")
        self.after(1000, self._update_countdown)

    def _on_quarantine(self):
        """Quarantine the file."""
        self._action_taken = True
        for fpath in self._alert.files:
            self._responder.quarantine_file(fpath, reason=f"HIGH threat: {self._alert.description}")
        self.destroy()

    def _on_kill_process(self):
        """Kill the malicious process."""
        self._action_taken = True
        self._responder.kill_process(self._alert.process.pid, self._alert.process.name)
        self.destroy()

    def _on_block_network(self):
        """Block network for the process."""
        self._action_taken = True
        self._responder.block_network(self._alert.process.pid, self._alert.process.name)
        self.destroy()

    def _on_view_details(self):
        """Show behavior alert details."""
        BehaviorAlertWindow(self.master, self._alert)


class RansomwareDetectorApp(ctk.CTk):
    """Main Application Window — v2.0 Anti-FP Edition."""

    def __init__(self):
        super().__init__()

        self.title("Ransomware Entropy Detector v2.2  |  Premium Defense")
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

        # Task 1: Chart update counter
        self._chart_update_counter = 0

        # Sensitivity profile (Task 9)
        self._sensitivity_var = tk.StringVar(value="balanced")

        # Network auto-refresh (Task 7)
        self._net_auto_refresh = False
        self._net_refresh_counter = 0

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

        # Task 4: Initialize tray manager
        try:
            self._tray_manager = get_tray_manager(self)
            self._tray_manager.set_callbacks(
                on_open=lambda: self.restore_from_tray(),
                on_quit=self.quit_app,
                on_toggle_protection=self._on_protection_toggled,
                on_view_alerts=lambda: self.restore_from_tray(),
                on_quick_scan=lambda: self.restore_from_tray(),
            )
            self._tray_manager.run()
        except Exception:
            self._tray_manager = None

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

        # v2.2 badge
        ctk.CTkLabel(
            hdr,
            text="v2.2  Premium",
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

        # ── v2.5: Sensitivity Profile Selector ──
        self._section_label(scroll, "◈ SCAN PROFILE")
        profile_frame = ctk.CTkFrame(scroll, fg_color=C["bg_card"], corner_radius=6)
        profile_frame.pack(fill="x", pady=(3, 5))

        ctk.CTkLabel(profile_frame, text="Sensitivity",
                     font=ctk.CTkFont(family="Consolas", size=9),
                     text_color=C["text_dim"]).pack(anchor="w", padx=8, pady=(6, 2))

        profile_row = ctk.CTkFrame(profile_frame, fg_color="transparent")
        profile_row.pack(fill="x", padx=6, pady=(0, 6))

        for profile_key, label in [
            ("paranoid", "🔒 Paranoid"),
            ("high_sensitivity", "🔶 High"),
            ("balanced", "⚖ Balanced"),
        ]:
            ctk.CTkButton(
                profile_row, text=label,
                font=ctk.CTkFont(family="Consolas", size=8),
                fg_color=C["bg_dark"],
                hover_color=C["border"],
                text_color=C["text_dim"],
                height=26, corner_radius=4,
                command=lambda p=profile_key: self._set_sensitivity(p)
            ).pack(side="left", padx=(0, 4))

        self._profile_hint_lbl = ctk.CTkLabel(
            profile_frame, text="Balanced — recommended",
            font=ctk.CTkFont(family="Consolas", size=7),
            text_color=C["cyan"]
        )
        self._profile_hint_lbl.pack(pady=(0, 6))

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

        # Task 2: Export Forensic Bundle
        self._export_forensic_btn = ctk.CTkButton(
            scroll, text="🔍  Export Forensic Bundle",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["danger"], hover_color="#B22222",
            text_color="#FFF", height=34, corner_radius=6,
            command=self._export_forensic_bundle
        )
        self._export_forensic_btn.pack(fill="x", pady=(0, 8))

        # v2.1: Whitelist Editor
        ctk.CTkButton(
            scroll, text="📋  Whitelist Editor",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["purple"], hover_color="#9A6FD0",
            text_color="#FFF", height=34, corner_radius=6,
            command=self._open_whitelist_editor
        ).pack(fill="x", pady=(0, 8))

        # ── ML Engine Info ──
        self._section_label(scroll, "◈ ML ENGINE  (v2.2)")
        self._ml_info_lbl = ctk.CTkLabel(
            scroll, text="Loading model...",
            font=ctk.CTkFont(family="Consolas", size=8),
            text_color=C["text_dim"], wraplength=260, justify="left"
        )
        self._ml_info_lbl.pack(anchor="w", padx=5, pady=(0, 4))

        # v2.5: Process Monitor Stats
        self._section_label(scroll, "◈ PROCESS MONITOR STATS")
        self._pm_stats_lbl = ctk.CTkLabel(
            scroll, text="No active monitoring",
            font=ctk.CTkFont(family="Consolas", size=8),
            text_color=C["text_dim"], wraplength=260, justify="left"
        )
        self._pm_stats_lbl.pack(anchor="w", padx=5, pady=(0, 4))

        # ── Config Manager ──
        self._section_label(scroll, "◈ SETTINGS")
        ctk.CTkButton(
            scroll, text="⚙  Config Manager",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=C["bg_card"], hover_color=C["border"],
            text_color=C["text"], height=34, corner_radius=6,
            command=self._open_config_manager
        ).pack(fill="x", pady=(3, 8))

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

        # Tab view for Scan Results and Behavior Signals (Task 1)
        self._results_tabview = ctk.CTkTabview(panel, fg_color=C["bg_card"])
        self._results_tabview.pack(fill="both", expand=True, padx=8, pady=(8, 4))

        # Tab: Scan Results
        self._scan_results_tab = self._results_tabview.add("Scan Results")
        self._build_scan_results_tab(self._scan_results_tab)

        # Tab: Behavior Signals (Task 1)
        self._behavior_signals_tab = self._results_tabview.add("Behavior Signals")
        self._build_behavior_signals_tab(self._behavior_signals_tab)

        # Tab: Rules Manager (Task 3)
        self._rules_manager_tab = self._results_tabview.add("Rules Manager")
        self._build_rules_manager_tab(self._rules_manager_tab)

        # Tab: Network Monitor (Task 6)
        self._network_monitor_tab = self._results_tabview.add("Network Monitor")
        self._build_network_monitor_tab(self._network_monitor_tab)

        # Tab: Quarantine Manager (v2.5)
        self._quarantine_tab = self._results_tabview.add("Quarantine")
        self._build_quarantine_tab(self._quarantine_tab)

    def _build_scan_results_tab(self, parent):
        """Build the Scan Results tab content."""
        tab_hdr = ctk.CTkFrame(parent, fg_color=C["bg_card"], corner_radius=8, height=38)
        tab_hdr.pack(fill="x", padx=4, pady=(4, 4))
        tab_hdr.pack_propagate(False)
        ctk.CTkLabel(
            tab_hdr, text="◈  SCAN RESULTS  —  Premium Defense",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=C["accent"]
        ).pack(side="left", padx=12, pady=6)

        # Filter bar
        filter_frame = ctk.CTkFrame(parent, fg_color="transparent")
        filter_frame.pack(fill="x", padx=8, pady=(0, 4))

        self._filter_var = tk.StringVar(value="ALL")
        for txt, val in [("All", "ALL"), ("Threats", "THREATS"),
                         ("Critical", "CRITICAL"), ("Safe", "SAFE"),
                         ("FP Adj.", "FP_ADJ")]:
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

        # Treeview table
        tree_frame = ctk.CTkFrame(parent, fg_color=C["bg_dark"], corner_radius=6)
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
            ("adj",         "FP↓",        40,  False),
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
        self._tree.tag_configure("FP_ADJ",  foreground=C["purple"])

        # v2.5: Double-click to show PE analysis details
        self._tree.bind("<Double-Button-1>", self._on_result_double_click)

    def _build_behavior_signals_tab(self, parent):
        """Task 1: Build the Behavior Signals tab with real-time chart."""
        # Header
        hdr = ctk.CTkFrame(parent, fg_color=C["bg_card"], corner_radius=8, height=38)
        hdr.pack(fill="x", padx=4, pady=(4, 4))
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr, text="◈  BEHAVIOR SIGNALS  —  Real-time Monitoring",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=C["green"]
        ).pack(side="left", padx=12, pady=6)

        # Status label
        self._behavior_status_lbl = ctk.CTkLabel(
            parent, text="● MONITORING",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=C["green"]
        )
        self._behavior_status_lbl.pack(anchor="w", padx=12, pady=(4, 0))

        # Chart frame
        chart_frame = ctk.CTkFrame(parent, fg_color=C["bg_dark"], corner_radius=6)
        chart_frame.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        # Create matplotlib figure
        self._behavior_fig = Figure(figsize=(8, 4), facecolor=C["bg_dark"])
        self._behavior_ax = self._behavior_fig.add_subplot(111)
        self._behavior_ax.set_facecolor(C["bg_dark"])

        # Configure plot
        self._behavior_ax.set_title("Rename Rate & I/O Rate (Last 60s)", color=C["text"], fontsize=10)
        self._behavior_ax.set_xlabel("Time (s)", color=C["text_dim"], fontsize=8)
        self._behavior_ax.set_ylabel("Rate", color=C["text_dim"], fontsize=8)
        self._behavior_ax.tick_params(colors=C["text_dim"], labelsize=7)
        for spine in self._behavior_ax.spines.values():
            spine.set_color(C["border"])

        # Create canvas
        self._behavior_canvas = FigureCanvasTkAgg(self._behavior_fig, master=chart_frame)
        self._behavior_canvas.get_tk_widget().pack(fill="both", expand=True)

        # Data storage for chart
        self._rename_rate_data: List[float] = []
        self._io_rate_data: List[float] = []
        self._time_data: List[float] = []
        self._chart_start_time = time.time()

        # Stats panel
        stats_frame = ctk.CTkFrame(parent, fg_color=C["bg_card"], corner_radius=6)
        stats_frame.pack(fill="x", padx=8, pady=(0, 8))
        stats_frame.columnconfigure((0, 1, 2, 3), weight=1)

        self._sig_stat_rename = self._stat_card(stats_frame, "Rename/s", "0", C["blue"], 0, 0)
        self._sig_stat_io = self._stat_card(stats_frame, "IO MB/s", "0", C["cyan"], 0, 1)
        self._sig_stat_score = self._stat_card(stats_frame, "Threat Score", "0.00", C["green"], 0, 2)
        self._sig_stat_alerts = self._stat_card(stats_frame, "Alerts", "0", C["red"], 0, 3)

        # Initialize signal aggregator
        self._signal_aggregator = DynamicSignalAggregator()

    def _update_behavior_chart(self):
        """Task 1: Update behavior signals chart every 2 seconds."""
        if not hasattr(self, "_behavior_fig"):
            return

        try:
            # Get real data from ProcessMonitor
            io_stats = {}
            if hasattr(self, "_monitor") and self._monitor.is_running:
                io_stats = self._monitor.get_current_io_rate()

            # Update time data
            current_time = time.time() - self._chart_start_time
            self._time_data.append(current_time)

            # Keep only last 60 seconds
            while self._time_data and self._time_data[0] < current_time - 60:
                self._time_data.pop(0)

            # Get aggregate IO rate across all monitored processes
            total_write_mbps = sum(s.get("write_mbps", 0) for s in io_stats.values())
            self._io_rate_data.append(total_write_mbps)

            # Count rename events (from process monitor alerts)
            rename_count = 0
            if hasattr(self, "_monitor") and self._monitor.is_running:
                pm = self._monitor._process_monitor
                rename_events = 0
                for pid, events in pm._rename_events.items():
                    now = datetime.now()
                    window = now - timedelta(seconds=10)
                    rename_events += sum(1 for e in events if e.timestamp > window)
                rename_count = rename_events
            self._rename_rate_data.append(float(rename_count))

            # Trim to match time data
            self._rename_rate_data = self._rename_rate_data[-len(self._time_data):]
            self._io_rate_data = self._io_rate_data[-len(self._time_data):]

            # Update stats labels
            if hasattr(self, "_sig_stat_rename"):
                self._sig_stat_rename.configure(text=str(rename_count))
            if hasattr(self, "_sig_stat_io"):
                self._sig_stat_io.configure(text=f"{total_write_mbps:.1f}")

            # Clear and redraw
            self._behavior_ax.clear()
            self._behavior_ax.set_facecolor(C["bg_dark"])
            self._behavior_ax.set_title("Rename Rate & I/O Rate (Last 60s)", color=C["text"], fontsize=10)
            self._behavior_ax.set_xlabel("Time (s)", color=C["text_dim"], fontsize=8)
            self._behavior_ax.set_ylabel("Rate", color=C["text_dim"], fontsize=8)
            self._behavior_ax.tick_params(colors=C["text_dim"], labelsize=7)

            # Plot data if available
            if len(self._time_data) > 1:
                # Relative time
                rel_time = [t - self._time_data[0] for t in self._time_data]
                self._behavior_ax.plot(rel_time, self._rename_rate_data, color=C["blue"], label="Rename/s", linewidth=1.5)
                self._behavior_ax.plot(rel_time, self._io_rate_data, color=C["cyan"], label="IO MB/s", linewidth=1.5)
                self._behavior_ax.legend(facecolor=C["bg_card"], labelcolor=C["text"], fontsize=7)

            # Set axis limits
            if self._time_data:
                self._behavior_ax.set_xlim(0, max(60, self._time_data[-1] - self._time_data[0]))
                max_rate = max(max(self._rename_rate_data) if self._rename_rate_data else 1,
                              max(self._io_rate_data) if self._io_rate_data else 1)
                self._behavior_ax.set_ylim(0, max(10, max_rate * 1.1))

            for spine in self._behavior_ax.spines.values():
                spine.set_color(C["border"])

            self._behavior_fig.tight_layout()
            self._behavior_canvas.draw()

        except Exception as e:
            pass  # Silently ignore chart update errors

    def record_behavior_data(self, rename_rate: float, io_rate_mbps: float):
        """Task 1: Record behavior data for chart."""
        if hasattr(self, "_rename_rate_data"):
            self._rename_rate_data.append(rename_rate)
            self._io_rate_data.append(io_rate_mbps)

    def _build_rules_manager_tab(self, parent):
        """Task 3: Build the Rules Manager tab."""
        # Header
        hdr = ctk.CTkFrame(parent, fg_color=C["bg_card"], corner_radius=8, height=38)
        hdr.pack(fill="x", padx=4, pady=(4, 4))
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr, text="◈  RULES MANAGER  —  YARA Rule Pack Updater",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=C["orange"]
        ).pack(side="left", padx=12, pady=6)

        # Status label
        self._rules_status_lbl = ctk.CTkLabel(
            parent, text="● Ready",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=C["text_dim"]
        )
        self._rules_status_lbl.pack(anchor="w", padx=12, pady=(4, 0))

        # Auto-update toggle
        toggle_frame = ctk.CTkFrame(parent, fg_color="transparent")
        toggle_frame.pack(fill="x", padx=8, pady=(8, 4))

        self._auto_update_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            toggle_frame, text="Auto-update (24h)",
            variable=self._auto_update_var,
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=C["text"],
            fg_color=C["bg_card"],
            hover_color=C["border"],
            command=self._toggle_auto_update
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            toggle_frame, text="Check for Updates",
            font=ctk.CTkFont(family="Consolas", size=9),
            fg_color=C["accent"], hover_color=C["accent_h"],
            text_color="#FFF", height=30, corner_radius=6,
            command=self._check_rule_updates
        ).pack(side="left", padx=(0, 5))

        ctk.CTkButton(
            toggle_frame, text="Force Update Now",
            font=ctk.CTkFont(family="Consolas", size=9),
            fg_color=C["danger"], hover_color="#B22222",
            text_color="#FFF", height=30, corner_radius=6,
            command=self._force_update_rules
        ).pack(side="left")

        # Progress bar
        self._rules_progress = ctk.CTkProgressBar(
            parent, height=8, corner_radius=4,
            fg_color=C["bg_dark"], progress_color=C["green"]
        )
        self._rules_progress.pack(fill="x", padx=8, pady=(4, 8))
        self._rules_progress.set(0)

        # Rules table
        table_frame = ctk.CTkFrame(parent, fg_color=C["bg_dark"], corner_radius=6)
        table_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Rules.Treeview",
                        background=C["bg_dark"],
                        foreground=C["text"],
                        rowheight=24,
                        fieldbackground=C["bg_dark"],
                        borderwidth=0,
                        font=("Consolas", 8))
        style.configure("Rules.Treeview.Heading",
                        background=C["bg_card"],
                        foreground=C["orange"],
                        borderwidth=0,
                        font=("Consolas", 8, "bold"),
                        relief="flat")

        columns = ("name", "source", "last_updated", "status")
        self._rules_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings",
            style="Rules.Treeview", selectmode="browse", height=8
        )

        col_config = [
            ("name", "Name", 200),
            ("source", "Source", 200),
            ("last_updated", "Last Updated", 150),
            ("status", "Status", 80),
        ]
        for col, heading, width in col_config:
            self._rules_tree.heading(col, text=heading)
            self._rules_tree.column(col, width=width, minwidth=50)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self._rules_tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self._rules_tree.xview)
        self._rules_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._rules_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self._rules_tree.tag_configure("ok", foreground=C["green"])
        self._rules_tree.tag_configure("error", foreground=C["red"])

        # Initialize rules manager
        self._rules_updater = YARARuleUpdater()
        self._load_rules_table()

    def _load_rules_table(self):
        """Load rules into the table."""
        for item in self._rules_tree.get_children():
            self._rules_tree.delete(item)

        # Load local rules
        local_rules = self._rules_updater.get_local_rules()
        update_log = self._rules_updater.get_update_log()

        # Add local rules
        for rule in local_rules:
            last_update = "Never"
            for entry in reversed(update_log):
                if entry.get("filename") == rule["name"]:
                    last_update = entry.get("timestamp", "Unknown")[:10]
                    break

            status = "✓ Built-in" if rule.get("is_builtin") else "✓ OK"
            self._rules_tree.insert("", "end",
                values=(rule["name"], "Local", last_update, status),
                tags=("ok" if "✓" in status else "error",)
            )

        # Add sources
        sources = self._rules_updater.get_source_status()
        for source in sources:
            last_update = "Never"
            for entry in reversed(update_log):
                if entry.get("source") == source["url"]:
                    last_update = entry.get("timestamp", "Unknown")[:10]
                    status = "✓ OK" if entry.get("status") == "success" else "✗ Failed"
                    break
            else:
                status = "○ Pending"

            self._rules_tree.insert("", "end",
                values=(source["name"], source["url"][:30] + "...", last_update, status),
                tags=("ok" if "✓" in status else "error",)
            )

    def _toggle_auto_update(self):
        """Toggle auto-update on/off."""
        if self._auto_update_var.get():
            self._rules_updater.start_scheduler()
            self._rules_status_lbl.configure(text="● Auto-update enabled (24h)", text_color=C["green"])
        else:
            self._rules_updater.stop_scheduler()
            self._rules_status_lbl.configure(text="● Auto-update disabled", text_color=C["text_dim"])

    def _check_rule_updates(self):
        """Check for rule updates."""
        self._rules_status_lbl.configure(text="● Checking for updates...", text_color=C["yellow"])
        self._rules_progress.set(0.5)

        def _check():
            results = self._rules_updater.check_for_updates()
            self._ui_queue.put(("rules_update_result", results))

        threading.Thread(target=_check, daemon=True).start()

    def _force_update_rules(self):
        """Force immediate rule update."""
        self._rules_status_lbl.configure(text="● Updating rules...", text_color=C["orange"])
        self._rules_progress.set(0.3)

        def _update():
            results = self._rules_updater.force_update_now()
            self._ui_queue.put(("rules_update_result", results))

        threading.Thread(target=_update, daemon=True).start()

    def _build_network_monitor_tab(self, parent):
        """Task 6: Build the Network Monitor tab."""
        # Header
        hdr = ctk.CTkFrame(parent, fg_color=C["bg_card"], corner_radius=8, height=38)
        hdr.pack(fill="x", padx=4, pady=(4, 4))
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr, text="◈  NETWORK MONITOR  —  C2 Detection",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=C["cyan"]
        ).pack(side="left", padx=12, pady=6)

        # Status label
        self._net_status_lbl = ctk.CTkLabel(
            parent, text="● Monitoring: OFF",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=C["text_dim"]
        )
        self._net_status_lbl.pack(anchor="w", padx=12, pady=(4, 0))

        # Control buttons
        btn_frame = ctk.CTkFrame(parent, fg_color="transparent")
        btn_frame.pack(fill="x", padx=8, pady=(4, 4))

        self._net_refresh_btn = ctk.CTkButton(
            btn_frame, text="↻ Refresh",
            font=ctk.CTkFont(family="Consolas", size=9),
            fg_color=C["accent"], hover_color=C["accent_h"],
            text_color="#FFF", height=30, corner_radius=6,
            command=self._refresh_network_connections
        ).pack(side="left", padx=(0, 4))

        self._net_auto_refresh_btn = ctk.CTkButton(
            btn_frame, text="▶ Auto-Refresh",
            font=ctk.CTkFont(family="Consolas", size=9),
            fg_color=C["bg_card"], hover_color=C["border"],
            text_color=C["text_dim"], height=30, corner_radius=6,
            command=self._toggle_net_auto_refresh
        ).pack(side="left", padx=(0, 4))

        self._net_block_btn = ctk.CTkButton(
            btn_frame, text="Block Selected IP",
            font=ctk.CTkFont(family="Consolas", size=9),
            fg_color=C["danger"], hover_color="#B22222",
            text_color="#FFF", height=30, corner_radius=6,
            command=self._block_selected_ip
        ).pack(side="left")

        # Connections table
        table_frame = ctk.CTkFrame(parent, fg_color=C["bg_dark"], corner_radius=6)
        table_frame.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Net.Treeview",
                        background=C["bg_dark"],
                        foreground=C["text"],
                        rowheight=22,
                        fieldbackground=C["bg_dark"],
                        borderwidth=0,
                        font=("Consolas", 8))
        style.configure("Net.Treeview.Heading",
                        background=C["bg_card"],
                        foreground=C["cyan"],
                        borderwidth=0,
                        font=("Consolas", 8, "bold"),
                        relief="flat")

        columns = ("pid", "process", "remote_ip", "port", "country", "risk", "c2_indicator")
        self._net_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings",
            style="Net.Treeview", selectmode="browse", height=12
        )

        col_config = [
            ("pid", "PID", 60),
            ("process", "Process", 120),
            ("remote_ip", "Remote IP", 130),
            ("port", "Port", 60),
            ("country", "Country", 80),
            ("risk", "Risk", 70),
            ("c2_indicator", "C2 Indicator", 150),
        ]
        for col, heading, width in col_config:
            self._net_tree.heading(col, text=heading)
            self._net_tree.column(col, width=width, minwidth=40)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self._net_tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self._net_tree.xview)
        self._net_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._net_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self._net_tree.tag_configure("safe", foreground=C["green"])
        self._net_tree.tag_configure("suspicious", foreground=C["yellow"])
        self._net_tree.tag_configure("blocked", foreground=C["red"])

        # Initialize network analyzer
        self._network_analyzer = NetworkAnalyzer()

        # v2.5: Refresh counter
        self._net_refresh_counter = 0

    def _build_quarantine_tab(self, parent):
        """v2.5: Build the Quarantine Manager tab."""
        # Header
        hdr = ctk.CTkFrame(parent, fg_color=C["bg_card"], corner_radius=8, height=38)
        hdr.pack(fill="x", padx=4, pady=(4, 4))
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr, text="◈  QUARANTINE MANAGER  —  Isolated Threats",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=C["danger"]
        ).pack(side="left", padx=12, pady=6)

        # Controls
        ctrl_frame = ctk.CTkFrame(parent, fg_color="transparent")
        ctrl_frame.pack(fill="x", padx=8, pady=(4, 4))
        ctrl_frame.columnconfigure((0, 1, 2), weight=1)

        ctk.CTkButton(
            ctrl_frame, text="↻ Refresh List",
            font=ctk.CTkFont(family="Consolas", size=9),
            fg_color=C["accent"], hover_color=C["accent_h"],
            text_color="#FFF", height=30, corner_radius=6,
            command=self._refresh_quarantine_list
        ).grid(row=0, column=0, padx=(0, 4), sticky="ew")

        ctk.CTkButton(
            ctrl_frame, text="↩ Restore Selected",
            font=ctk.CTkFont(family="Consolas", size=9),
            fg_color=C["green"], hover_color="#1A9A4A",
            text_color="#FFF", height=30, corner_radius=6,
            command=self._restore_quarantined_file
        ).grid(row=0, column=1, padx=(0, 4), sticky="ew")

        ctk.CTkButton(
            ctrl_frame, text="🗑 Delete Selected",
            font=ctk.CTkFont(family="Consolas", size=9),
            fg_color=C["danger"], hover_color="#B22222",
            text_color="#FFF", height=30, corner_radius=6,
            command=self._delete_quarantined_file
        ).grid(row=0, column=2, sticky="ew")

        # Info label
        self._quarantine_info_lbl = ctk.CTkLabel(
            ctrl_frame, text="0 quarantined files",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=C["text_dim"]
        )
        self._quarantine_info_lbl.grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 0))

        # Table
        table_frame = ctk.CTkFrame(parent, fg_color=C["bg_dark"], corner_radius=6)
        table_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Quar.Treeview",
                        background=C["bg_dark"],
                        foreground=C["text"],
                        rowheight=22,
                        fieldbackground=C["bg_dark"],
                        borderwidth=0,
                        font=("Consolas", 8))
        style.configure("Quar.Treeview.Heading",
                        background=C["bg_card"],
                        foreground=C["danger"],
                        borderwidth=0,
                        font=("Consolas", 8, "bold"),
                        relief="flat")

        columns = ("id", "original_path", "reason", "timestamp", "hash")
        self._quarantine_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings",
            style="Quar.Treeview", selectmode="extended", height=10
        )

        col_config = [
            ("id", "ID", 140),
            ("original_path", "Original Path", 320),
            ("reason", "Reason", 150),
            ("timestamp", "Date", 140),
            ("hash", "SHA-256", 180),
        ]
        for col, heading, width in col_config:
            self._quarantine_tree.heading(col, text=heading)
            self._quarantine_tree.column(col, width=width, minwidth=80)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self._quarantine_tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self._quarantine_tree.xview)
        self._quarantine_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._quarantine_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self._quarantine_tree.tag_configure("safe", foreground=C["green"])
        self._quarantine_tree.tag_configure("danger", foreground=C["red"])

        # Load initial list
        self._refresh_quarantine_list()

    def _refresh_quarantine_list(self):
        """Load quarantine list."""
        responder = get_auto_responder()
        items = responder.get_quarantine_list()

        for item in self._quarantine_tree.get_children():
            self._quarantine_tree.delete(item)

        for item in items:
            short_path = item["original_path"][:50] + "..." if len(item["original_path"]) > 50 else item["original_path"]
            self._quarantine_tree.insert("", "end",
                values=(
                    item["id"],
                    short_path,
                    item.get("reason", "Unknown")[:25],
                    item.get("timestamp", "")[:19],
                    item.get("hash", "")[:16] + "..." if item.get("hash") else "N/A",
                ),
                tags=("danger",)
            )

        count = len(items)
        self._quarantine_info_lbl.configure(
            text=f"{count} quarantined file{'s' if count != 1 else ''}"
        )

    def _restore_quarantined_file(self):
        """Restore selected quarantined file."""
        selection = self._quarantine_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Select a file to restore.")
            return

        items_data = [self._quarantine_tree.item(s)["values"] for s in selection]
        restored = 0
        for vals in items_data:
            qid = vals[0]
            responder = get_auto_responder()
            if responder.restore_file(qid):
                restored += 1

        self._log("success", f"Restored {restored} file(s)")
        self._refresh_quarantine_list()
        messagebox.showinfo("Restore", f"Restored {restored} file(s)")

    def _delete_quarantined_file(self):
        """Delete selected quarantined file permanently."""
        selection = self._quarantine_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Select a file to delete.")
            return

        confirm = messagebox.askyesno(
            "Confirm Delete",
            "This will PERMANENTLY delete the selected file(s).\nThis action cannot be undone."
        )
        if not confirm:
            return

        deleted = 0
        for s in selection:
            vals = self._quarantine_tree.item(s)["values"]
            qid = vals[0]
            responder = get_auto_responder()
            # Move to /dev/null by restoring to original path and deleting
            manifest = responder._load_manifest()
            entry = manifest.get(qid)
            if entry:
                quarantined_path = entry.get("quarantined_path", "")
                try:
                    if os.path.exists(quarantined_path):
                        os.remove(quarantined_path)
                    del manifest[qid]
                    responder._save_manifest(manifest)
                    deleted += 1
                except Exception:
                    pass

        self._log("warning", f"Deleted {deleted} quarantined file(s)")
        self._refresh_quarantine_list()
        messagebox.showinfo("Delete", f"Deleted {deleted} file(s)")

    def _refresh_network_connections(self):
        """Refresh network connections table."""
        self._net_status_lbl.configure(text="● Refreshing...", text_color=C["yellow"])

        def _refresh():
            connections = self._network_analyzer.get_all_connections()
            self._ui_queue.put(("net_connections", connections))

        threading.Thread(target=_refresh, daemon=True).start()

    def _toggle_net_auto_refresh(self):
        """Toggle auto-refresh for network connections."""
        self._net_auto_refresh = not self._net_auto_refresh
        if self._net_auto_refresh:
            self._net_auto_refresh_btn.configure(
                text="⏸ Stop Auto-Refresh",
                fg_color=C["danger"], hover_color="#B22222",
            )
            self._log("info", "Network auto-refresh: ON (every 10s)")
        else:
            self._net_auto_refresh_btn.configure(
                text="▶ Auto-Refresh",
                fg_color=C["accent"], hover_color=C["accent_h"],
            )
            self._log("info", "Network auto-refresh: OFF")

    def _block_selected_ip(self):
        """Block selected IP in network table."""
        selection = self._net_tree.selection()
        if not selection:
            return

        item = self._net_tree.item(selection[0])
        values = item.get("values", [])

        if len(values) < 3:
            return

        ip = values[2]  # remote_ip column
        pid = int(values[0]) if values[0] else 0
        process = values[1]

        responder = get_auto_responder()
        success = responder.block_network(pid, process)

        if success:
            self._log("success", f"Blocked network for IP: {ip}")
            messagebox.showinfo("Success", f"Network blocked for {ip}")
        else:
            self._log("danger", f"Failed to block IP: {ip}")
            messagebox.showerror("Error", f"Failed to block IP: {ip}")

    def _populate_network_table(self, connections):
        """Populate network connections table."""
        for item in self._net_tree.get_children():
            self._net_tree.delete(item)

        for conn in connections[:100]:  # Show max 100
            ip = conn.get("remote_ip", "Unknown")
            port = conn.get("remote_port", 0)
            pid = conn.get("pid", 0)
            process = conn.get("process_name", "Unknown")

            # Analyze for C2 indicators
            analysis = self._network_analyzer.analyze_connections([conn])
            risk_level = analysis.get("risk_level", "SAFE")
            indicators = analysis.get("indicators", [])
            c2_indicator = ", ".join([i["type"] for i in indicators]) if indicators else ""

            # Risk color
            if risk_level == "CRITICAL":
                tag = "blocked"
            elif risk_level == "HIGH":
                tag = "suspicious"
            else:
                tag = "safe"

            # Country (placeholder)
            country = "???"

            self._net_tree.insert("", "end",
                values=(pid, process, ip, port, country, risk_level, c2_indicator),
                tags=(tag,)
            )

        self._net_status_lbl.configure(
            text=f"● Monitoring: {len(connections)} connections",
            text_color=C["green"]
        )

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

    def _set_sensitivity(self, profile: str):
        """Set sensitivity profile and update UI."""
        self._sensitivity_var.set(profile)

        hints = {
            "paranoid":          ("🔒 Paranoid — maximum sensitivity",  C["red"]),
            "high_sensitivity":   ("🔶 High Sensitivity",                C["orange"]),
            "balanced":           ("⚖ Balanced — recommended",          C["cyan"]),
        }
        hint, color = hints.get(profile, ("⚖ Balanced", C["cyan"]))
        self._profile_hint_lbl.configure(text=hint, text_color=color)
        self._log("info", f"Profile: {profile}")

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

        # Đồng bộ sensitivity profile vào scanner
        self._scanner.set_sensitivity(self._sensitivity_var.get())

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
        scan_mode = "full" if recursive else "quick"
        self._scanner.scan(
            directory=scan_dir,
            recursive=recursive,
            on_progress=self._on_scan_progress,
            on_complete=self._on_scan_complete,
            on_error=self._on_scan_error,
            scan_mode=scan_mode,
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

    def _export_forensic_bundle(self):
        """Task 2: Export Forensic Bundle."""
        if not self._results:
            messagebox.showinfo("Info", "No scan results to export.")
            return

        output_dir = filedialog.askdirectory(title="Select output directory for forensic bundle")
        if not output_dir:
            return

        self._log("info", "Generating forensic bundle...")

        def _gen():
            try:
                exporter = ForensicBundleExporter()
                bundle_path = exporter.export(self._results, output_dir)

                # Count IOCs
                ioc_count = sum(
                    1 for r in self._results
                    if r.risk_level in ["CRITICAL", "HIGH"]
                )

                self._ui_queue.put(("log", "success", f"Forensic bundle saved: {bundle_path}"))
                self._ui_queue.put((
                    "msgbox", "Export Complete",
                    f"Saved: {os.path.basename(bundle_path)}\n({ioc_count} IOCs found)"
                ))
            except Exception as e:
                self._ui_queue.put(("log", "danger", f"Forensic bundle export failed: {e}"))

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

                    # Task 5: Check auto-response policy
                    responder = get_auto_responder()
                    action = responder.get_response_action(alert.severity)

                    if action == "auto_quarantine":
                        # Auto quarantine for CRITICAL
                        for fpath in alert.files:
                            responder.quarantine_file(fpath, reason=f"CRITICAL: {alert.description}")
                        self._log("danger", f"[AUTO] Quarantined: {alert.files[0] if alert.files else 'unknown'}")

                    elif action == "ask_user":
                        # Show auto-response dialog for HIGH
                        AutoResponseWindow(self, alert, responder)

                    else:
                        # Just show behavior alert window
                        BehaviorAlertWindow(self, alert)

                    # Task 1: Update signal aggregator and chart
                    if hasattr(self, "_signal_aggregator"):
                        signal_types = [alert.behavior_type.value]
                        score = self._signal_aggregator.compute_score(signal_types)
                        # Update stats
                        if hasattr(self, "_sig_stat_score"):
                            score_color = C["red"] if score >= 0.7 else C["green"]
                            self._sig_stat_score.configure(
                                text=f"{score:.2f}",
                                text_color=score_color
                            )
                        if hasattr(self, "_sig_stat_alerts"):
                            count = len(getattr(self, "_monitor", None).alerts) if hasattr(self, "_monitor") else 0
                            self._sig_stat_alerts.configure(text=str(count))

                elif mtype == "rules_update_result":
                    # Task 3: Handle rules update result
                    _, results = msg
                    self._rules_progress.set(1.0)
                    if results.get("failed", 0) > 0:
                        self._rules_status_lbl.configure(
                            text=f"● Update failed: {results['failed']}/{results['total_sources']}",
                            text_color=C["red"]
                        )
                    else:
                        self._rules_status_lbl.configure(
                            text=f"● Update complete: {results['successful']} rules updated",
                            text_color=C["green"]
                        )
                    self._load_rules_table()

                elif mtype == "net_connections":
                    # Task 6: Handle network connections update
                    _, connections = msg
                    self._populate_network_table(connections)

                elif mtype == "msgbox":
                    _, title, body = msg
                    messagebox.showinfo(title, body)

        except Exception:
            pass

        # Task 1: Update behavior chart every ~2 seconds
        self._chart_update_counter += 1
        if self._chart_update_counter >= 13:  # 13 * 150ms = ~2 seconds
            self._chart_update_counter = 0
            if hasattr(self, "_update_behavior_chart"):
                self._update_behavior_chart()

        # v2.5: Network auto-refresh (every 10 seconds = ~67 ticks)
        if self._net_auto_refresh:
            self._net_refresh_counter += 1
            if self._net_refresh_counter >= 67:  # ~10 seconds
                self._net_refresh_counter = 0
                self._refresh_network_connections()

        # v2.5: Update PM stats periodically
        if hasattr(self, "_pm_stats_lbl"):
            self._update_pm_stats()

        self.after(150, self._poll_ui_queue)

    def _add_tree_row(self, result: ScanResult):
        """Thêm một hàng vào bảng kết quả — v2 thêm FP columns."""
        risk = result.risk_level or "UNKNOWN"
        icon = {
            "CRITICAL": "🟥", "HIGH": "🔴", "MEDIUM": "🟡",
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
        """v2.5: Show detailed PE/YARA analysis on double-click."""
        selection = self._tree.selection()
        if not selection:
            return
        item = self._tree.item(selection[0])
        values = item["values"]
        if not values:
            return
        filename = values[1]
        for result in self._results:
            if result.filename == filename:
                if result.extension in {".exe", ".dll", ".sys"} or getattr(result, "yara_matches", []):
                    PEAnalysisWindow(self, result)
                else:
                    GenericFileInfoWindow(self, result)
                return


class GenericFileInfoWindow(ctk.CTkToplevel):
    """v2.5: Hiển thị chi tiết file thường (non-PE)."""

    def __init__(self, parent, result):
        super().__init__()
        self.title(f"File Info: {result.filename}")
        self.geometry("520x360")
        self.configure(fg_color=C["bg_dark"])
        self.resizable(False, False)

        hdr = ctk.CTkFrame(self, fg_color=C["bg_panel"], corner_radius=8)
        hdr.pack(fill="x", padx=12, pady=(12, 0))
        ctk.CTkLabel(
            hdr, text=f"FILE INFO: {result.filename}",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=C["accent"]
        ).pack(padx=12, pady=8)

        content = ctk.CTkFrame(self, fg_color=C["bg_dark"])
        content.pack(fill="both", expand=True, padx=12, pady=(8, 12))

        risk_color = RISK_COLORS.get(result.risk_level, C["text"])
        raw_proba = getattr(result, "raw_probability", result.probability)
        fp_adj = getattr(result, "fp_adjusted", False)
        yara_boosted = getattr(result, "yara_boosted", False)
        fp_reason = getattr(result, "fp_reason", "") or ""

        info_items = [
            ("Path", result.path),
            ("Size", f"{result.size/1024:.1f} KB" if result.size < 1024*1024 else f"{result.size/1024/1024:.1f} MB"),
            ("Extension", result.extension or "none"),
            ("Entropy", f"{result.entropy:.4f} bits/byte"),
            ("Risk Level", result.risk_level),
            ("Adjusted Prob", f"{result.probability*100:.1f}%"),
            ("Raw Prob", f"{raw_proba*100:.1f}%"),
            ("FP Adjusted", "Yes" if fp_adj else "No"),
            ("YARA Boosted", "Yes" if yara_boosted else "No"),
            ("Threshold", f"{getattr(result, 'effective_threshold', 0.65):.2f}"),
        ]

        for key, val in info_items:
            row = ctk.CTkFrame(content, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=2)
            ctk.CTkLabel(row, text=f"{key}:",
                         font=ctk.CTkFont(family="Consolas", size=9),
                         text_color=C["text_dim"], width=120, anchor="w").pack(side="left")
            val_color = risk_color if key == "Risk Level" else C["text"]
            ctk.CTkLabel(row, text=str(val),
                         font=ctk.CTkFont(family="Consolas", size=9,
                                          weight="bold" if key == "Risk Level" else "normal"),
                         text_color=val_color).pack(side="left")

        if fp_reason:
            reason_row = ctk.CTkFrame(content, fg_color="transparent")
            reason_row.pack(fill="x", padx=8, pady=(6, 0))
            ctk.CTkLabel(reason_row, text="Analysis:",
                         font=ctk.CTkFont(family="Consolas", size=9),
                         text_color=C["purple"], width=120, anchor="w").pack(side="left")
            ctk.CTkLabel(reason_row, text=fp_reason.strip(" |"),
                         font=ctk.CTkFont(family="Consolas", size=8),
                         text_color=C["text_dim"], wraplength=340).pack(side="left")

        ctk.CTkButton(
            self, text="CLOSE", command=self.destroy,
            fg_color=C["bg_card"], hover_color=C["border"],
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=C["text_dim"], height=32, corner_radius=6, width=120
        ).pack(pady=(8, 12))


class RansomwareDetectorApp(ctk.CTk):

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
        """Handle window close - minimize to tray if tray is active."""
        # Check if tray manager is active
        if hasattr(self, "_tray_manager") and self._tray_manager is not None:
            # Minimize to tray instead of closing
            self._tray_manager.minimize_to_tray()
            return

        if self._monitor.is_running:
            self._monitor.stop()
        if self._scanner.is_scanning:
            self._scanner.cancel()
        self.destroy()

    def restore_from_tray(self):
        """Task 4: Restore window from tray."""
        try:
            self.deiconify()
            self.lift()
            self.focus()
        except:
            pass

    def quit_app(self):
        """Task 4: Quit application completely."""
        if hasattr(self, "_tray_manager") and self._tray_manager:
            try:
                self._tray_manager.stop()
            except:
                pass
        if self._monitor.is_running:
            self._monitor.stop()
        if self._scanner.is_scanning:
            self._scanner.cancel()
        self.destroy()

    def _on_protection_toggled(self, enabled: bool):
        """Task 4: Handle protection toggle."""
        if enabled:
            self._watch_status_lbl.configure(text="● PROTECTION ON", text_color=C["green"])
        else:
            self._watch_status_lbl.configure(text="● PROTECTION OFF", text_color=C["text_dim"])

    def _update_pm_stats(self):
        """v2.5: Update process monitor stats label."""
        if not hasattr(self, "_monitor") or not self._monitor.is_running:
            return
        try:
            pm = self._monitor._process_monitor
            stats = pm.get_all_stats()
            total_events = stats.get("total_events", 0)
            total_alerts = stats.get("total_alerts", 0)
            unique_procs = stats.get("unique_processes", 0)
            by_type = stats.get("alerts_by_type", {})
            lines = [
                f"Events: {total_events}  |  Alerts: {total_alerts}",
                f"Unique PIDs: {unique_procs}",
            ]
            if by_type:
                for k, v in by_type.items():
                    if v > 0:
                        lines.append(f"  {k}: {v}")
            self._pm_stats_lbl.configure(text="\n".join(lines), text_color=C["cyan"])
        except Exception:
            pass

    def _open_config_manager(self):
        """v2.5: Open Config Manager window."""
        ConfigManagerWindow(self)


class ConfigManagerWindow(ctk.CTkToplevel):
    """v2.5: GUI panel for ConfigManager."""

    def __init__(self, parent):
        super().__init__(parent)
        self.title("Config Manager")
        self.geometry("560x580")
        self.configure(fg_color=C["bg_dark"])
        self.resizable(False, False)
        self.transient(parent)

        cfg = get_config()

        hdr = ctk.CTkFrame(self, fg_color=C["bg_panel"], corner_radius=8)
        hdr.pack(fill="x", padx=10, pady=(10, 0))
        ctk.CTkLabel(
            hdr, text="⚙  CONFIG MANAGER",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=C["accent"]
        ).pack(padx=12, pady=8)

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=10, pady=(8, 0))

        sections = [
            ("ML", cfg.get("ml")),
            ("Scanner", cfg.get("scanner")),
            ("Process Monitor", cfg.get("process_monitor")),
            ("Watchdog", cfg.get("watchdog")),
            ("FP Reducer", cfg.get("fp_reducer")),
            ("Notifications", cfg.get("notifications")),
            ("Auto Response", cfg.get("auto_response")),
            ("Network Monitor", cfg.get("network_monitor")),
        ]

        for section, data in sections:
            sec_frame = ctk.CTkFrame(scroll, fg_color=C["bg_card"], corner_radius=6)
            sec_frame.pack(fill="x", pady=(0, 8))
            ctk.CTkLabel(
                sec_frame, text=f"◈ {section.upper()}",
                font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                text_color=C["green"]
            ).pack(anchor="w", padx=8, pady=(6, 2))

            if isinstance(data, dict):
                for key, val in list(data.items())[:8]:
                    if isinstance(val, (str, int, float, bool)):
                        row = ctk.CTkFrame(sec_frame, fg_color="transparent")
                        row.pack(fill="x", padx=8, pady=1)
                        ctk.CTkLabel(
                            row, text=f"  {key}:",
                            font=ctk.CTkFont(family="Consolas", size=8),
                            text_color=C["text_dim"], width=140, anchor="w"
                        ).pack(side="left")
                        ctk.CTkLabel(
                            row, text=str(val),
                            font=ctk.CTkFont(family="Consolas", size=8),
                            text_color=C["cyan"]
                        ).pack(side="left")
                    elif isinstance(val, dict):
                        for sub_k, sub_v in list(val.items())[:5]:
                            row = ctk.CTkFrame(sec_frame, fg_color="transparent")
                            row.pack(fill="x", padx=8, pady=1)
                            ctk.CTkLabel(
                                row, text=f"    {sub_k}:",
                                font=ctk.CTkFont(family="Consolas", size=7),
                                text_color=C["text_dim"], width=140, anchor="w"
                            ).pack(side="left")
                            ctk.CTkLabel(
                                row, text=str(sub_v),
                                font=ctk.CTkFont(family="Consolas", size=7),
                                text_color=C["text"]
                            ).pack(side="left")

            ctk.CTkFrame(sec_frame, height=1, fg_color=C["border"]).pack(fill="x", padx=8, pady=(2, 4))

        # Buttons
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=8)
        btn_row.columnconfigure((0, 1), weight=1)

        ctk.CTkButton(
            btn_row, text="↺ Reset to Defaults",
            font=ctk.CTkFont(family="Consolas", size=9),
            fg_color=C["bg_card"], hover_color=C["border"],
            text_color=C["text_dim"], height=32, corner_radius=6,
            command=lambda: (cfg.reset_to_defaults(), self._reload())
        ).grid(row=0, column=0, padx=(0, 4), sticky="ew")

        ctk.CTkButton(
            btn_row, text="SAVE & CLOSE",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            fg_color=C["accent"], hover_color=C["accent_h"],
            text_color="#FFF", height=32, corner_radius=6,
            command=self.destroy
        ).grid(row=0, column=1, padx=(4, 0), sticky="ew")

    def _reload(self):
        self.destroy()
        ConfigManagerWindow(self.master)


def launch():
    app = RansomwareDetectorApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
