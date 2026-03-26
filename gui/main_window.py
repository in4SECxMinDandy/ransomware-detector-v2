"""
main_window.py — Ransomware Detector v2 GUI
==========================================
CustomTkinter-based main window with:
  - Real-time monitoring dashboard
  - Full/Quick/Incremental scan engine
  - Alert & Behavior log viewer
  - Settings (threshold, sensitivity, whitelist)
  - Quarantine management
  - Report export (CSV, PNG, Forensic bundle)
  - System tray integration
  - Matplotlib live charts

Architecture:
  - CTk window with custom dark cybersecurity theme
  - All core modules (scanner, monitor, responder) live in background threads
  - GUI updates via after() polls or direct callbacks — never blocks the event loop
"""

from __future__ import annotations

import os
import sys
import time
import threading
import webbrowser
from datetime import datetime
from typing import Optional, List, Any, Dict, Callable

import customtkinter as ctk
from tkinter import filedialog, messagebox

# ─── Core imports ────────────────────────────────────────────────────────────
from core.config_manager import config, ConfigManager
from core.scanner import Scanner, ScanResult, SENSITIVITY_PROFILES
from core.watchdog_monitor import RealTimeMonitor, ThreatEvent
from core.process_monitor import BehaviorAlert, BehaviorType, ProcessInfo
from core.ml_engine import get_engine, CalibratedMalwareDetector
from core.auto_responder import get_auto_responder
from core.notifications import get_notifier, NotificationManager, Notification
from core.report_generator import export_csv, export_report_png
from core.forensic_exporter import export_forensic_bundle
from core.network_monitor import NetworkAnalyzer
from core.logger_setup import get_logger, setup_logging

# ─── GUI module imports ────────────────────────────────────────────────────
from gui.tray_manager import TrayManager
from gui.whitelist_editor import WhitelistEditorWindow
from gui.tab_office_scanner import OfficeScannerTab
from gui.tab_entropy_watch import EntropyWatchTab
from gui.tab_honeypot import HoneypotTab
from gui.tab_ml_training import MLTrainingTab

setup_logging()
logger = get_logger("gui.main_window")

# ─── Matplotlib ────────────────────────────────────────────────────────────
import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# ════════════════════════════════════════════════════════════════════════════
# COLOR PALETTE
# ════════════════════════════════════════════════════════════════════════════

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
    "cyan":     "#22D3EE",
    "accent":   "#3B82F6",
    "accent_h": "#2563EB",
    "danger":   "#B91C1C",
    "purple":   "#A78BFA",
}

RISK_COLORS = {
    "CRITICAL": C["red"],
    "HIGH":     C["orange"],
    "MEDIUM":   C["yellow"],
    "LOW":      C["blue"],
    "SAFE":     C["green"],
    "UNKNOWN":  C["text_dim"],
}


# ════════════════════════════════════════════════════════════════════════════
# PLOT WIDGET — embeds a Matplotlib Figure in a CTk frame
# ════════════════════════════════════════════════════════════════════════════

class PlotFrame(ctk.CTkFrame):
    """Lightweight Matplotlib container for CTk."""

    def __init__(self, parent, figsize=(5, 2.5), **kwargs):
        super().__init__(parent, **kwargs)
        self.figure = Figure(figsize=figsize, facecolor=C["bg_card"])
        self.canvas = FigureCanvasTkAgg(self.figure, master=self)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self._ax = self.figure.add_subplot(111)
        self._configure_axes()

    def _configure_axes(self):
        self._ax.set_facecolor(C["bg_card"])
        self._ax.tick_params(colors=C["text_dim"])
        self._ax.xaxis.label.set_color(C["text_dim"])
        self._ax.yaxis.label.set_color(C["text_dim"])
        for spine in self._ax.spines.values():
            spine.set_edgecolor(C["border"])
        self.figure.patch.set_facecolor(C["bg_card"])

    def clear(self):
        self._ax.clear()
        self._configure_axes()

    def plot(self, x, y, color=C["accent"], label="", linewidth=1.5):
        self._ax.plot(x, y, color=color, linewidth=linewidth, label=label)
        if label:
            self._ax.legend(facecolor=C["bg_card"], labelcolor=C["text"],
                            edgecolor=C["border"], fontsize=7)
        self._ax.tick_params(axis="both", labelsize=7)
        self._configure_axes()
        # Note: draw_idle() is called by caller to avoid blocking GUI

    def bar(self, categories, values, colors=None, ylabel=""):
        self._ax.clear()
        self._ax.set_facecolor(C["bg_card"])
        bar_colors = colors or [C["accent"]] * len(values)
        self._ax.bar(categories, values, color=bar_colors,
                     edgecolor=C["bg_card"], linewidth=0.5)
        self._ax.set_ylabel(ylabel, color=C["text_dim"], fontsize=7)
        self._ax.tick_params(axis="both", labelsize=7, colors=C["text_dim"])
        for spine in self._ax.spines.values():
            spine.set_edgecolor(C["border"])
        self.canvas.draw_idle()

    def pie(self, sizes, labels, colors, title=""):
        self._ax.clear()
        self._ax.set_facecolor(C["bg_card"])
        if sizes:
            wedges, _, autotexts = self._ax.pie(
                sizes, labels=None, colors=colors,
                autopct=lambda p: f"{p:.0f}%",
                startangle=90,
                wedgeprops={"linewidth": 1, "edgecolor": C["bg_dark"]},
            )
            for at in autotexts:
                at.set_fontsize(7)
                at.set_color(C["bg_dark"])
                at.set_fontweight("bold")
            self._ax.legend(labels, loc="lower center", ncol=min(3, len(labels)),
                            bbox_to_anchor=(0.5, -0.22), fontsize=6,
                            frameon=False, labelcolor=C["text"])
        if title:
            self._ax.set_title(title, color=C["accent"], fontsize=8, pad=4)
        self.figure.patch.set_facecolor(C["bg_card"])
        self.canvas.draw_idle()

    def scatter_entropy(self, entropies, probabilities, risk_levels):
        self._ax.clear()
        self._ax.set_facecolor(C["bg_card"])
        scatter_colors = [RISK_COLORS.get(r, C["text_dim"]) for r in risk_levels]
        self._ax.scatter(entropies, probabilities, c=scatter_colors,
                         alpha=0.6, s=10, linewidths=0)
        self._ax.axhline(y=config.get("ml.default_threshold", 0.65),
                         color=C["orange"], linestyle="--", linewidth=0.8, alpha=0.7)
        self._ax.axvline(x=7.2, color=C["yellow"], linestyle="--", linewidth=0.8, alpha=0.7)
        self._ax.set_xlabel("Entropy (b/B)", color=C["text_dim"], fontsize=7)
        self._ax.set_ylabel("Risk Prob", color=C["text_dim"], fontsize=7)
        self._ax.tick_params(axis="both", labelsize=7, colors=C["text_dim"])
        for spine in self._ax.spines.values():
            spine.set_edgecolor(C["border"])
        self.canvas.draw_idle()

    def signal_gauge(self, score, label="Threat Score"):
        self._ax.clear()
        self._ax.set_facecolor(C["bg_card"])
        self._ax.set_xlim(0, 1)
        self._ax.set_ylim(0, 1)
        self._ax.axis("off")

        # Draw arc background
        theta = np.linspace(0, np.pi, 100)
        x_bg = 0.5 + 0.4 * np.cos(theta)
        y_bg = 0.2 + 0.15 * np.sin(theta)
        self._ax.plot(x_bg, y_bg, color=C["border"], linewidth=8, solid_capstyle="butt")

        # Draw arc fill
        fill_angle = theta[min(int(score * len(theta)), len(theta) - 1)]
        x_fill = 0.5 + 0.4 * np.cos(theta[:len(theta) // 2 + int(score * (len(theta) // 2))])
        y_fill = 0.2 + 0.15 * np.sin(theta[:len(theta) // 2 + int(score * (len(theta) // 2))])
        fill_color = C["red"] if score > 0.7 else C["orange"] if score > 0.4 else C["green"]
        self._ax.plot(x_fill, y_fill, color=fill_color, linewidth=8, solid_capstyle="butt")

        # Text
        self._ax.text(0.5, 0.55, f"{score:.0%}", ha="center", va="center",
                      fontsize=18, fontweight="bold", color=fill_color)
        self._ax.text(0.5, 0.38, label, ha="center", va="center",
                      fontsize=7, color=C["text_dim"])

        self.figure.patch.set_facecolor(C["bg_card"])
        self.canvas.draw_idle()


# ════════════════════════════════════════════════════════════════════════════
# CUSTOM WIDGETS
# ════════════════════════════════════════════════════════════════════════════

class AnimatedToggle(ctk.CTkFrame):
    """Toggle switch with animated indicator."""

    def __init__(self, parent, text="", width=44, height=24, command=None):
        super().__init__(parent, width=width, height=height, fg_color=C["bg_panel"])
        self._command = command
        self._on = False
        self._width = width
        self._height = height

        self._canvas = ctk.CTkCanvas(
            self, width=width, height=height,
            bg=self.cget("fg_color"), highlightthickness=0, bd=0
        )
        self._canvas.pack()

        self._track = self._canvas.create_oval(
            2, 2, height - 2, height - 2,
            fill=C["border"], outline=""
        )
        self._thumb = self._canvas.create_oval(
            4, 4, height - 4, height - 4,
            fill=C["text_dim"], outline=""
        )
        self._label = ctk.CTkLabel(self, text=text, font=("Consolas", 10),
                                    text_color=C["text_dim"])

        self._canvas.bind("<Button-1>", self._toggle)
        self._canvas.bind("<Enter>", self._on_hover)
        self._canvas.bind("<Leave>", self._off_hover)

    def _toggle(self, event=None):
        self._on = not self._on
        self._refresh()
        if self._command:
            self._command(self._on)

    def _on_hover(self, event):
        if not self._on:
            self._canvas.itemconfigure(self._track, fill=C["accent"])

    def _off_hover(self, event):
        if not self._on:
            self._canvas.itemconfigure(self._track, fill=C["border"])

    def _refresh(self):
        h = self._height
        if self._on:
            self._canvas.coords(self._thumb, h // 2, 4, h - 4, h - 4)
            self._canvas.itemconfigure(self._track, fill=C["green"])
            self._canvas.itemconfigure(self._thumb, fill="#FFFFFF")
            self._label.configure(text_color=C["green"])
        else:
            self._canvas.coords(self._thumb, 4, 4, h - 4, h - 4)
            self._canvas.itemconfigure(self._track, fill=C["border"])
            self._canvas.itemconfigure(self._thumb, fill=C["text_dim"])
            self._label.configure(text_color=C["text_dim"])

    def pack(self, **kwargs):
        self._label.pack(side="right", padx=(4, 0))
        self._canvas.pack(side="left")
        super().pack(**kwargs)

    @property
    def on(self):
        return self._on

    @on.setter
    def on(self, value: bool):
        self._on = value
        self._refresh()


class StatusBadge(ctk.CTkFrame):
    """Pill-shaped status badge."""

    def __init__(self, parent, text="SAFE", color=C["green"], **kwargs):
        super().__init__(parent, **kwargs)
        self._label = ctk.CTkLabel(
            self, text=text,
            font=("Consolas", 9, "bold"),
            text_color=C["bg_dark"],
        )
        self._label.pack(padx=8, pady=2)
        self.configure(fg_color=color, corner_radius=10)

    def configure(self, text="", color=None, **kwargs):
        if text:
            self._label.configure(text=text)
        if color:
            super().configure(fg_color=color)
        super().configure(**kwargs)


class ScanProgressBar(ctk.CTkFrame):
    """Progress bar with file count and ETA."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.configure(fg_color=C["bg_card"], corner_radius=6)

        self._var = ctk.StringVar(value="0 / 0")
        self._pct_var = ctk.StringVar(value="0%")
        self._eta_var = ctk.StringVar(value="")

        self._bar = ctk.CTkProgressBar(self, height=8, progress_color=C["accent"],
                                        fg_color=C["border"])
        self._bar.set(0)
        self._bar.pack(fill="x", padx=8, pady=(8, 0))

        info_frame = ctk.CTkFrame(self, fg_color="transparent")
        info_frame.pack(fill="x", padx=8, pady=(2, 8))

        ctk.CTkLabel(info_frame, textvariable=self._var,
                     font=("Consolas", 9), text_color=C["text_dim"]
                     ).pack(side="left")

        ctk.CTkLabel(info_frame, textvariable=self._pct_var,
                     font=("Consolas", 9, "bold"), text_color=C["accent"]
                     ).pack(side="left", padx=8)

        ctk.CTkLabel(info_frame, textvariable=self._eta_var,
                     font=("Consolas", 8), text_color=C["text_dim"]
                     ).pack(side="right")

    def set_progress(self, current: int, total: int, elapsed: float = 0):
        pct = current / max(total, 1)
        self._bar.set(pct)
        self._var.set(f"{current} / {total}")
        self._pct_var.set(f"{pct * 100:.0f}%")
        if elapsed > 0 and current > 0:
            rate = current / elapsed
            remaining = total - current
            eta = remaining / rate if rate > 0 else 0
            self._eta_var.set(f"ETA: {eta:.0f}s")
        else:
            self._eta_var.set("")

    def reset(self):
        self._bar.set(0)
        self._var.set("0 / 0")
        self._pct_var.set("0%")
        self._eta_var.set("")


# ════════════════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ════════════════════════════════════════════════════════════════════════════

class MainWindow(ctk.CTk):
    """
    Ransomware Detector v2 — Main Application Window.

    Sections:
      0 | Dashboard   — real-time stats, charts, quick actions
      1 | Scan        — full/quick/incremental scan engine
      2 | Alerts      — threat events & behavior alerts
      3 | Settings    — threshold, sensitivity, whitelist, auto-response
      4 | Quarantine  — quarantined files management
      5 | Reports     — export CSV/PNG/forensic bundle
      6 | Logs        — in-app log viewer
    """

    # ─── Constants ─────────────────────────────────────────────────────────

    REFRESH_MS      = 1000
    LOG_MAX_LINES   = 500
    CHART_SECONDS   = 60   # rolling window for live charts
    CHART_BUCKETS   = 30   # data points in rolling window

    # ─── Lifecycle ─────────────────────────────────────────────────────────

    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("Ransomware Detector v2 — Premium")
        self.geometry("1280x760")
        self.minsize(1000, 640)
        self.configure(fg_color=C["bg_dark"])

        # ── Core components ───────────────────────────────────────────────
        self._scanner    = Scanner()
        self._monitor    = RealTimeMonitor()
        self._responder  = get_auto_responder()
        self._notifier   = get_notifier()
        self._engine     = get_engine()
        self._network    = NetworkAnalyzer()

        # ── New modules ────────────────────────────────────────────────
        try:
            from core.honeypot_manager import HoneypotManager
            self._honeypot_manager = HoneypotManager(
                watchdog_callback=None, config={}
            )
        except Exception:
            self._honeypot_manager = None

        try:
            from core.virustotal_client import VirusTotalClient
            vt_key = config.get("virustotal.api_key", "")
            self._vt_client = VirusTotalClient(vt_key) if vt_key else None
        except Exception:
            self._vt_client = None

        # ── UI state ────────────────────────────────────────────────────
        self._current_page    = 0
        self._scan_start_time: Optional[float] = None
        self._scan_cancel_flag = False
        self._protection_on   = True

        # Chart rolling data
        self._entropy_history: List[float] = []
        self._time_history: List[float] = []
        self._io_history: List[float] = []
        self._io_time: List[float] = []
        self._alert_timestamps: List[float] = []
        self._scan_entropy_data: List[float] = []
        self._scan_prob_data: List[float] = []
        self._scan_risk_data: List[str] = []

        # Alert & log storage
        self._threat_events: List[ThreatEvent] = []
        self._behavior_alerts: List[BehaviorAlert] = []
        self._log_lines: List[str] = []

        # Page containers
        self._pages: List[ctk.CTkFrame] = []

        # ── DPI scaling ──────────────────────────────────────────────────
        self._check_dpi_scaling()

        # ── Build UI ─────────────────────────────────────────────────────
        self._build_ui()
        self._bind_events()
        self._load_engine()
        self._start_polling()
        self._wire_new_modules()

        # ── Protocol ─────────────────────────────────────────────────────
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    # ─── DPI ────────────────────────────────────────────────────────────────

    def _check_dpi_scaling(self):
        try:
            import ctypes
            user32 = ctypes.windll.user32
            user32.SetProcessDPIAware()
            dpi = user32.GetDpiForSystem()
            scale = dpi / 96.0
            if scale != 1.0:
                ctk.CTkLabel(self, text=f"  DPI Scale: {scale:.2f}x  ",
                              text_color=C["text_dim"]).place(relx=0.99, rely=0.01, anchor="ne")
        except Exception:
            pass

    # ─── Event Bindings ────────────────────────────────────────────────────

    def _bind_events(self):
        # Monitor callbacks
        self._monitor.on_threat    = self._on_threat
        self._monitor.on_analyzed  = self._on_file_analyzed
        self._monitor.on_behavior  = self._on_behavior_alert

        # Scanner callbacks (set dynamically per scan)
        self._scanner._on_progress: Optional[Callable] = None
        self._scanner._on_complete: Optional[Callable] = None

    # ─── Engine Loading ─────────────────────────────────────────────────────

    def _load_engine(self):
        def _load():
            loaded = self._engine.load_model()
            self.after(0, lambda: self._engine_loaded_callback(loaded))

        threading.Thread(target=_load, daemon=True).start()

    def _engine_loaded_callback(self, loaded: bool):
        if loaded:
            info = self._engine.get_model_info()
            thresh = info.get("current_threshold", 0.65)
            self._set_status(f"ML Engine loaded — threshold={thresh:.2f}", C["green"])
            self._log("success", f"Model ready (acc={info.get('accuracy', 0)*100:.1f}%)")
            # Update threshold slider
            if hasattr(self, "_thresh_slider"):
                self._thresh_slider.set(thresh)
        else:
            self._set_status("ML Engine not loaded — train model first", C["orange"])
            self._log("warning", "No trained model found — run in terminal: python -m core.ml_engine")

    # ─── Polling ───────────────────────────────────────────────────────────

    def _start_polling(self):
        self._poll_id = self.after(self.REFRESH_MS, self._poll)

    def _poll(self):
        """Called every REFRESH_MS ms to update live widgets."""
        try:
            if self._monitor.is_running:
                self._update_monitor_stats()
                self._update_live_chart()
            self._update_time_display()
        except Exception:
            pass
        self._poll_id = self.after(self.REFRESH_MS, self._poll)

    def _update_time_display(self):
        if hasattr(self, "_time_lbl") and self._monitor.is_running:
            elapsed = time.time() - getattr(self, "_monitor_start_time", time.time())
            m, s = divmod(int(elapsed), 60)
            self._time_lbl.configure(text=f"{m:02d}:{s:02d}")

    def _update_monitor_stats(self):
        stats = self._monitor.get_stats()
        if hasattr(self, "_files_analyzed_lbl"):
            self._files_analyzed_lbl.configure(
                text=str(stats.get("total_analyzed", 0))
            )
        if hasattr(self, "_threats_lbl"):
            self._threats_lbl.configure(
                text=str(stats.get("total_threats", 0))
            )

    def _update_live_chart(self):
        """Append new data point to rolling live chart."""
        if not hasattr(self, "_live_plot") or not hasattr(self, "_entropy_history"):
            return
        now = time.time()

        # Record signal score
        sig_stats = self._monitor.get_signal_stats()
        pm_sig = sig_stats.get("signal_aggregator", {})
        score = pm_sig.get("avg_score", 0.0)

        self._entropy_history.append(score)
        self._time_history.append(now)

        # Keep CHART_BUCKETS points
        if len(self._entropy_history) > self.CHART_BUCKETS:
            self._entropy_history = self._entropy_history[-self.CHART_BUCKETS:]
            self._time_history = self._time_history[-self.CHART_BUCKETS:]

        if len(self._entropy_history) >= 2:
            t0 = self._time_history[0]
            x = [t - t0 for t in self._time_history]
            color = C["red"] if self._entropy_history[-1] > 0.7 else C["orange"] if self._entropy_history[-1] > 0.4 else C["green"]
            # Update line in-place: no clear() → no full redraw
            self._live_plot._ax.clear()
            self._live_plot._configure_axes()
            self._live_plot._ax.plot(x, self._entropy_history, color=color, linewidth=2)
            self._live_plot._ax.set_ylim(0, 1)
            self._live_plot._ax.set_ylabel("Threat Score", color=C["text_dim"], fontsize=7)
            self._live_plot._ax.set_xlabel("Time (s)", color=C["text_dim"], fontsize=7)
            self._live_plot.canvas.draw_idle()

    # ═══════════════════════════════════════════════════════════════════════
    # UI BUILD
    # ═══════════════════════════════════════════════════════════════════════

    def _build_ui(self):
        # ── Header ───────────────────────────────────────────────────────
        self._build_header()

        # ── Body: sidebar + content ──────────────────────────────────────
        body = ctk.CTkFrame(self, fg_color=C["bg_dark"])
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self._build_sidebar(body)
        self._build_page_container(body)

        # ── Initial page ─────────────────────────────────────────────────
        self._show_page(0)

    # ─── Header ─────────────────────────────────────────────────────────────

    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=C["bg_panel"], height=52)
        hdr.pack(fill="x", padx=0, pady=0)
        hdr.pack_propagate(False)

        # Logo / title
        title = ctk.CTkLabel(
            hdr, text="⛨  RANSOMWARE DETECTOR  v2",
            font=("Consolas", 14, "bold"),
            text_color=C["accent"]
        )
        title.pack(side="left", padx=(12, 4), pady=8)

        subtitle = ctk.CTkLabel(
            hdr, text="ML-Powered Real-Time Protection",
            font=("Consolas", 8),
            text_color=C["text_dim"]
        )
        subtitle.pack(side="left", padx=(0, 12), pady=8)

        # Status bar in header
        sep = ctk.CTkFrame(hdr, width=1, fg_color=C["border"])
        sep.pack(side="left", fill="y", padx=8, pady=8)

        # Uptime
        self._time_lbl = ctk.CTkLabel(
            hdr, text="00:00",
            font=("Consolas", 9),
            text_color=C["text_dim"]
        )
        self._time_lbl.pack(side="left", padx=4, pady=8)

        sep2 = ctk.CTkFrame(hdr, width=1, fg_color=C["border"])
        sep2.pack(side="left", fill="y", padx=8, pady=8)

        # Files / Threats
        ctk.CTkLabel(hdr, text="Files:",
                     font=("Consolas", 8), text_color=C["text_dim"]
                     ).pack(side="left", padx=(0, 2), pady=8)
        self._files_analyzed_lbl = ctk.CTkLabel(
            hdr, text="0",
            font=("Consolas", 9, "bold"), text_color=C["blue"]
        )
        self._files_analyzed_lbl.pack(side="left", padx=(0, 8), pady=8)

        ctk.CTkLabel(hdr, text="Threats:",
                     font=("Consolas", 8), text_color=C["text_dim"]
                     ).pack(side="left", padx=(0, 2), pady=8)
        self._threats_lbl = ctk.CTkLabel(
            hdr, text="0",
            font=("Consolas", 9, "bold"), text_color=C["red"]
        )
        self._threats_lbl.pack(side="left", padx=(0, 8), pady=8)

        # Status badge
        self._status_badge = StatusBadge(hdr, text="READY", color=C["green"])
        self._status_badge.pack(side="left", padx=8, pady=8)

        # Status var
        self._status_var = ctk.StringVar(value="Ready")
        self._status_lbl = ctk.CTkLabel(
            hdr, textvariable=self._status_var,
            font=("Consolas", 8), text_color=C["text_dim"]
        )
        self._status_lbl.pack(side="left", padx=4, pady=8)

        # Spacer
        ctk.CTkLabel(hdr, text="").pack(side="left", expand=True)

        # Protection toggle
        ctk.CTkLabel(hdr, text="Protection:",
                     font=("Consolas", 9), text_color=C["text_dim"]
                     ).pack(side="right", padx=(0, 4), pady=8)
        self._protection_toggle = AnimatedToggle(
            hdr, text="", width=44, height=24,
            command=self._on_protection_toggle
        )
        self._protection_toggle.on = True
        self._protection_toggle.pack(side="right", padx=(0, 12), pady=8)

        # Minimize to tray button
        ctk.CTkButton(
            hdr, text="▽", width=32, height=32,
            fg_color="transparent", hover_color=C["bg_card"],
            text_color=C["text_dim"], font=("Consolas", 14),
            command=self._minimize_to_tray
        ).pack(side="right", padx=(0, 4), pady=6)

    def _build_sidebar(self, parent):
        sidebar = ctk.CTkFrame(parent, width=180, fg_color=C["bg_panel"], corner_radius=0)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        nav_items = [
            ("⛨",  "Dashboard",      self._show_dashboard),
            ("◈",  "Scan",           self._show_scan),
            ("⚠",  "Alerts",         self._show_alerts),
            ("⚙",  "Settings",       self._show_settings),
            ("◻",  "Quarantine",     self._show_quarantine),
            ("⎙",  "Reports",        self._show_reports),
            ("☰",  "Logs",           self._show_logs),
            ("📄", "Office Scanner",  self._show_office_scanner),
            ("📊", "Entropy Watch",   self._show_entropy_watch),
            ("🎣", "Honeypot",       self._show_honeypot),
            ("🤖", "ML Training",    self._show_ml_training),
        ]

        self._nav_buttons: List[ctk.CTkButton] = []

        for icon, label, cmd in nav_items:
            btn = ctk.CTkButton(
                sidebar, text=f"  {icon}  {label}",
                font=("Consolas", 10),
                fg_color="transparent", hover_color=C["bg_card"],
                text_color=C["text_dim"], anchor="w", height=38,
                command=cmd
            )
            btn.pack(fill="x", padx=8, pady=2)
            self._nav_buttons.append(btn)

        # Separator
        ctk.CTkFrame(sidebar, height=1, fg_color=C["border"]).pack(
            fill="x", padx=8, pady=8
        )

        # Monitor control
        self._monitor_btn = ctk.CTkButton(
            sidebar, text="  ▶  Start Monitor",
            font=("Consolas", 10, "bold"),
            fg_color=C["green"], hover_color="#1EA34A",
            text_color=C["bg_dark"], anchor="center", height=40,
            command=self._toggle_monitor
        )
        self._monitor_btn.pack(fill="x", padx=8, pady=4)

        # Monitor path
        default_path = os.path.expanduser("~")
        ctk.CTkLabel(
            sidebar, text="Monitor path:",
            font=("Consolas", 7), text_color=C["text_dim"]
        ).pack(anchor="w", padx=12, pady=(8, 0))
        self._monitor_path_var = ctk.StringVar(value=default_path)
        self._monitor_path_entry = ctk.CTkEntry(
            sidebar, textvariable=self._monitor_path_var,
            font=("Consolas", 8), fg_color=C["bg_card"],
            border_color=C["border"], text_color=C["text"],
            height=28
        )
        self._monitor_path_entry.pack(fill="x", padx=8, pady=(2, 0))

        ctk.CTkButton(
            sidebar, text="Browse...", height=24,
            font=("Consolas", 8),
            fg_color=C["bg_card"], hover_color=C["border"],
            text_color=C["text_dim"],
            command=self._browse_monitor_path
        ).pack(fill="x", padx=8, pady=(2, 8))

        # Version at bottom
        ctk.CTkLabel(
            sidebar, text="v2.3  |  2026",
            font=("Consolas", 7), text_color=C["text_dim"]
        ).pack(side="bottom", pady=8)

    def _build_page_container(self, parent):
        self._page_container = ctk.CTkFrame(parent, fg_color=C["bg_dark"])
        self._page_container.pack(side="left", fill="both", expand=True, padx=(0, 0))
        self._page_container.grid_columnconfigure(0, weight=1)
        self._page_container.grid_rowconfigure(0, weight=1)

        # Build all pages
        self._build_dashboard()
        self._build_scan_page()
        self._build_alerts_page()
        self._build_settings_page()
        self._build_quarantine_page()
        self._build_reports_page()
        self._build_logs_page()
        self._build_office_scanner_page()
        self._build_entropy_watch_page()
        self._build_honeypot_page()
        self._build_ml_training_page()

    # ─── Page: Dashboard ────────────────────────────────────────────────────

    def _build_dashboard(self):
        page = ctk.CTkScrollableFrame(
            self._page_container, fg_color=C["bg_dark"], scrollbar_button_color=C["border"],
            scrollbar_button_hover_color=C["accent"]
        )
        page.grid(row=0, column=0, sticky="nsew")
        self._pages.append(page)

        # ── Row 1: Stat cards ──────────────────────────────────────────
        card_row = ctk.CTkFrame(page, fg_color="transparent")
        card_row.pack(fill="x", padx=4, pady=(8, 4))
        card_row.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        cards = [
            ("⛨", "Status", "PROTECTED", C["green"]),
            ("◈", "Files Scanned", "0", C["blue"]),
            ("⚠", "Threats Detected", "0", C["red"]),
            ("⏱", "Uptime", "00:00:00", C["accent"]),
            ("📊", "Threat Score", "0%", C["text_dim"]),
        ]

        self._card_labels: List[ctk.CTkLabel] = []
        for col, (icon, title, value, color) in enumerate(cards):
            card = ctk.CTkFrame(card_row, fg_color=C["bg_card"], corner_radius=8)
            card.grid(row=0, column=col, padx=4, pady=4, sticky="nsew")

            ctk.CTkLabel(card, text=icon, font=("Consolas", 16),
                         text_color=color).pack(pady=(12, 0))
            ctk.CTkLabel(card, text=title, font=("Consolas", 8),
                         text_color=C["text_dim"]).pack()
            lbl = ctk.CTkLabel(card, text=value, font=("Consolas", 16, "bold"),
                                text_color=color)
            lbl.pack(pady=(0, 12))
            self._card_labels.append(lbl)

        # ── Row 2: Charts ──────────────────────────────────────────────
        chart_row = ctk.CTkFrame(page, fg_color="transparent")
        chart_row.pack(fill="both", expand=True, padx=4, pady=4)
        chart_row.grid_columnconfigure((0, 1), weight=1)
        chart_row.grid_rowconfigure(0, weight=1)

        # Left: threat score gauge
        left_card = ctk.CTkFrame(chart_row, fg_color=C["bg_card"], corner_radius=8)
        left_card.grid(row=0, column=0, padx=(0, 4), pady=0, sticky="nsew")
        ctk.CTkLabel(left_card, text="THREAT SCORE", font=("Consolas", 10, "bold"),
                     text_color=C["accent"]).pack(pady=(10, 4))
        self._gauge_plot = PlotFrame(left_card, figsize=(4.5, 2.8))
        self._gauge_plot.signal_gauge(0.0, "System Threat Level")
        self._gauge_plot.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Right: live chart
        right_card = ctk.CTkFrame(chart_row, fg_color=C["bg_card"], corner_radius=8)
        right_card.grid(row=0, column=1, padx=(4, 0), pady=0, sticky="nsew")
        ctk.CTkLabel(right_card, text="LIVE THREAT MONITOR", font=("Consolas", 10, "bold"),
                     text_color=C["accent"]).pack(pady=(10, 4))
        self._live_plot = PlotFrame(right_card, figsize=(4.5, 2.8))
        self._live_plot.clear()
        self._live_plot._ax.text(0.5, 0.5, "Start monitor to see live data",
                                  ha="center", va="center",
                                  color=C["text_dim"], fontsize=9,
                                  transform=self._live_plot._ax.transAxes)
        self._live_plot.canvas.draw_idle()
        self._live_plot.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # ── Row 3: Quick Actions ───────────────────────────────────────
        action_row = ctk.CTkFrame(page, fg_color="transparent")
        action_row.pack(fill="x", padx=4, pady=4)

        quick_actions = [
            ("Quick Scan",  "▶",  self._quick_scan),
            ("Full Scan",  "◈",  self._full_scan),
            ("Stop Scan",  "■",  self._cancel_scan),
            ("View Alerts","⚠",  self._show_alerts),
            ("Export",     "⎙",  self._show_reports),
        ]

        for label, icon, cmd in quick_actions:
            btn = ctk.CTkButton(
                action_row, text=f"{icon}  {label}",
                font=("Consolas", 10, "bold"),
                fg_color=C["bg_card"], hover_color=C["accent"],
                text_color=C["text"], height=44,
                command=cmd
            )
            btn.pack(side="left", padx=4, pady=4, fill="x", expand=True)

        # ── Row 4: Process Monitor Summary ────────────────────────────
        pm_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        pm_card.pack(fill="x", padx=4, pady=4)

        ctk.CTkLabel(pm_card, text="PROCESS BEHAVIOR MONITOR",
                     font=("Consolas", 10, "bold"), text_color=C["accent"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        pm_sub = ctk.CTkFrame(pm_card, fg_color="transparent")
        pm_sub.pack(fill="x", padx=12, pady=(0, 10))
        pm_sub.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._pm_labels: Dict[str, ctk.CTkLabel] = {}
        pm_items = [
            ("Total Events", "0", C["text_dim"]),
            ("Encryption Bursts", "0", C["orange"]),
            ("IO Anomalies", "0", C["red"]),
            ("Signal Score", "0%", C["blue"]),
        ]
        for col, (title, val, color) in enumerate(pm_items):
            item = ctk.CTkFrame(pm_sub, fg_color=C["bg_dark"], corner_radius=6)
            item.grid(row=0, column=col, padx=4, pady=4)
            ctk.CTkLabel(item, text=title, font=("Consolas", 7),
                         text_color=C["text_dim"]).pack(pady=(6, 0))
            lbl = ctk.CTkLabel(item, text=val, font=("Consolas", 14, "bold"),
                               text_color=color)
            lbl.pack(pady=(0, 6))
            key = title.lower().replace(" ", "_")
            self._pm_labels[key] = lbl

        # ── Row 5: Recent Alerts Preview ───────────────────────────────
        alert_preview = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        alert_preview.pack(fill="x", padx=4, pady=4)

        ctk.CTkLabel(alert_preview, text="RECENT ALERTS",
                     font=("Consolas", 10, "bold"), text_color=C["accent"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        self._recent_alerts_list = ctk.CTkScrollableFrame(
            alert_preview, height=120, fg_color="transparent",
            scrollbar_button_color=C["border"]
        )
        self._recent_alerts_list.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkLabel(self._recent_alerts_list, text="No recent alerts",
                     font=("Consolas", 9), text_color=C["text_dim"]
                     ).pack(pady=20)

        ctk.CTkButton(
            alert_preview, text="View All Alerts →",
            font=("Consolas", 9), text_color=C["accent"],
            fg_color="transparent", hover_color=C["bg_card"],
            height=28, command=self._show_alerts
        ).pack(pady=(0, 8))

    # ─── Page: Scan ─────────────────────────────────────────────────────────

    def _build_scan_page(self):
        page = ctk.CTkScrollableFrame(
            self._page_container, fg_color=C["bg_dark"], scrollbar_button_color=C["border"],
            scrollbar_button_hover_color=C["accent"]
        )
        page.grid(row=0, column=0, sticky="nsew")
        self._pages.append(page)

        # Directory selector
        dir_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        dir_card.pack(fill="x", padx=8, pady=(8, 4))

        ctk.CTkLabel(dir_card, text="◈  SCAN DIRECTORY",
                     font=("Consolas", 11, "bold"), text_color=C["accent"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        path_row = ctk.CTkFrame(dir_card, fg_color="transparent")
        path_row.pack(fill="x", padx=12, pady=(0, 10))

        self._scan_path_var = ctk.StringVar(value=os.path.expanduser("~"))
        self._scan_path_entry = ctk.CTkEntry(
            path_row, textvariable=self._scan_path_var,
            font=("Consolas", 10), fg_color=C["bg_dark"],
            border_color=C["border"], text_color=C["text"], height=36
        )
        self._scan_path_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            path_row, text="Browse", height=36,
            font=("Consolas", 10), fg_color=C["accent"], hover_color=C["accent_h"],
            text_color="#FFF", command=self._browse_scan_path
        ).pack(side="left")

        # Sensitivity selector
        sens_row = ctk.CTkFrame(dir_card, fg_color="transparent")
        sens_row.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkLabel(sens_row, text="Sensitivity:",
                     font=("Consolas", 9), text_color=C["text_dim"]
                     ).pack(side="left", padx=(0, 8))

        self._sens_var = ctk.StringVar(value="balanced")
        for i, (key, label) in enumerate([
            ("balanced", "Balanced"),
            ("high_sensitivity", "High Sensitivity"),
            ("paranoid", "Paranoid"),
        ]):
            rb = ctk.CTkRadioButton(
                sens_row, text=label, variable=self._sens_var, value=key,
                font=("Consolas", 9), text_color=C["text"],
                fg_color=C["accent"], hover_color=C["accent_h"],
            )
            rb.pack(side="left", padx=(0, 12))

        # Scan buttons
        btn_row = ctk.CTkFrame(dir_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=12, pady=(0, 10))

        self._scan_type_var = ctk.StringVar(value="full")
        scan_types = [
            ("full", "Full Scan", C["accent"]),
            ("quick", "Quick Scan", C["orange"]),
            ("incremental", "Incremental", C["purple"]),
        ]
        for key, label, color in scan_types:
            rb = ctk.CTkRadioButton(
                btn_row, text=label, variable=self._scan_type_var, value=key,
                font=("Consolas", 9, "bold"), text_color=color,
                fg_color=color, hover_color=color,
            )
            rb.pack(side="left", padx=(0, 12))

        self._start_scan_btn = ctk.CTkButton(
            btn_row, text="▶  START SCAN",
            font=("Consolas", 11, "bold"), height=40,
            fg_color=C["green"], hover_color="#1EA34A",
            text_color=C["bg_dark"], command=self._start_scan
        )
        self._start_scan_btn.pack(side="right")

        self._cancel_scan_btn = ctk.CTkButton(
            btn_row, text="■  CANCEL",
            font=("Consolas", 11), height=40,
            fg_color=C["danger"], hover_color="#9B1C1C",
            text_color="#FFF", state="disabled", command=self._cancel_scan
        )
        self._cancel_scan_btn.pack(side="right", padx=(8, 0))

        # Progress
        self._progress_bar = ScanProgressBar(page)
        self._progress_bar.pack(fill="x", padx=8, pady=4)

        # Progress stats
        self._scan_stats_lbl = ctk.CTkLabel(
            page, text="",
            font=("Consolas", 9), text_color=C["text_dim"]
        )
        self._scan_stats_lbl.pack(fill="x", padx=12)

        # Results section
        results_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        results_card.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        ctk.CTkLabel(results_card, text="SCAN RESULTS",
                     font=("Consolas", 11, "bold"), text_color=C["accent"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        # Results treeview
        tree_frame = ctk.CTkFrame(results_card, fg_color=C["bg_dark"], corner_radius=6)
        tree_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        columns = ("filename", "size", "entropy", "prob", "risk")
        self._results_tree = ctk.CTkScrollableFrame(
            tree_frame, fg_color="transparent",
            scrollbar_button_color=C["border"],
            height=460
        )
        self._results_tree.pack(fill="both", expand=True)

        # Header row
        header = ctk.CTkFrame(self._results_tree, fg_color=C["bg_panel"], height=28)
        header.pack(fill="x", padx=0, pady=(0, 1))
        header.pack_propagate(False)
        col_widths = [300, 80, 80, 80, 90]
        col_labels = ["Filename", "Size (KB)", "Entropy", "Prob %", "Risk"]
        for i, (w, lbl) in enumerate(zip(col_widths, col_labels)):
            f = ctk.CTkFrame(header, width=w, fg_color="transparent")
            f.pack(side="left", padx=2, fill="y", expand=True)
            f.pack_propagate(False)
            ctk.CTkLabel(f, text=lbl, font=("Consolas", 8, "bold"),
                         text_color=C["text_dim"]).pack(pady=4)

        self._results_rows: List[ctk.CTkFrame] = []
        self._scan_results: List[ScanResult] = []

    # ─── Page: Alerts ────────────────────────────────────────────────────────

    def _build_alerts_page(self):
        page = ctk.CTkScrollableFrame(
            self._page_container, fg_color=C["bg_dark"], scrollbar_button_color=C["border"],
            scrollbar_button_hover_color=C["accent"]
        )
        page.grid(row=0, column=0, sticky="nsew")
        self._pages.append(page)

        # Filters
        filter_row = ctk.CTkFrame(page, fg_color="transparent")
        filter_row.pack(fill="x", padx=8, pady=(8, 4))

        self._alert_filter_var = ctk.StringVar(value="all")
        for key, label in [("all", "All"), ("critical", "Critical"),
                            ("high", "High"), ("medium", "Medium")]:
            rb = ctk.CTkRadioButton(
                filter_row, text=label, variable=self._alert_filter_var, value=key,
                font=("Consolas", 9), text_color=C["text"],
                fg_color=C["accent"]
            )
            rb.pack(side="left", padx=(0, 12))

        ctk.CTkButton(
            filter_row, text="Clear All", height=28,
            font=("Consolas", 9), text_color=C["red"],
            fg_color="transparent", hover_color=C["bg_card"],
            command=self._clear_alerts
        ).pack(side="right")

        # Threat events section
        threat_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        threat_card.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        ctk.CTkLabel(threat_card, text="⚠  THREAT EVENTS",
                     font=("Consolas", 11, "bold"), text_color=C["red"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        self._threat_events_frame = ctk.CTkScrollableFrame(
            threat_card, height=200, fg_color="transparent",
            scrollbar_button_color=C["border"]
        )
        self._threat_events_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self._threat_event_widgets: List[ctk.CTkFrame] = []

        # Behavior alerts section
        behavior_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        behavior_card.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        ctk.CTkLabel(behavior_card, text="🔍  BEHAVIOR ALERTS",
                     font=("Consolas", 11, "bold"), text_color=C["orange"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        self._behavior_frame = ctk.CTkScrollableFrame(
            behavior_card, height=200, fg_color="transparent",
            scrollbar_button_color=C["border"]
        )
        self._behavior_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self._behavior_widgets: List[ctk.CTkFrame] = []

        self._show_alert_empty(page)

    def _show_alert_empty(self, page):
        # Called from the builder to show "no alerts" placeholder
        pass

    # ─── Page: Settings ─────────────────────────────────────────────────────

    def _build_settings_page(self):
        page = ctk.CTkScrollableFrame(
            self._page_container, fg_color=C["bg_dark"], scrollbar_button_color=C["border"],
            scrollbar_button_hover_color=C["accent"]
        )
        page.grid(row=0, column=0, sticky="nsew")
        self._pages.append(page)

        # Detection Threshold
        thresh_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        thresh_card.pack(fill="x", padx=8, pady=(8, 4))

        ctk.CTkLabel(thresh_card, text="⛨  DETECTION THRESHOLD",
                     font=("Consolas", 11, "bold"), text_color=C["accent"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        ctk.CTkLabel(
            thresh_card,
            text="Higher = fewer false positives, Lower = more sensitive",
            font=("Consolas", 8), text_color=C["text_dim"]
        ).pack(anchor="w", padx=12, pady=(0, 8))

        slider_row = ctk.CTkFrame(thresh_card, fg_color="transparent")
        slider_row.pack(fill="x", padx=12, pady=(0, 10))

        self._thresh_slider = ctk.CTkSlider(
            slider_row, from_=0.30, to=0.95, number_of_steps=65,
            progress_color=C["accent"], fg_color=C["border"],
            button_color=C["accent"], button_hover_color=C["accent_h"]
        )
        self._thresh_slider.set(config.get("ml.default_threshold", 0.65))
        self._thresh_slider.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._thresh_slider.bind("<ButtonRelease-1>", lambda e: self._on_threshold_change())

        self._thresh_val_lbl = ctk.CTkLabel(
            slider_row, text=f"{self._thresh_slider.get():.2f}",
            font=("Consolas", 11, "bold"), text_color=C["accent"], width=50
        )
        self._thresh_val_lbl.pack(side="left")

        # Auto-response settings
        auto_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        auto_card.pack(fill="x", padx=8, pady=4)

        ctk.CTkLabel(auto_card, text="⚡  AUTO-RESPONSE POLICY",
                     font=("Consolas", 11, "bold"), text_color=C["accent"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        for severity, action in [
            ("CRITICAL", "Auto Quarantine"),
            ("HIGH",     "Ask User"),
            ("MEDIUM",   "Notify Only"),
            ("LOW",      "Log Only"),
        ]:
            row = ctk.CTkFrame(auto_card, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=2)
            color = RISK_COLORS.get(severity, C["text"])
            ctk.CTkLabel(row, text=severity, font=("Consolas", 9, "bold"),
                         text_color=color, width=80, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=f"→ {action}", font=("Consolas", 9),
                         text_color=C["text_dim"]).pack(side="left")

        ctk.CTkButton(
            auto_card, text="Save Policy", height=32,
            font=("Consolas", 10), fg_color=C["accent"], hover_color=C["accent_h"],
            text_color="#FFF", command=self._save_auto_response_policy,
        ).pack(anchor="e", padx=12, pady=(8, 10))

        # Whitelist
        wl_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        wl_card.pack(fill="x", padx=8, pady=4)

        ctk.CTkLabel(wl_card, text="◈  WHITELIST EDITOR",
                     font=("Consolas", 11, "bold"), text_color=C["accent"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        wl_btns = ctk.CTkFrame(wl_card, fg_color="transparent")
        wl_btns.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkButton(
            wl_btns, text="Open Whitelist Editor",
            height=36, font=("Consolas", 10),
            fg_color=C["accent"], hover_color=C["accent_h"],
            text_color="#FFF", command=self._open_whitelist_editor
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            wl_btns, text="Apply Whitelist",
            height=36, font=("Consolas", 10),
            fg_color=C["bg_card"], hover_color=C["border"],
            text_color=C["text"], command=self._apply_whitelist
        ).pack(side="left")

        # Notification settings
        notif_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        notif_card.pack(fill="x", padx=8, pady=4)

        ctk.CTkLabel(notif_card, text="🔔  NOTIFICATIONS",
                     font=("Consolas", 11, "bold"), text_color=C["accent"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        notif_row = ctk.CTkFrame(notif_card, fg_color="transparent")
        notif_row.pack(fill="x", padx=12, pady=(0, 10))

        self._notif_toggle = AnimatedToggle(
            notif_row, text="Enable Notifications",
            command=self._on_notif_toggle
        )
        self._notif_toggle.on = config.get("notifications.enabled", True)
        self._notif_toggle.pack(side="left")

        self._sound_toggle = AnimatedToggle(
            notif_row, text="Sound Alerts",
            command=self._on_sound_toggle
        )
        self._sound_toggle.on = config.get("notifications.sound_enabled", True)
        self._sound_toggle.pack(side="left", padx=(16, 0))

        # ── VirusTotal ─────────────────────────────────────────────────────────
        vt_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        vt_card.pack(fill="x", padx=8, pady=4)

        ctk.CTkLabel(vt_card, text="VirusTotal Integration",
                     font=("Consolas", 11, "bold"), text_color=C["accent"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        vt_row = ctk.CTkFrame(vt_card, fg_color="transparent")
        vt_row.pack(fill="x", padx=12, pady=(0, 8))

        ctk.CTkLabel(vt_row, text="API Key:", font=("Consolas", 9),
                     text_color=C["text_dim"]).pack(side="left", padx=(0, 8))
        self._vt_api_key_var = ctk.StringVar(
            value=config.get("virustotal.api_key", "")
        )
        self._vt_api_key_entry = ctk.CTkEntry(
            vt_row, textvariable=self._vt_api_key_var,
            font=("Consolas", 9), fg_color=C["bg_dark"],
            border_color=C["border"], text_color=C["text"],
            width=300, show="*"
        )
        self._vt_api_key_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self._btn_vt_save = ctk.CTkButton(
            vt_row, text="Save", height=28,
            font=("Consolas", 9), fg_color=C["accent"],
            hover_color=C["accent_h"], text_color="#FFF",
            command=self._on_vt_save
        )
        self._btn_vt_save.pack(side="left")

        vt_status_row = ctk.CTkFrame(vt_card, fg_color="transparent")
        vt_status_row.pack(fill="x", padx=12, pady=(0, 10))

        self._vt_status_lbl = ctk.CTkLabel(
            vt_status_row, text="Not configured",
            font=("Consolas", 9), text_color=C["text_dim"]
        )
        self._vt_status_lbl.pack(side="left")

        self._vt_toggle = ctk.CTkSwitch(
            vt_status_row, text="Enable VT Checks",
            font=("Consolas", 9), text_color=C["text_dim"],
            progress_color=C["accent"], fg_color=C["border"],
            command=self._on_vt_toggle
        )
        self._vt_toggle.pack(side="right")
        self._vt_toggle.select() if config.get("virustotal.enabled", True) else self._vt_toggle.deselect()

        # ── DeepSeek AI Analysis ──────────────────────────────────────────────
        ai_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        ai_card.pack(fill="x", padx=8, pady=4)

        ai_title_row = ctk.CTkFrame(ai_card, fg_color="transparent")
        ai_title_row.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(ai_title_row, text="🤖  Claude AI Analysis",
                     font=("Consolas", 11, "bold"), text_color=C["cyan"]
                     ).pack(side="left")
        ctk.CTkLabel(ai_title_row,
                     text="Get AI-powered threat analysis. Proxy: taphoaapi.info.vn",
                     font=("Consolas", 8), text_color=C["text_dim"]
                     ).pack(side="left", padx=(12, 0))

        ai_key_row = ctk.CTkFrame(ai_card, fg_color="transparent")
        ai_key_row.pack(fill="x", padx=12, pady=(0, 6))

        ctk.CTkLabel(ai_key_row, text="API Key:", font=("Consolas", 9),
                     text_color=C["text_dim"]).pack(side="left", padx=(0, 8))
        self._ai_api_key_var = ctk.StringVar(
            value=config.get("ai.api_key", "")
        )
        self._ai_api_key_entry = ctk.CTkEntry(
            ai_key_row, textvariable=self._ai_api_key_var,
            font=("Consolas", 9), fg_color=C["bg_dark"],
            border_color=C["border"], text_color=C["text"],
            width=340, show="*"
        )
        self._ai_api_key_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self._btn_ai_save = ctk.CTkButton(
            ai_key_row, text="Save", height=28,
            font=("Consolas", 9), fg_color=C["accent"],
            hover_color=C["accent_h"], text_color="#FFF",
            command=self._on_ai_save
        )
        self._btn_ai_save.pack(side="left")

        ai_model_row = ctk.CTkFrame(ai_card, fg_color="transparent")
        ai_model_row.pack(fill="x", padx=12, pady=(0, 4))

        ctk.CTkLabel(ai_model_row, text="Model:", font=("Consolas", 9),
                     text_color=C["text_dim"]).pack(side="left", padx=(0, 8))
        self._ai_model_var = ctk.StringVar(
            value=config.get("ai.model", "claude-sonnet-4-6")
        )
        ai_model_menu = ctk.CTkOptionMenu(
            ai_model_row,
            values=["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001"],
            variable=self._ai_model_var,
            font=("Consolas", 9), fg_color=C["bg_dark"],
            button_color=C["accent"], button_hover_color=C["accent_h"],
            dropdown_fg_color=C["bg_card"],
            text_color=C["text"], width=220,
            command=self._on_ai_model_change
        )
        ai_model_menu.pack(side="left", padx=(0, 12))
        ctk.CTkLabel(ai_model_row,
                     text="sonnet = balanced  |  opus = most capable  |  haiku = fastest",
                     font=("Consolas", 7), text_color=C["text_dim"]
                     ).pack(side="left")

        ai_status_row = ctk.CTkFrame(ai_card, fg_color="transparent")
        ai_status_row.pack(fill="x", padx=12, pady=(0, 10))

        self._ai_status_lbl = ctk.CTkLabel(
            ai_status_row,
            text="Not configured — enter API key above",
            font=("Consolas", 9), text_color=C["text_dim"]
        )
        self._ai_status_lbl.pack(side="left")

        self._btn_ai_test = ctk.CTkButton(
            ai_status_row, text="Test Connection", height=26,
            font=("Consolas", 8), fg_color=C["bg_dark"],
            hover_color=C["border"], text_color=C["cyan"],
            command=self._on_ai_test
        )
        self._btn_ai_test.pack(side="left", padx=(12, 0))

        self._ai_toggle = ctk.CTkSwitch(
            ai_status_row, text="Enable AI Analysis",
            font=("Consolas", 9), text_color=C["text_dim"],
            progress_color=C["cyan"], fg_color=C["border"],
            command=self._on_ai_toggle
        )
        self._ai_toggle.pack(side="right")
        if config.get("ai.enabled", True):
            self._ai_toggle.select()
        else:
            self._ai_toggle.deselect()

        # Refresh status on open
        if config.get("ai.api_key", ""):
            self._ai_status_lbl.configure(text="API key saved ✓", text_color=C["green"])

        # ── API Server ─────────────────────────────────────────────────────────
        api_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        api_card.pack(fill="x", padx=8, pady=4)

        ctk.CTkLabel(api_card, text="REST API Server (FastAPI)",
                     font=("Consolas", 11, "bold"), text_color=C["accent"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        api_row = ctk.CTkFrame(api_card, fg_color="transparent")
        api_row.pack(fill="x", padx=12, pady=(0, 4))

        ctk.CTkLabel(api_row, text="Host:", font=("Consolas", 9),
                     text_color=C["text_dim"]).pack(side="left", padx=(0, 4))
        self._api_host_var = ctk.StringVar(value=config.get("api.host", "0.0.0.0"))
        ctk.CTkEntry(api_row, textvariable=self._api_host_var,
                     font=("Consolas", 9), fg_color=C["bg_dark"],
                     border_color=C["border"], text_color=C["text"],
                     width=100).pack(side="left", padx=(0, 8))

        ctk.CTkLabel(api_row, text="Port:", font=("Consolas", 9),
                     text_color=C["text_dim"]).pack(side="left", padx=(0, 4))
        self._api_port_var = ctk.StringVar(value=str(config.get("api.port", 8000)))
        ctk.CTkEntry(api_row, textvariable=self._api_port_var,
                     font=("Consolas", 9), fg_color=C["bg_dark"],
                     border_color=C["border"], text_color=C["text"],
                     width=80).pack(side="left", padx=(0, 8))

        self._btn_api_toggle = ctk.CTkButton(
            api_row, text="Start Server", height=32,
            font=("Consolas", 10, "bold"), fg_color=C["green"],
            hover_color="#1EA34A", text_color=C["bg_dark"],
            command=self._on_api_toggle
        )
        self._btn_api_toggle.pack(side="right")

        api_status_row = ctk.CTkFrame(api_card, fg_color="transparent")
        api_status_row.pack(fill="x", padx=12, pady=(0, 10))

        self._api_status_lbl = ctk.CTkLabel(
            api_status_row, text="API server is not running",
            font=("Consolas", 9), text_color=C["text_dim"]
        )
        self._api_status_lbl.pack(side="left")

        self._api_log = ctk.CTkTextbox(
            api_card, font=("Cascadia Code", 8),
            fg_color=C["bg_dark"], text_color=C["text"],
            border_color=C["border"], border_width=1,
            scrollbar_button_color=C["border"],
            wrap="word", height=80
        )
        self._api_log.pack(fill="x", padx=12, pady=(0, 10))
        self._api_log.configure(state="disabled")
        self._api_server_running = False
        self._api_server = None

        # About / Model info
        about_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        about_card.pack(fill="x", padx=8, pady=4)

        ctk.CTkLabel(about_card, text="ℹ  MODEL INFORMATION",
                     font=("Consolas", 11, "bold"), text_color=C["accent"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        self._model_info_lbl = ctk.CTkLabel(
            about_card, text="Loading model info...",
            font=("Consolas", 9), text_color=C["text_dim"], justify="left"
        )
        self._model_info_lbl.pack(anchor="w", padx=12, pady=(0, 10))

    # ─── Page: Quarantine ────────────────────────────────────────────────────

    def _build_quarantine_page(self):
        page = ctk.CTkScrollableFrame(
            self._page_container, fg_color=C["bg_dark"], scrollbar_button_color=C["border"],
            scrollbar_button_hover_color=C["accent"]
        )
        page.grid(row=0, column=0, sticky="nsew")
        self._pages.append(page)

        info_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        info_card.pack(fill="x", padx=8, pady=(8, 4))

        ctk.CTkLabel(info_card, text="◻  QUARANTINE MANAGEMENT",
                     font=("Consolas", 11, "bold"), text_color=C["accent"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        self._quarantine_list = ctk.CTkScrollableFrame(
            info_card, height=300, fg_color="transparent",
            scrollbar_button_color=C["border"]
        )
        self._quarantine_list.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        ctk.CTkLabel(
            self._quarantine_list, text="No quarantined files",
            font=("Consolas", 9), text_color=C["text_dim"]
        ).pack(pady=20)

        btn_row = ctk.CTkFrame(page, fg_color="transparent")
        btn_row.pack(fill="x", padx=8, pady=4)

        ctk.CTkButton(
            btn_row, text="Refresh List", height=36,
            font=("Consolas", 10),
            fg_color=C["bg_card"], hover_color=C["border"],
            text_color=C["text"], command=self._refresh_quarantine
        ).pack(side="left")

    # ─── Page: Reports ───────────────────────────────────────────────────────

    def _build_reports_page(self):
        page = ctk.CTkScrollableFrame(
            self._page_container, fg_color=C["bg_dark"], scrollbar_button_color=C["border"],
            scrollbar_button_hover_color=C["accent"]
        )
        page.grid(row=0, column=0, sticky="nsew")
        self._pages.append(page)

        export_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        export_card.pack(fill="x", padx=8, pady=(8, 4))

        ctk.CTkLabel(export_card, text="⎙  EXPORT REPORTS",
                     font=("Consolas", 11, "bold"), text_color=C["accent"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        # Scan first prompt
        self._export_prompt_lbl = ctk.CTkLabel(
            export_card,
            text="⚠ Run a scan first to generate reports",
            font=("Consolas", 9), text_color=C["orange"]
        )
        self._export_prompt_lbl.pack(anchor="w", padx=12, pady=(0, 8))

        export_btn_row = ctk.CTkFrame(export_card, fg_color="transparent")
        export_btn_row.pack(fill="x", padx=12, pady=(0, 10))

        export_btns = [
            ("Export CSV", C["blue"], self._export_csv),
            ("Export PNG Chart", C["purple"], self._export_png),
            ("Forensic Bundle", C["orange"], self._export_forensic),
        ]
        for label, color, cmd in export_btns:
            ctk.CTkButton(
                export_btn_row, text=label, height=40,
                font=("Consolas", 10, "bold"),
                fg_color=color, hover_color=color,
                text_color="#FFF", command=cmd
            ).pack(side="left", padx=(0, 8))

        # Scan history / stats
        stats_card = ctk.CTkFrame(page, fg_color=C["bg_card"], corner_radius=8)
        stats_card.pack(fill="both", expand=True, padx=8, pady=4)

        ctk.CTkLabel(stats_card, text="📊  SCAN STATISTICS",
                     font=("Consolas", 11, "bold"), text_color=C["accent"]
                     ).pack(anchor="w", padx=12, pady=(10, 4))

        # Chart: entropy scatter
        self._scatter_plot = PlotFrame(stats_card, figsize=(8, 3.5))
        self._scatter_plot._ax.text(0.5, 0.5, "Run a scan to see entropy distribution",
                                    ha="center", va="center",
                                    color=C["text_dim"], fontsize=9,
                                    transform=self._scatter_plot._ax.transAxes)
        self._scatter_plot.canvas.draw_idle()
        self._scatter_plot.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self._scan_summary_lbl = ctk.CTkLabel(
            stats_card, text="No scan data yet",
            font=("Consolas", 9), text_color=C["text_dim"]
        )
        self._scan_summary_lbl.pack(anchor="w", padx=12, pady=(0, 8))

    # ─── Page: Logs ─────────────────────────────────────────────────────────

    def _build_logs_page(self):
        page = ctk.CTkFrame(self._page_container, fg_color=C["bg_dark"])
        page.grid(row=0, column=0, sticky="nsew")
        self._pages.append(page)

        log_header = ctk.CTkFrame(page, fg_color=C["bg_panel"], height=40)
        log_header.pack(fill="x")
        log_header.pack_propagate(False)

        ctk.CTkLabel(
            log_header, text="☰  APPLICATION LOGS",
            font=("Consolas", 11, "bold"), text_color=C["accent"]
        ).pack(side="left", padx=12, pady=6)

        ctk.CTkButton(
            log_header, text="Clear", height=28,
            font=("Consolas", 8), text_color=C["text_dim"],
            fg_color="transparent", hover_color=C["bg_card"],
            command=self._clear_logs
        ).pack(side="right", padx=8, pady=4)

        self._log_text = ctk.CTkTextbox(
            page, font=("Consolas", 9),
            fg_color=C["bg_dark"], text_color=C["text"],
            border_color=C["border"], border_width=0,
            scrollbar_button_color=C["border"]
        )
        self._log_text.pack(fill="both", expand=True, padx=8, pady=8)
        self._log_text.configure(state="disabled")

        self._log_text.tag_config("info", foreground=C["blue"])
        self._log_text.tag_config("success", foreground=C["green"])
        self._log_text.tag_config("warning", foreground=C["orange"])
        self._log_text.tag_config("danger", foreground=C["red"])
        self._log_text.tag_config("system", foreground=C["purple"])

    # ═══════════════════════════════════════════════════════════════════════
    # NAVIGATION
    # ═══════════════════════════════════════════════════════════════════════

    def _show_page(self, index: int):
        for i, page in enumerate(self._pages):
            if i == index:
                page.grid(row=0, column=0, sticky="nsew")
            else:
                try:
                    page.grid_forget()
                except Exception:
                    pass
        self._current_page = index

        # Update sidebar buttons
        for i, btn in enumerate(self._nav_buttons):
            if i == index:
                btn.configure(fg_color=C["bg_card"], text_color=C["accent"])
            else:
                btn.configure(fg_color="transparent", text_color=C["text_dim"])

    def _show_dashboard(self):
        self._show_page(0)

    def _show_scan(self):
        self._show_page(1)

    def _show_alerts(self):
        self._show_page(2)

    def _show_settings(self):
        self._show_page(3)
        self._refresh_model_info()

    def _show_quarantine(self):
        self._show_page(4)
        self._refresh_quarantine()

    def _show_reports(self):
        self._show_page(5)

    def _show_logs(self):
        self._show_page(6)

    # ═══════════════════════════════════════════════════════════════════════
    # SCAN ENGINE
    # ═══════════════════════════════════════════════════════════════════════

    def _browse_scan_path(self):
        path = filedialog.askdirectory(title="Select directory to scan")
        if path:
            self._scan_path_var.set(path)

    def _start_scan(self):
        path = self._scan_path_var.get().strip()
        if not path or not os.path.isdir(path):
            messagebox.showwarning("Invalid Path", "Please select a valid directory.")
            return

        self._scan_type = self._scan_type_var.get()
        sensitivity = self._sens_var.get()
        self._scanner.set_sensitivity(sensitivity)
        self._scan_start_time = time.time()
        self._scan_results.clear()
        self._scan_entropy_data.clear()
        self._scan_prob_data.clear()
        self._scan_risk_data.clear()

        self._start_scan_btn.configure(state="disabled", text="SCANNING...")
        self._cancel_scan_btn.configure(state="normal")

        self._log("info", f"Starting {self._scan_type} scan: {path}")
        self._set_status(f"Scanning: {path}", C["blue"])

        def _run():
            # VirusTotal: dùng cùng cài đặt Settings (virustotal.enabled / auto_check)
            vt_on = bool(config.get("virustotal.enabled", False))
            vt_all = bool(config.get("virustotal.auto_check", False))
            self._scanner.scan(
                directory=path,
                recursive=(self._scan_type == "full"),
                on_progress=self._on_scan_progress,
                on_complete=self._on_scan_complete,
                on_error=self._on_scan_error,
                scan_mode=self._scan_type,
                vt_enabled=vt_on,
                vt_auto_check=vt_all,
            )

        threading.Thread(target=_run, daemon=True).start()

    def _quick_scan(self):
        self._scan_type_var.set("quick")
        self._start_scan()

    def _full_scan(self):
        self._scan_type_var.set("full")
        self._start_scan()

    def _cancel_scan(self):
        self._scanner.cancel()
        self._log("warning", "Scan cancelled by user")
        self._start_scan_btn.configure(state="normal", text="▶  START SCAN")
        self._cancel_scan_btn.configure(state="disabled")
        self._set_status("Scan cancelled", C["orange"])

    def _on_scan_progress(self, current: int, total: int, result: ScanResult):
        elapsed = time.time() - self._scan_start_time
        self._scan_results.append(result)

        self._scan_entropy_data.append(result.entropy)
        self._scan_prob_data.append(result.probability)
        self._scan_risk_data.append(result.risk_level)

        self.after(0, lambda: self._progress_bar.set_progress(current, total, elapsed))
        self.after(0, lambda: self._update_scan_stats())
        self.after(0, lambda: self._add_result_row(result))

        # ── Route HIGH/CRITICAL results to Alerts tab ──────────────────────
        if result.risk_level in ("CRITICAL", "HIGH") and not result.error:
            from core.watchdog_monitor import ThreatEvent
            threat = ThreatEvent(result, "scan")
            self._threat_events.append(threat)
            self.after(0, lambda t=threat: self._add_threat_widget(t))

    def _on_scan_complete(self, results: List[ScanResult]):
        elapsed = time.time() - self._scan_start_time
        summary = self._scanner.get_summary()

        self.after(0, lambda: self._progress_bar.set_progress(
            len(results), len(results), elapsed
        ))
        self.after(0, lambda: self._start_scan_btn.configure(
            state="normal", text="▶  START SCAN"
        ))
        self.after(0, lambda: self._cancel_scan_btn.configure(state="disabled"))

        safe = summary.get("safe", 0)
        crit = summary.get("critical", 0)
        high = summary.get("high", 0)
        total_s = summary.get("total", 0)

        msg = f"Scan complete — {total_s} files in {elapsed:.1f}s | SAFE: {safe} | CRITICAL: {crit} | HIGH: {high}"
        color = C["red"] if crit > 0 else C["green"]
        self.after(0, lambda: self._set_status(msg, color))
        self.after(0, lambda: self._log("success", msg))

        # Update scatter chart
        if self._scan_entropy_data:
            self.after(0, self._update_scatter_chart)

    def _on_scan_error(self, error: str):
        self.after(0, lambda: self._start_scan_btn.configure(
            state="normal", text="▶  START SCAN"
        ))
        self.after(0, lambda: self._cancel_scan_btn.configure(state="disabled"))
        self.after(0, lambda: self._set_status(f"Scan error: {error}", C["red"]))
        self.after(0, lambda: self._log("danger", f"Scan error: {error}"))

    def _update_scan_stats(self):
        results = self._scan_results
        if not results:
            return
        total = len(results)
        encrypted = sum(1 for r in results if r.label == 1)
        avg_ent = sum(r.entropy for r in results) / total
        self._scan_stats_lbl.configure(
            text=f"Total: {total} | Encrypted: {encrypted} | Avg Entropy: {avg_ent:.3f} | "
                 f"Scan Type: {self._scan_type.title()}"
        )

    def _add_result_row(self, result: ScanResult):
        if not hasattr(self, "_results_tree"):
            return
        row = ctk.CTkFrame(self._results_tree, fg_color=C["bg_card"], height=24)
        row.pack(fill="x", padx=0, pady=(0, 1))
        row.pack_propagate(False)

        risk_color = RISK_COLORS.get(result.risk_level, C["text_dim"])
        size_kb = result.size / 1024 if result.size else 0

        vals = [
            (result.filename[:45], 300, C["text"]),
            (f"{size_kb:.1f}", 80, C["text_dim"]),
            (f"{result.entropy:.3f}", 80, risk_color),
            (f"{result.probability * 100:.1f}", 80, risk_color),
            (result.risk_level, 90, risk_color),
        ]

        for i, (text, w, color) in enumerate(vals):
            f = ctk.CTkFrame(row, width=w, fg_color="transparent")
            f.pack(side="left", padx=2, fill="y", expand=True)
            f.pack_propagate(False)
            ctk.CTkLabel(f, text=text, font=("Consolas", 8), text_color=color,
                         anchor="w").pack(pady=2, padx=4)

        self._results_rows.append(row)

    def _update_scatter_chart(self):
        if not self._scan_entropy_data:
            return
        try:
            self._scatter_plot.scatter_entropy(
                self._scan_entropy_data,
                self._scan_prob_data,
                self._scan_risk_data
            )
            # Update summary
            total = len(self._scan_results)
            threats = sum(1 for r in self._scan_results if r.label == 1)
            self._scan_summary_lbl.configure(
                text=f"Total: {total} files | Threats: {threats} ({threats / max(total, 1) * 100:.1f}%) | "
                     f"Last scan: {datetime.now().strftime('%H:%M:%S')}"
            )
            self._export_prompt_lbl.configure(text="✓ Scan results ready — export available")
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════
    # MONITOR ENGINE
    # ═══════════════════════════════════════════════════════════════════════

    def _browse_monitor_path(self):
        path = filedialog.askdirectory(title="Select directory to monitor")
        if path:
            self._monitor_path_var.set(path)

    def _toggle_monitor(self):
        if self._monitor.is_running:
            self._stop_monitor()
        else:
            self._start_monitor()

    def _start_monitor(self):
        path = self._monitor_path_var.get().strip()
        if not os.path.isdir(path):
            messagebox.showwarning("Invalid Path", "Please select a valid directory to monitor.")
            return

        # Chạy start() trong thread nền để không chặn GUI (schedule recursive có thể rất lâu)
        self._set_status("Starting monitor…", C["text_dim"])
        self._monitor_btn.configure(state="disabled")

        def _do_start():
            ok = self._monitor.start(path, recursive=True)
            self.after(0, lambda: self._on_monitor_start_done(ok, path))

        threading.Thread(target=_do_start, daemon=True).start()

    def _on_monitor_start_done(self, success: bool, path: str):
        self._monitor_btn.configure(state="normal")
        if success:
            self._monitor_start_time = time.time()
            self._monitor_btn.configure(
                text="  ■  Stop Monitor",
                fg_color=C["red"], hover_color=C["danger"],
                text_color="#FFF"
            )
            self._set_status(f"Monitoring: {path}", C["green"])
            self._log("success", f"Real-time monitor started: {path}")
        else:
            self._set_status("Monitor failed to start", C["red"])
            self._log("danger", "Failed to start monitor — ensure ML model is loaded")

    def _stop_monitor(self):
        self._monitor.stop()
        self._monitor_btn.configure(
            text="  ▶  Start Monitor",
            fg_color=C["green"], hover_color="#1EA34A",
            text_color=C["bg_dark"]
        )
        self._set_status("Monitor stopped", C["text_dim"])
        self._log("info", "Real-time monitor stopped")

    def _on_protection_toggle(self, on: bool):
        self._protection_on = on
        if on:
            self._set_status("Protection enabled", C["green"])
        else:
            self._set_status("⚠ Protection disabled", C["red"])

    # ═══════════════════════════════════════════════════════════════════════
    # ALERT / BEHAVIOR CALLBACKS
    # ═══════════════════════════════════════════════════════════════════════

    def _on_threat(self, event: ThreatEvent):
        self._threat_events.append(event)
        self.after(0, lambda: self._add_threat_widget(event))

    def _on_file_analyzed(self, result: ScanResult, event_type: str):
        # Called for every file analyzed during monitoring
        if not hasattr(self, "_threats_lbl"):
            return
        current = int(self._threats_lbl.cget("text"))
        self.after(0, lambda: self._threats_lbl.configure(text=str(current)))

    def _on_behavior_alert(self, alert: BehaviorAlert):
        self._behavior_alerts.append(alert)
        # Batch all widget updates into ONE after(0) to avoid flooding the event loop
        self.after(0, lambda a=alert: (
            self._add_behavior_widget(a),
            self._update_behavior_summary(a),
            self._update_gauge_from_alert(a),
            self._log("warning", f"Behavior: {a.behavior_type.value} | {a.process.name} | {a.description}")
        ))

    def _add_threat_widget(self, event: ThreatEvent):
        if not hasattr(self, "_threat_events_frame"):
            return
        # Clear "no alerts" placeholder
        for child in self._threat_events_frame.winfo_children():
            if isinstance(child, ctk.CTkLabel) and "No recent" in child.cget("text"):
                child.destroy()
                break

        risk_color = RISK_COLORS.get(event.result.risk_level, C["text_dim"])
        ts = datetime.fromisoformat(event.timestamp).strftime("%H:%M:%S")

        card = ctk.CTkFrame(self._threat_events_frame, fg_color=C["bg_card"], corner_radius=6)
        card.pack(fill="x", pady=2)

        top_row = ctk.CTkFrame(card, fg_color="transparent")
        top_row.pack(fill="x", padx=8, pady=(6, 0))

        ctk.CTkLabel(top_row, text=f"[{ts}]", font=("Consolas", 8),
                     text_color=C["text_dim"]).pack(side="left")
        ctk.CTkLabel(top_row, text=event.result.risk_level, font=("Consolas", 8, "bold"),
                     text_color=risk_color).pack(side="left", padx=8)
        ctk.CTkLabel(top_row, text=event.event_type.capitalize(),
                     font=("Consolas", 8), text_color=C["text_dim"]).pack(side="right")

        ctk.CTkLabel(card, text=event.result.filename,
                     font=("Consolas", 9), text_color=C["text"],
                     anchor="w", wraplength=600
                     ).pack(anchor="w", padx=8, pady=(0, 6))

        action_row = ctk.CTkFrame(card, fg_color="transparent")
        action_row.pack(fill="x", padx=8, pady=(0, 6))
        
        ctk.CTkButton(
            action_row, text="Analyze with AI", height=24,
            font=("Consolas", 8), text_color=C["cyan"],
            fg_color="transparent", hover_color=C["bg_card"],
            command=lambda e=event: self._ai_analyze_threat_event(e)
        ).pack(side="left")

        self._threat_event_widgets.append(card)
        if len(self._threat_event_widgets) > 50:
            oldest = self._threat_event_widgets.pop(0)
            oldest.destroy()

    def _add_behavior_widget(self, alert: BehaviorAlert):
        if not hasattr(self, "_behavior_frame"):
            return
        for child in self._behavior_frame.winfo_children():
            if isinstance(child, ctk.CTkLabel) and "No" in child.cget("text"):
                child.destroy()
                break

        sev_color = RISK_COLORS.get(alert.severity.upper(), C["text_dim"])
        ts = alert.timestamp.strftime("%H:%M:%S")

        card = ctk.CTkFrame(self._behavior_frame, fg_color=C["bg_card"], corner_radius=6)
        card.pack(fill="x", pady=2)

        top_row = ctk.CTkFrame(card, fg_color="transparent")
        top_row.pack(fill="x", padx=8, pady=(6, 0))

        ctk.CTkLabel(top_row, text=f"[{ts}]", font=("Consolas", 8),
                     text_color=C["text_dim"]).pack(side="left")
        ctk.CTkLabel(top_row, text=alert.behavior_type.value,
                     font=("Consolas", 8, "bold"), text_color=sev_color
                     ).pack(side="left", padx=8)
        ctk.CTkLabel(top_row, text=f"{alert.process.name} (PID {alert.process.pid})",
                     font=("Consolas", 8), text_color=C["text_dim"]
                     ).pack(side="right")

        ctk.CTkLabel(card, text=alert.description,
                     font=("Consolas", 9), text_color=C["text"],
                     anchor="w", wraplength=600
                     ).pack(anchor="w", padx=8, pady=(0, 6))

        # Action buttons
        action_row = ctk.CTkFrame(card, fg_color="transparent")
        action_row.pack(fill="x", padx=8, pady=(0, 6))

        if alert.process.pid:
            ctk.CTkButton(
                action_row, text="Kill Process", height=24,
                font=("Consolas", 8), text_color=C["red"],
                fg_color="transparent", hover_color=C["bg_card"],
                command=lambda p=alert.process: self._kill_process_action(p)
            ).pack(side="left", padx=(0, 4))

            ctk.CTkButton(
                action_row, text="Block Network", height=24,
                font=("Consolas", 8), text_color=C["orange"],
                fg_color="transparent", hover_color=C["bg_card"],
                command=lambda p=alert.process: self._block_network_action(p)
            ).pack(side="left")

        ctk.CTkButton(
            action_row, text="Analyze with AI", height=24,
            font=("Consolas", 8), text_color=C["cyan"],
            fg_color="transparent", hover_color=C["bg_card"],
            command=lambda a=alert: self._ai_analyze_alert(a)
        ).pack(side="left", padx=(4, 0))

        self._behavior_widgets.append(card)
        if len(self._behavior_widgets) > 50:
            oldest = self._behavior_widgets.pop(0)
            oldest.destroy()

    def _update_behavior_summary(self, alert: BehaviorAlert):
        if not hasattr(self, "_pm_labels"):
            return
        key_map = {
            BehaviorType.ENCRYPTION_BURST: "encryption_bursts",
            BehaviorType.MASS_IO_ANOMALY: "io_anomalies",
            BehaviorType.FILE_RENAME_BURST: "io_anomalies",
            BehaviorType.RAPID_OPS: "total_events",
            BehaviorType.HIGH_ENTROPY_WRITE: "total_events",
            BehaviorType.SUSPICIOUS_PROCESS: "total_events",
            BehaviorType.EXTENSION_CHANGE: "total_events",
        }
        key = key_map.get(alert.behavior_type, "total_events")
        if key in self._pm_labels:
            current = self._pm_labels[key].cget("text")
            try:
                count = int(current.split()[0]) + 1 if " " in current else int(current) + 1
                self._pm_labels[key].configure(text=f"{count} {alert.behavior_type.value.replace('_', ' ').title()}")

            except Exception:
                pass

    def _update_gauge_from_alert(self, alert: BehaviorAlert):
        if not hasattr(self, "_gauge_plot"):
            return
        sev_map = {"CRITICAL": 0.9, "HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.2}
        score = sev_map.get(alert.severity.upper(), 0.1)
        self._gauge_plot.signal_gauge(score, alert.behavior_type.value.replace("_", " "))

    def _kill_process_action(self, process: ProcessInfo):
        if messagebox.askyesno("Kill Process",
                               f"Kill process '{process.name}' (PID {process.pid})?"):
            result = self._responder.kill_process(process.pid, process.name)
            if result:
                self._log("success", f"Process {process.name} killed")
            else:
                self._log("danger", f"Failed to kill process {process.name}")

    def _block_network_action(self, process: ProcessInfo):
        result = self._responder.block_network(process.pid, process.name)
        if result:
            self._log("success", f"Network blocked for {process.name}")
        else:
            self._log("danger", f"Failed to block network for {process.name}")

    def _ai_analyze_alert(self, alert: BehaviorAlert):
        def _run_ai():
            from core.ai_analyzer import get_ai_analyzer
            analyzer = get_ai_analyzer()
            self._log("info", f"Sending alert for AI analysis: {alert.behavior_type.value}...")
            self._set_status("Analyzing threat with AI...", C["cyan"])
            
            threat_context = {
                "behavior_type": alert.behavior_type.value,
                "process_name": alert.process.name,
                "pid": alert.process.pid,
                "severity": alert.severity,
                "description": alert.description,
            }
            
            result = analyzer.analyze_threat(threat_context)
            
            self.after(0, lambda: self._show_ai_result_popup(alert.process.name, result))
            
        import threading
        threading.Thread(target=_run_ai, daemon=True).start()

    def _ai_analyze_threat_event(self, event: ThreatEvent):
        def _run_ai():
            from core.ai_analyzer import get_ai_analyzer
            analyzer = get_ai_analyzer()
            self._log("info", f"Sending file threat for AI analysis: {event.result.filename}...")
            self._set_status("Analyzing file threat with AI...", C["cyan"])
            
            threat_context = {
                "filename": event.result.filename,
                "file_size": event.result.size,
                "entropy": event.result.entropy,
                "ml_probability": event.result.probability,
                "risk_level": event.result.risk_level,
                "event_type": event.event_type,
            }
            
            result = analyzer.analyze_threat(threat_context)
            filename_short = event.result.filename.split("/")[-1].split("\\")[-1]
            
            self.after(0, lambda: self._show_ai_result_popup(filename_short, result))
            
        import threading
        threading.Thread(target=_run_ai, daemon=True).start()

    def _show_ai_result_popup(self, process_name: str, result: str):
        self._set_status("AI Analysis complete", C["green"])
        self._log("success", f"AI Analysis finished for {process_name}")
        win = ctk.CTkToplevel(self)
        win.title(f"AI Analysis - {process_name}")
        win.geometry("700x500")
        win.attributes("-topmost", True)
        
        textbox = ctk.CTkTextbox(win, font=("Consolas", 11), wrap="word")
        textbox.pack(fill="both", expand=True, padx=10, pady=10)
        textbox.insert("0.0", result)
        textbox.configure(state="disabled")

    # ─── DeepSeek AI Settings handlers ──────────────────────────────────────

    def _on_ai_save(self):
        """Save Claude API key to config and reinitialize analyzer."""
        api_key = self._ai_api_key_var.get().strip()
        config.set("ai.api_key", api_key)
        # Force re-create singleton so new key takes effect
        import core.ai_analyzer as _ai_mod
        _ai_mod._ai_analyzer_instance = None
        if api_key:
            self._ai_status_lbl.configure(text="API key saved ✓  (click Test to verify)", text_color=C["green"])
            self._log("success", "Claude API key saved")
        else:
            self._ai_status_lbl.configure(text="API key cleared", text_color=C["text_dim"])

    def _on_ai_model_change(self, model: str):
        config.set("ai.model", model)
        # Reset singleton so model update takes effect
        import core.ai_analyzer as _ai_mod
        _ai_mod._ai_analyzer_instance = None
        self._log("info", f"Claude model changed to: {model}")

    def _on_ai_toggle(self):
        enabled = self._ai_toggle.get() == 1
        config.set("ai.enabled", enabled)
        self._log("info", f"AI Analysis {'enabled' if enabled else 'disabled'}")

    def _on_ai_test(self):
        """Test Claude connection with a minimal API call."""
        if not config.get("ai.api_key", ""):
            self._ai_status_lbl.configure(text="⚠ No API key — save one first", text_color=C["orange"])
            return
        self._ai_status_lbl.configure(text="Testing connection…", text_color=C["text_dim"])
        self._btn_ai_test.configure(state="disabled")

        def _test():
            from core.ai_analyzer import get_ai_analyzer
            import core.ai_analyzer as _ai_mod
            _ai_mod._ai_analyzer_instance = None  # fresh instance with latest key
            analyzer = get_ai_analyzer()
            result = analyzer.analyze_threat({"test": "ping", "message": "Reply with: OK"})
            ok = "error" not in result.lower() and "401" not in result and "403" not in result
            self.after(0, lambda: self._on_ai_test_done(ok, result))

        threading.Thread(target=_test, daemon=True).start()

    def _on_ai_test_done(self, ok: bool, message: str):
        self._btn_ai_test.configure(state="normal")
        if ok:
            self._ai_status_lbl.configure(
                text="✓ Connected to Claude API", text_color=C["green"]
            )
            self._log("success", "Claude API connection verified")
        else:
            short = message[:120].replace("\n", " ")
            self._ai_status_lbl.configure(
                text=f"✗ {short}", text_color=C["red"]
            )
            self._log("danger", f"Claude API test failed: {message[:200]}")

    def _clear_alerts(self):
        self._threat_events.clear()
        self._behavior_alerts.clear()
        for w in getattr(self, "_threat_event_widgets", []):
            w.destroy()
        for w in getattr(self, "_behavior_widgets", []):
            w.destroy()
        self._threat_event_widgets.clear()
        self._behavior_widgets.clear()
        self._log("info", "All alerts cleared")

    # ═══════════════════════════════════════════════════════════════════════
    # SETTINGS HANDLERS
    # ═══════════════════════════════════════════════════════════════════════

    def _on_threshold_change(self):
        thresh = self._thresh_slider.get()
        self._thresh_val_lbl.configure(text=f"{thresh:.2f}")
        self._engine.set_threshold(thresh)
        config.set("ml.default_threshold", thresh)
        self._log("info", f"Threshold updated to {thresh:.2f}")

    def _save_auto_response_policy(self):
        self._responder.save()
        self._log("success", "Auto-response policy saved")

    def _open_whitelist_editor(self):
        try:
            editor = WhitelistEditorWindow(self)
            editor.lift()
        except Exception as e:
            self._log("danger", f"Failed to open whitelist editor: {e}")

    def _apply_whitelist(self):
        self._log("success", "Whitelist applied to scanner")
        self._set_status("Whitelist updated", C["green"])

    def _on_notif_toggle(self, on: bool):
        config.set("notifications.enabled", on)
        self._notifier.enabled = on

    def _on_sound_toggle(self, on: bool):
        config.set("notifications.sound_enabled", on)
        self._notifier.sound_enabled = on

    def _refresh_model_info(self):
        info = self._engine.get_model_info()
        acc = info.get("accuracy", 0)
        prec = info.get("precision", 0)
        rec = info.get("recall", 0)
        thresh = info.get("current_threshold", 0)
        fpr = info.get("false_positive_rate", 0)

        text = (
            f"  Accuracy:     {acc * 100:.2f}%\n"
            f"  Precision:   {prec * 100:.2f}%\n"
            f"  Recall:       {rec * 100:.2f}%\n"
            f"  FPR:          {fpr * 100:.2f}%\n"
            f"  Threshold:    {thresh:.2f}\n"
            f"  Features:    {info.get('n_features', 16)}"
        )
        self._model_info_lbl.configure(text=text)

    # ─── VirusTotal handlers ───────────────────────────────────────────────

    def _on_vt_save(self):
        api_key = self._vt_api_key_var.get().strip()
        config.set("virustotal.api_key", api_key)
        if api_key:
            try:
                from core.virustotal_client import VirusTotalClient
                self._vt_client = VirusTotalClient(api_key)
                self._vt_status_lbl.configure(
                    text="Connected", text_color=C["green"]
                )
                self._log("success", "VirusTotal API key saved and client initialized")
            except Exception as e:
                self._vt_status_lbl.configure(
                    text=f"Error: {e}", text_color=C["red"]
                )
                self._log("danger", f"VT client init failed: {e}")
        else:
            self._vt_client = None
            self._vt_status_lbl.configure(text="Not configured", text_color=C["text_dim"])

    def _on_vt_toggle(self):
        enabled = self._vt_toggle.get() == 1
        config.set("virustotal.enabled", enabled)
        self._log("info", f"VirusTotal checks {'enabled' if enabled else 'disabled'}")

    # ─── API Server handlers ─────────────────────────────────────────────────

    def _on_api_toggle(self):
        if self._api_server_running:
            self._stop_api_server()
        else:
            self._start_api_server()

    def _start_api_server(self):
        try:
            import uvicorn
            from api.main import app
        except ImportError:
            messagebox.showwarning("Missing Dependency",
                                   "FastAPI/uvicorn not installed.\nRun: pip install fastapi uvicorn")
            return

        host = self._api_host_var.get().strip() or "0.0.0.0"
        try:
            port = int(self._api_port_var.get().strip())
        except ValueError:
            messagebox.showwarning("Invalid Port", "Port must be a number.")
            return

        def run_server():
            try:
                import asyncio
                config.set("api.host", host)
                config.set("api.port", port)
                uvicorn.run(app, host=host, port=port, log_level="info")
            except Exception as e:
                self.after(0, lambda: self._on_api_error(str(e)))

        self._api_server_thread = threading.Thread(target=run_server, daemon=True)
        self._api_server_thread.start()
        self._api_server_running = True
        self._btn_api_toggle.configure(text="Stop Server", fg_color=C["red"],
                                       hover_color=C["danger"], text_color="#FFF")
        self._api_status_lbl.configure(
            text=f"Running at http://{host}:{port}", text_color=C["green"]
        )
        self._log("success", f"API server started at http://{host}:{port}")
        self._append_api_log(f"[INFO] Server started at http://{host}:{port}")

    def _stop_api_server(self):
        self._api_server_running = False
        self._btn_api_toggle.configure(text="Start Server", fg_color=C["green"],
                                      hover_color="#1EA34A", text_color=C["bg_dark"])
        self._api_status_lbl.configure(text="API server stopped", text_color=C["text_dim"])
        self._log("info", "API server stopped")
        self._append_api_log("[INFO] Server stopped")

    def _on_api_error(self, error: str):
        self._api_server_running = False
        self._btn_api_toggle.configure(text="Start Server", fg_color=C["green"],
                                      hover_color="#1EA34A", text_color=C["bg_dark"])
        self._api_status_lbl.configure(text=f"Error: {error}", text_color=C["red"])
        self._log("danger", f"API server error: {error}")
        self._append_api_log(f"[ERROR] {error}")

    def _append_api_log(self, message: str):
        self._api_log.configure(state="normal")
        self._api_log.insert("end", message + "\n")
        self._api_log.see("end")
        self._api_log.configure(state="disabled")

    # ═══════════════════════════════════════════════════════════════════════
    # QUARANTINE
    # ═══════════════════════════════════════════════════════════════════════

    def _refresh_quarantine(self):
        if not hasattr(self, "_quarantine_list"):
            return
        for child in self._quarantine_list.winfo_children():
            child.destroy()

        items = self._responder.get_quarantine_list()
        if not items:
            ctk.CTkLabel(
                self._quarantine_list, text="No quarantined files",
                font=("Consolas", 9), text_color=C["text_dim"]
            ).pack(pady=20)
            return

        for item in items:
            card = ctk.CTkFrame(self._quarantine_list, fg_color=C["bg_card"], corner_radius=6)
            card.pack(fill="x", pady=2)

            ctk.CTkLabel(card, text=os.path.basename(item["original_path"]),
                         font=("Consolas", 9), text_color=C["text"],
                         anchor="w", wraplength=500
                         ).pack(anchor="w", padx=8, pady=(6, 2))

            ctk.CTkLabel(card, text=f"  {item['reason']} — {item['timestamp']}",
                         font=("Consolas", 7), text_color=C["text_dim"]
                         ).pack(anchor="w", padx=8, pady=(0, 6))

            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=(0, 6))

            qid = item["id"]
            ctk.CTkButton(
                row, text="Restore", height=24,
                font=("Consolas", 8), text_color=C["green"],
                fg_color="transparent", hover_color=C["bg_card"],
                command=lambda i=item: self._restore_file(i)
            ).pack(side="left", padx=(0, 4))

            ctk.CTkButton(
                row, text="Delete", height=24,
                font=("Consolas", 8), text_color=C["red"],
                fg_color="transparent", hover_color=C["bg_card"],
                command=lambda i=item: self._delete_quarantined(i)
            ).pack(side="left")

    def _restore_file(self, item: Dict):
        success = self._responder.restore_file(item["id"])
        if success:
            self._log("success", f"File restored: {item['original_path']}")
        else:
            self._log("danger", f"Failed to restore: {item['original_path']}")
        self._refresh_quarantine()

    def _delete_quarantined(self, item: Dict):
        if messagebox.askyesno("Delete", f"Permanently delete this quarantined file?"):
            self._log("warning", f"Quarantined file deleted: {item['original_path']}")
            self._refresh_quarantine()

    # ═══════════════════════════════════════════════════════════════════════
    # REPORTS / EXPORT
    # ═══════════════════════════════════════════════════════════════════════

    def _export_csv(self):
        if not self._scan_results:
            messagebox.showinfo("No Data", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile="scan_results.csv"
        )
        if path:
            export_csv(self._scan_results, path)
            self._log("success", f"CSV exported: {path}")
            webbrowser.open(f"file:///{path}")

    def _export_png(self):
        if not self._scan_results:
            messagebox.showinfo("No Data", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG", "*.png")],
            initialfile="scan_report.png"
        )
        if path:
            elapsed = time.time() - self._scan_start_time if self._scan_start_time else 0
            export_report_png(self._scan_results, path,
                               scan_duration=float(elapsed))
            self._log("success", f"PNG chart exported: {path}")
            webbrowser.open(f"file:///{path}")

    def _export_forensic(self):
        if not self._scan_results:
            messagebox.showinfo("No Data", "Run a scan first.")
            return
        path = filedialog.askdirectory(title="Select output directory for forensic bundle")
        if path:
            bundle = export_forensic_bundle(self._scan_results, path)
            self._log("success", f"Forensic bundle: {bundle}")
            webbrowser.open(f"file:///{bundle}")

    # ═══════════════════════════════════════════════════════════════════════
    # STATUS & LOGGING
    # ═══════════════════════════════════════════════════════════════════════

    def _set_status(self, text: str, color: str):
        self._status_var.set(text)
        try:
            self._status_badge.configure(text_color=C["bg_dark"], color=color)
            self._status_badge._label.configure(text=text[:15])
        except Exception:
            pass

    def _log(self, level: str, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": "[INFO]", "success": "[OK]  ",
            "warning": "[WARN]", "danger": "[ALERT]",
            "system": "[SYS] "
        }.get(level, "[LOG] ")
        line = f"{ts}  {prefix}  {text}\n"

        self._log_lines.append(line)
        if len(self._log_lines) > self.LOG_MAX_LINES:
            self._log_lines = self._log_lines[-self.LOG_MAX_LINES:]

        if hasattr(self, "_log_text") and self._log_text.winfo_exists():
            try:
                self._log_text.configure(state="normal")
                self._log_text.insert("end", line, level)
                self._log_text.see("end")
                self._log_text.configure(state="disabled")
            except Exception:
                pass

    def _clear_logs(self):
        self._log_lines.clear()
        if hasattr(self, "_log_text"):
            self._log_text.configure(state="normal")
            self._log_text.delete("1.0", "end")
            self._log_text.configure(state="disabled")

    # ═══════════════════════════════════════════════════════════════════════
    # NEW TABS — Office Scanner, Entropy Watch, Honeypot, ML Training
    # ═══════════════════════════════════════════════════════════════════════

    def _build_office_scanner_page(self):
        page = OfficeScannerTab(self._page_container)
        page.grid(row=0, column=0, sticky="nsew")
        self._pages.append(page)
        self._office_scanner_tab = page

    def _build_entropy_watch_page(self):
        page = EntropyWatchTab(self._page_container)
        page.grid(row=0, column=0, sticky="nsew")
        self._pages.append(page)
        self._entropy_watch_tab = page
        # Wire entropy events from monitor to tab
        if hasattr(self, "_monitor") and self._monitor:
            def _on_entropy_entry(file_path, entropy):
                ts = datetime.now().strftime("%H:%M:%S")
                self.after(0, lambda fp=file_path, e=entropy, t=ts:
                          self._entropy_watch_tab.add_entropy_entry(fp, e, t))
            self._monitor.on_entropy_alert = _on_entropy_entry

    def _build_honeypot_page(self):
        page = HoneypotTab(self._page_container)
        page.grid(row=0, column=0, sticky="nsew")
        self._pages.append(page)
        self._honeypot_tab = page
        # Inject honeypot manager when available
        if hasattr(self, "_honeypot_manager") and self._honeypot_manager:
            page.set_honeypot_manager(self._honeypot_manager)

    def _build_ml_training_page(self):
        page = MLTrainingTab(self._page_container)
        page.grid(row=0, column=0, sticky="nsew")
        self._pages.append(page)
        self._ml_training_tab = page
        # Inject ML engine
        if hasattr(self, "_engine") and self._engine:
            page.set_ml_engine(self._engine)

    def _show_office_scanner(self):
        self._show_page(7)

    def _show_entropy_watch(self):
        self._show_page(8)

    def _show_honeypot(self):
        self._show_page(9)

    def _show_ml_training(self):
        self._show_page(10)

    # ─── Wire new tabs after init ──────────────────────────────────────────

    def _wire_new_modules(self):
        """Called from __init__ after all modules are loaded."""
        if hasattr(self, "_honeypot_manager") and hasattr(self, "_honeypot_tab"):
            self._honeypot_tab.set_honeypot_manager(self._honeypot_manager)
        if hasattr(self, "_engine") and hasattr(self, "_ml_training_tab"):
            self._ml_training_tab.set_ml_engine(self._engine)

    # ═══════════════════════════════════════════════════════════════════════
    # TRAY
    # ═══════════════════════════════════════════════════════════════════════

    def _minimize_to_tray(self):
        if hasattr(self, "_tray_manager") and self._tray_manager is not None:
            self._tray_manager.minimize_to_tray()
        else:
            self.withdraw()

    def restore_from_tray(self):
        self.deiconify()
        self.lift()
        self.focus()

    # ═══════════════════════════════════════════════════════════════════════
    # CLOSING
    # ═══════════════════════════════════════════════════════════════════════

    def on_closing(self):
        if hasattr(self, "_monitor") and self._monitor.is_running:
            self._monitor.stop()
        if hasattr(self, "_tray_manager") and self._tray_manager is not None:
            self._tray_manager.minimize_to_tray()
            return
        if hasattr(self, "_poll_id"):
            self.after_cancel(self._poll_id)
        self.destroy()


# ════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════

# ─── Backward-compat alias (old name) ──────────────────────────────────────
RansomwareDetectorApp = MainWindow


def launch():
    app = MainWindow()
    app.mainloop()


if __name__ == "__main__":
    launch()
