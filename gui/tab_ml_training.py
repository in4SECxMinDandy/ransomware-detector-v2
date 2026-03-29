"""
gui/tab_ml_training.py
======================
ML Training & Feedback Loop tab — CustomTkinter.

Features:
  - Feedback statistics (FP/FN counts)
  - Accuracy history chart
  - Model versions table with rollback
  - Retrain button with progress
  - ML model info display
"""

import threading
from typing import List, Dict, Any
from datetime import datetime

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


class MLTrainingTab(ctk.CTkFrame):
    """
    Tab for ML model feedback loop and retraining.
    Designed to be embedded inside MainWindow._build_page_container().
    """

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=C["bg_dark"], **kwargs)

        self._ml_engine = None
        self._is_retraining = False
        self._accuracy_dates: List[str] = []
        self._accuracy_values: List[float] = []

        self._setup_ui()
        self._refresh()

    def _setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        # ── Title ───────────────────────────────────────────────────────────────
        title = ctk.CTkLabel(
            self, text="ML Incremental Learning",
            font=("Consolas", 14, "bold"), text_color=C["accent"]
        )
        title.grid(row=0, column=0, sticky="w", padx=12, pady=(12, 4))

        subtitle = ctk.CTkLabel(
            self,
            text="Feedback loop — mark detections as Correct/Incorrect to improve model accuracy over time",
            font=("Consolas", 8), text_color=C["text_dim"], wraplength=700
        )
        subtitle.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 8))

        # ── Stats row ──────────────────────────────────────────────────────────
        stats_card = ctk.CTkFrame(self, fg_color=C["bg_card"], corner_radius=8,
                                  border_width=1, border_color=C["border"])
        stats_card.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))
        stats_card.grid_columnconfigure(0, weight=1)
        stats_card.grid_columnconfigure(1, weight=1)
        stats_card.grid_columnconfigure(2, weight=1)
        stats_card.grid_columnconfigure(3, weight=1)
        stats_card.grid_columnconfigure(4, weight=1)

        self._fp_lbl = ctk.CTkLabel(
            stats_card, text="False Positives: 0",
            font=("Consolas", 10, "bold"), text_color=C["yellow"]
        )
        self._fp_lbl.grid(row=0, column=0, padx=8, pady=12)

        self._fn_lbl = ctk.CTkLabel(
            stats_card, text="False Negatives: 0",
            font=("Consolas", 10, "bold"), text_color=C["red"]
        )
        self._fn_lbl.grid(row=0, column=1, padx=8, pady=12)

        self._total_lbl = ctk.CTkLabel(
            stats_card, text="Total: 0",
            font=("Consolas", 10, "bold"), text_color=C["text"]
        )
        self._total_lbl.grid(row=0, column=2, padx=8, pady=12)

        self._last_lbl = ctk.CTkLabel(
            stats_card, text="Last: -",
            font=("Consolas", 9), text_color=C["text_dim"]
        )
        self._last_lbl.grid(row=0, column=3, padx=8, pady=12)

        self._auto_toggle = ctk.CTkSwitch(
            stats_card, text="Auto-retrain",
            font=("Consolas", 9), text_color=C["text_dim"],
            progress_color=C["accent"], fg_color=C["border"],
            command=self._on_auto_toggle
        )
        self._auto_toggle.grid(row=0, column=4, padx=8, pady=12, sticky="e")

        # ── Accuracy chart + info row ───────────────────────────────────────────
        chart_card = ctk.CTkFrame(self, fg_color=C["bg_card"], corner_radius=8,
                                  border_width=1, border_color=C["border"])
        chart_card.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 8))
        chart_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            chart_card, text="Model Accuracy History",
            font=("Consolas", 10, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        from gui.components.plot_frame import PlotFrame
        self._accuracy_chart = PlotFrame(chart_card, figsize=(10, 3))
        self._accuracy_chart.plot_feedback_history([], [])
        self._accuracy_chart.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 8))

        # ── Info + Actions row ─────────────────────────────────────────────────
        info_row = ctk.CTkFrame(self, fg_color="transparent")
        info_row.grid(row=4, column=0, sticky="nsew", padx=12, pady=(0, 8))
        info_row.grid_columnconfigure(0, weight=1)
        info_row.grid_columnconfigure(1, weight=0)
        info_row.grid_rowconfigure(0, weight=1)

        # Model info card
        model_card = ctk.CTkFrame(info_row, fg_color=C["bg_card"], corner_radius=8,
                                  border_width=1, border_color=C["border"])
        model_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        ctk.CTkLabel(
            model_card, text="Current Model",
            font=("Consolas", 11, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        self._model_info_lbl = ctk.CTkLabel(
            model_card,
            text="Version: -\nAccuracy: -\nThreshold: -\nPrecision: -\nRecall: -",
            font=("Cascadia Code", 10), text_color=C["text"],
            justify="left", anchor="nw"
        )
        self._model_info_lbl.grid(row=1, column=0, sticky="nw", padx=12, pady=(0, 12))

        # Model versions table
        versions_card = ctk.CTkFrame(model_card, fg_color=C["bg_dark"], corner_radius=6,
                                     border_width=1, border_color=C["border"])
        versions_card.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))
        versions_card.grid_columnconfigure(0, weight=1)
        versions_card.grid_rowconfigure(2, weight=1)
        model_card.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(
            versions_card, text="Model Versions",
            font=("Consolas", 10, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(8, 4))

        # Versions header
        v_header = ctk.CTkFrame(versions_card, fg_color=C["bg_panel"], height=26)
        v_header.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 1))
        v_header.pack_propagate(False)

        v_col_widths = [160, 140, 80, 80, 80]
        v_col_labels = ["Version", "Created At", "Accuracy", "Precision", "Samples"]
        for i, (w, lbl) in enumerate(zip(v_col_widths, v_col_labels)):
            f = ctk.CTkFrame(v_header, width=w, fg_color="transparent")
            f.pack(side="left", padx=2, fill="y", expand=True)
            f.pack_propagate(False)
            ctk.CTkLabel(f, text=lbl, font=("Consolas", 8, "bold"),
                        text_color=C["text_dim"]).pack(pady=3)

        self._versions_container = ctk.CTkScrollableFrame(
            versions_card, fg_color="transparent",
            scrollbar_button_color=C["border"],
            height=130
        )
        self._versions_container.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))

        ctk.CTkLabel(
            self._versions_container, text="No model versions yet",
            font=("Consolas", 9), text_color=C["text_dim"]
        ).grid(row=0, column=0, pady=10)

        self._version_rows: List[ctk.CTkFrame] = []

        # Actions card
        actions_card = ctk.CTkFrame(info_row, fg_color=C["bg_card"], corner_radius=8,
                                    border_width=1, border_color=C["border"])
        actions_card.grid(row=0, column=1, sticky="ns")

        ctk.CTkLabel(
            actions_card, text="Actions",
            font=("Consolas", 11, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 8), columnspan=2)

        self._btn_retrain = ctk.CTkButton(
            actions_card, text="Retrain Now", height=40,
            font=("Consolas", 10, "bold"), fg_color=C["accent"],
            hover_color="#2563EB", text_color="#FFF",
            command=self._on_retrain
        )
        self._btn_retrain.grid(row=1, column=0, padx=12, pady=(0, 8), sticky="ew", columnspan=2)

        self._btn_rollback = ctk.CTkButton(
            actions_card, text="Rollback Version", height=36,
            font=("Consolas", 10), fg_color=C["bg_card"],
            hover_color=C["border"], text_color=C["text"],
            command=self._on_rollback
        )
        self._btn_rollback.grid(row=2, column=0, padx=12, pady=(0, 8), sticky="ew", columnspan=2)

        self._btn_clear_old = ctk.CTkButton(
            actions_card, text="Delete Old Versions", height=36,
            font=("Consolas", 10), fg_color=C["bg_card"],
            hover_color=C["border"], text_color=C["text"],
            command=self._on_delete_old
        )
        self._btn_clear_old.grid(row=3, column=0, padx=12, pady=(0, 8), sticky="ew", columnspan=2)

        ctk.CTkLabel(
            actions_card, text="",
            font=("Consolas", 1)
        ).grid(row=4, column=0, pady=0)

        # Progress bar
        self._retrain_progress = ctk.CTkProgressBar(
            actions_card, height=10,
            progress_color=C["green"], fg_color=C["border"]
        )
        self._retrain_progress.grid(row=5, column=0, padx=12, pady=(0, 8), sticky="ew", columnspan=2)
        self._retrain_progress.set(0)

        self._progress_lbl = ctk.CTkLabel(
            actions_card, text="",
            font=("Consolas", 8), text_color=C["text_dim"]
        )
        self._progress_lbl.grid(row=6, column=0, padx=12, pady=(0, 8), sticky="w", columnspan=2)

        # ── Training log ───────────────────────────────────────────────────────
        log_card = ctk.CTkFrame(self, fg_color=C["bg_card"], corner_radius=8,
                                border_width=1, border_color=C["border"])
        log_card.grid(row=5, column=0, sticky="ew", padx=12, pady=(0, 8))
        log_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            log_card, text="Training Log",
            font=("Consolas", 10, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        self._log_text = ctk.CTkTextbox(
            log_card, font=("Cascadia Code", 9),
            fg_color=C["bg_dark"], text_color=C["text"],
            border_color=C["border"], border_width=1,
            scrollbar_button_color=C["border"],
            wrap="word", height=80
        )
        self._log_text.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 8))
        self._log_text.configure(state="disabled")

        self._log("[SYS] ML Training tab initialized")

    def _log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._log_text.configure(state="normal")
        self._log_text.insert("end", f"[{timestamp}] {message}\n")
        self._log_text.see("end")
        self._log_text.configure(state="disabled")

    def set_ml_engine(self, engine):
        """Inject ML engine from main window."""
        self._ml_engine = engine
        self._refresh()

    def _refresh(self):
        if not self._ml_engine:
            return
        try:
            # Feedback stats
            stats = self._ml_engine.get_feedback_stats()
            self._fp_lbl.configure(text=f"False Positives: {stats.get('false_positive', 0)}")
            self._fn_lbl.configure(text=f"False Negatives: {stats.get('false_negative', 0)}")
            self._total_lbl.configure(text=f"Total: {stats.get('total', 0)}")
            self._last_lbl.configure(text=f"Last: {stats.get('last_feedback', '-')}")

            # Model info
            info = self._ml_engine.get_model_info()
            info_text = (
                f"Version: {info.get('version', 'unknown')}\n"
                f"Accuracy: {info.get('accuracy', 0):.2%}\n"
                f"Threshold: {info.get('current_threshold', 0):.2f}\n"
                f"Precision: {info.get('precision', 0):.2%}\n"
                f"Recall: {info.get('recall', 0):.2%}"
            )
            self._model_info_lbl.configure(text=info_text)

            # Accuracy history
            versions = self._ml_engine.get_model_versions()
            dates = []
            accs = []
            for v in versions:
                created = v.get("created_at", "")
                if "T" in created:
                    created = created.split("T")[0]
                dates.append(created)
                acc = v.get("accuracy", 0)
                if isinstance(acc, float):
                    accs.append(acc)
                else:
                    accs.append(0.0)
            self._accuracy_chart.plot_feedback_history(dates, accs)

            # Versions table
            self._refresh_versions(versions)

        except Exception as e:
            self._log(f"Refresh error: {e}")

    def _refresh_versions(self, versions: List[Dict]):
        for row in self._version_rows:
            row.destroy()
        self._version_rows.clear()
        for w in self._versions_container.grid_slaves():
            if isinstance(w, ctk.CTkLabel) and "No model" in w.cget("text"):
                w.destroy()

        if not versions:
            ctk.CTkLabel(
                self._versions_container, text="No model versions yet",
                font=("Consolas", 9), text_color=C["text_dim"]
            ).grid(row=0, column=0, pady=10)
            return

        for row_idx, v in enumerate(versions):
            row = ctk.CTkFrame(self._versions_container, fg_color=C["bg_card"],
                              border_width=1, border_color=C["border"],
                              height=28)
            row.pack(fill="x", padx=4, pady=1)
            row.pack_propagate(False)

            created = v.get("created_at", "")
            if "T" in created:
                created = created.split("T")[0]
            acc = v.get("accuracy", 0)
            prec = v.get("precision", 0)

            ctk.CTkLabel(row, text=str(v.get("version", ""))[:22],
                        font=("Consolas", 8), text_color=C["text"]
                        ).grid(row=0, column=0, sticky="w", padx=8, pady=3)
            ctk.CTkLabel(row, text=created,
                        font=("Consolas", 8), text_color=C["text_dim"]
                        ).grid(row=0, column=1, sticky="w", padx=8, pady=3)
            ctk.CTkLabel(row, text=f"{acc:.2%}" if acc else "-",
                        font=("Consolas", 8), text_color=C["green"]
                        ).grid(row=0, column=2, sticky="w", padx=8, pady=3)
            ctk.CTkLabel(row, text=f"{prec:.2%}" if prec else "-",
                        font=("Consolas", 8), text_color=C["blue"]
                        ).grid(row=0, column=3, sticky="w", padx=8, pady=3)
            ctk.CTkLabel(row, text=str(v.get("sample_count", 0)),
                        font=("Consolas", 8), text_color=C["text_dim"]
                        ).grid(row=0, column=4, sticky="w", padx=(8, 12), pady=3)

            # Highlight active
            if v.get("is_active"):
                row.configure(border_color=C["accent"], border_width=1)

            self._version_rows.append(row)

    # ─── Actions ───────────────────────────────────────────────────────────────

    def _on_retrain(self):
        if self._is_retraining:
            return

        if not self._ml_engine:
            messagebox.showwarning("Error", "ML engine not available")
            return

        stats = self._ml_engine.get_feedback_stats()
        total = stats.get("total", 0)
        if total < 10:
            messagebox.showwarning(
                "Insufficient Data",
                f"Need at least 10 feedback samples to retrain.\nCurrently have: {total}"
            )
            return

        reply = messagebox.askyesno(
            "Retrain Model",
            f"Retrain model with {total} feedback samples?\nThis may take a few minutes."
        )
        if not reply:
            return

        self._is_retraining = True
        self._btn_retrain.configure(state="disabled", text="Training...")
        self._retrain_progress.set(0)
        self._progress_lbl.configure(text="Starting retrain...")
        self._log("Retraining started...")

        def retrain_worker():
            try:
                result = self._ml_engine.retrain_with_feedback()
                self.after(0, lambda: self._on_retrain_done(result))
            except Exception as e:
                self.after(0, lambda: self._on_retrain_error(str(e)))

        threading.Thread(target=retrain_worker, daemon=True).start()

    def _on_retrain_done(self, result: Dict[str, Any]):
        self._is_retraining = False
        self._btn_retrain.configure(state="normal", text="Retrain Now")
        self._retrain_progress.set(0)
        self._progress_lbl.configure(text="")

        if result.get("success"):
            self._log("Retrain successful!")
            self._log(f"  Version: {result.get('new_model_version')}")
            self._log(f"  Samples: {result.get('samples_used')}")
            self._log(f"  Time: {result.get('training_time_seconds')}s")
            messagebox.showinfo(
                "Retrain Complete",
                f"Model retrained successfully!\n"
                f"Version: {result.get('new_model_version')}\n"
                f"Samples: {result.get('samples_used')}"
            )
        else:
            self._log(f"Retrain failed: {result.get('error')}")
            messagebox.showerror("Retrain Failed", result.get("error"))

        self._refresh()

    def _on_retrain_error(self, error: str):
        self._is_retraining = False
        self._btn_retrain.configure(state="normal", text="Retrain Now")
        self._retrain_progress.set(0)
        self._progress_lbl.configure(text="")
        self._log(f"Retrain error: {error}")
        messagebox.showerror("Retrain Error", error)

    def _on_rollback(self):
        if not hasattr(self, "_selected_version"):
            messagebox.showwarning("Select Version", "Please select a model version to rollback to")
            return

        version = getattr(self, "_selected_version", None)
        if not version:
            messagebox.showwarning("Select Version", "Please select a model version to rollback to")
            return

        reply = messagebox.askyesno("Rollback", f"Rollback to version {version}?")
        if not reply:
            return

        try:
            success = self._ml_engine.rollback_model(version)
            if success:
                self._log(f"Rolled back to {version}")
                messagebox.showinfo("Rollback", f"Rolled back to {version}")
            else:
                messagebox.showerror("Rollback", "Rollback failed")
        except Exception as e:
            messagebox.showerror("Rollback Error", str(e))

        self._refresh()

    def _on_delete_old(self):
        reply = messagebox.askyesno(
            "Delete Old Versions",
            "Delete all model versions except the active one?"
        )
        if reply:
            self._log("Delete old versions requested (not yet implemented)")

    def _on_auto_toggle(self):
        try:
            from core.config_manager import config
            enabled = self._auto_toggle.get() == 1
            config.set("ml_feedback.auto_retrain_enabled", enabled)
        except Exception:
            pass

    def add_feedback(self, sha256: str, features, predicted_label: str,
                     feedback_label: str, feedback_type: str):
        """Add a feedback sample (called from main window scan results)."""
        if not self._ml_engine:
            return
        try:
            self._ml_engine.add_feedback_sample(
                sha256, features, predicted_label, feedback_label, feedback_type
            )
            self._refresh()
            self._log(f"Feedback: {feedback_type} — {predicted_label} -> {feedback_label}")
        except Exception as e:
            self._log(f"Feedback error: {e}")
