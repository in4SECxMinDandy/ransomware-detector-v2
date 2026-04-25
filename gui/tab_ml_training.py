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
        self._source_plan: Dict[str, Any] | None = None

        self._setup_ui()
        self._refresh()

    def _setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        # ── Title ───────────────────────────────────────────────────────────────
        title = ctk.CTkLabel(
            self, text="Học tăng cường cho ML",
            font=("Consolas", 14, "bold"), text_color=C["accent"]
        )
        title.grid(row=0, column=0, sticky="w", padx=12, pady=(12, 4))

        subtitle = ctk.CTkLabel(
            self,
            text="Vòng lặp feedback - đánh dấu kết quả đúng/sai để cải thiện độ chính xác của model theo thời gian",
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
            stats_card, text="False Positive: 0",
            font=("Consolas", 10, "bold"), text_color=C["yellow"]
        )
        self._fp_lbl.grid(row=0, column=0, padx=8, pady=12)

        self._fn_lbl = ctk.CTkLabel(
            stats_card, text="False Negative: 0",
            font=("Consolas", 10, "bold"), text_color=C["red"]
        )
        self._fn_lbl.grid(row=0, column=1, padx=8, pady=12)

        self._total_lbl = ctk.CTkLabel(
            stats_card, text="Tổng: 0",
            font=("Consolas", 10, "bold"), text_color=C["text"]
        )
        self._total_lbl.grid(row=0, column=2, padx=8, pady=12)

        self._last_lbl = ctk.CTkLabel(
            stats_card, text="Lần cuối: -",
            font=("Consolas", 9), text_color=C["text_dim"]
        )
        self._last_lbl.grid(row=0, column=3, padx=8, pady=12)

        self._auto_toggle = ctk.CTkSwitch(
            stats_card, text="Tự retrain",
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
            chart_card, text="Lịch sử Accuracy của model",
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
            model_card, text="Model hiện tại",
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
            versions_card, text="Các version của model",
            font=("Consolas", 10, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(8, 4))

        # Versions header
        v_header = ctk.CTkFrame(versions_card, fg_color=C["bg_panel"], height=26)
        v_header.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 1))
        v_header.pack_propagate(False)

        v_col_widths = [160, 140, 80, 80, 80]
        v_col_labels = ["Version", "Tạo lúc", "Accuracy", "Precision", "Mẫu"]
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
            self._versions_container, text="Chưa có version model nào",
            font=("Consolas", 9), text_color=C["text_dim"]
        ).grid(row=0, column=0, pady=10)

        self._version_rows: List[ctk.CTkFrame] = []

        # Actions card
        actions_card = ctk.CTkFrame(info_row, fg_color=C["bg_card"], corner_radius=8,
                                    border_width=1, border_color=C["border"])
        actions_card.grid(row=0, column=1, sticky="ns")

        ctk.CTkLabel(
            actions_card, text="Thao tác",
            font=("Consolas", 11, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 8), columnspan=2)

        self._btn_retrain = ctk.CTkButton(
            actions_card, text="Retrain model", height=40,
            font=("Consolas", 10, "bold"), fg_color=C["accent"],
            hover_color="#2563EB", text_color="#FFF",
            command=self._on_auto_retrain
        )
        self._btn_retrain.grid(row=1, column=0, padx=12, pady=(0, 8), sticky="ew", columnspan=2)

        ctk.CTkLabel(
            actions_card,
            text="Sử dụng feedback, quarantine, Honeypot và lịch sử quét.",
            font=("Consolas", 8),
            text_color=C["text_dim"],
            wraplength=220,
            justify="left",
        ).grid(row=2, column=0, padx=12, pady=(0, 8), sticky="w", columnspan=2)

        self._btn_rollback = ctk.CTkButton(
            actions_card, text="Rollback version", height=36,
            font=("Consolas", 10), fg_color=C["bg_card"],
            hover_color=C["border"], text_color=C["text"],
            command=self._on_rollback
        )
        self._btn_rollback.grid(row=3, column=0, padx=12, pady=(0, 8), sticky="ew", columnspan=2)

        self._btn_clear_old = ctk.CTkButton(
            actions_card, text="Xóa version cũ", height=36,
            font=("Consolas", 10), fg_color=C["bg_card"],
            hover_color=C["border"], text_color=C["text"],
            command=self._on_delete_old
        )
        self._btn_clear_old.grid(row=4, column=0, padx=12, pady=(0, 8), sticky="ew", columnspan=2)

        ctk.CTkLabel(
            actions_card, text="",
            font=("Consolas", 1)
        ).grid(row=5, column=0, pady=0)

        # Progress bar
        self._retrain_progress = ctk.CTkProgressBar(
            actions_card, height=10,
            progress_color=C["green"], fg_color=C["border"]
        )
        self._retrain_progress.grid(row=6, column=0, padx=12, pady=(0, 8), sticky="ew", columnspan=2)
        self._retrain_progress.set(0)

        self._progress_lbl = ctk.CTkLabel(
            actions_card, text="",
            font=("Consolas", 8), text_color=C["text_dim"]
        )
        self._progress_lbl.grid(row=7, column=0, padx=12, pady=(0, 8), sticky="w", columnspan=2)

        source_card = ctk.CTkFrame(self, fg_color=C["bg_card"], corner_radius=8,
                                   border_width=1, border_color=C["border"])
        source_card.grid(row=5, column=0, sticky="ew", padx=12, pady=(0, 8))
        source_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            source_card, text="Nguồn training",
            font=("Consolas", 10, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        source_controls = ctk.CTkFrame(source_card, fg_color="transparent")
        source_controls.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 8))

        self._source_kind_var = ctk.StringVar(value="both")
        self._source_scale_var = ctk.StringVar(value="pilot")

        ctk.CTkLabel(source_controls, text="Loại",
                     font=("Consolas", 8), text_color=C["text_dim"]).pack(side="left", padx=(0, 4))
        self._source_kind_menu = ctk.CTkOptionMenu(
            source_controls, values=["both", "safe", "encrypted"],
            variable=self._source_kind_var, width=110,
            command=self._on_source_selection_change,
        )
        self._source_kind_menu.pack(side="left", padx=(0, 8))

        ctk.CTkLabel(source_controls, text="Quy mô",
                     font=("Consolas", 8), text_color=C["text_dim"]).pack(side="left", padx=(0, 4))
        self._source_scale_menu = ctk.CTkOptionMenu(
            source_controls, values=["smoke", "pilot", "production"],
            variable=self._source_scale_var, width=110,
            command=self._on_source_selection_change,
        )
        self._source_scale_menu.pack(side="left", padx=(0, 8))

        self._btn_source_plan = ctk.CTkButton(
            source_controls, text="Tạo plan", height=28,
            font=("Consolas", 9, "bold"), fg_color=C["accent"],
            hover_color="#2563EB", command=self._on_create_source_plan
        )
        self._btn_source_plan.pack(side="left", padx=(0, 6))

        self._btn_source_prepare = ctk.CTkButton(
            source_controls, text="Tải / Chuẩn bị", height=28,
            font=("Consolas", 9), fg_color=C["bg_panel"],
            hover_color=C["border"], command=self._on_source_prepare
        )
        self._btn_source_prepare.pack(side="left", padx=(0, 6))

        self._btn_source_train = ctk.CTkButton(
            source_controls, text="Train từ plan", height=28,
            font=("Consolas", 9), fg_color=C["bg_panel"],
            hover_color=C["border"], command=self._on_source_train
        )
        self._btn_source_train.pack(side="left")

        self._source_text = ctk.CTkTextbox(
            source_card, font=("Cascadia Code", 8),
            fg_color=C["bg_dark"], text_color=C["text"],
            border_color=C["border"], border_width=1,
            scrollbar_button_color=C["border"],
            wrap="word", height=120
        )
        self._source_text.grid(row=2, column=0, sticky="ew", padx=8, pady=(0, 8))
        self._source_text.configure(state="disabled")

        # ── Training log ───────────────────────────────────────────────────────
        log_card = ctk.CTkFrame(self, fg_color=C["bg_card"], corner_radius=8,
                                border_width=1, border_color=C["border"])
        log_card.grid(row=6, column=0, sticky="ew", padx=12, pady=(0, 8))
        log_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            log_card, text="Nhật ký training",
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

        self._log("[SYS] Đã khởi tạo tab ML Training")
        self._refresh_source_matches()

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
        self._refresh_source_matches()

    def _refresh(self):
        if not self._ml_engine:
            return
        try:
            # Feedback stats
            stats = self._ml_engine.get_feedback_stats()
            self._fp_lbl.configure(text=f"False Positive: {stats.get('false_positive', 0)}")
            self._fn_lbl.configure(text=f"False Negative: {stats.get('false_negative', 0)}")
            self._total_lbl.configure(text=f"Tổng: {stats.get('total', 0)}")
            self._last_lbl.configure(text=f"Lần cuối: {stats.get('last_feedback', '-')}")

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
            self._log(f"Lỗi làm mới: {e}")

    def _set_source_text(self, text: str):
        self._source_text.configure(state="normal")
        self._source_text.delete("1.0", "end")
        self._source_text.insert("end", text)
        self._source_text.configure(state="disabled")

    def _refresh_source_matches(self):
        try:
            from core.training_source_registry import render_training_sources

            text = render_training_sources(
                kind=self._source_kind_var.get(),
                pe_only=True,
            )
            self._set_source_text(text)
        except Exception as e:
            self._set_source_text(f"Không thể tải nguồn dữ liệu: {e}")

    def _on_source_selection_change(self, _value: str):
        self._source_plan = None
        self._refresh_source_matches()

    def _build_current_source_plan(self) -> bool:
        try:
            from core.training_source_planner import build_training_source_plan, render_training_plan

            self._source_plan = build_training_source_plan(
                kind=self._source_kind_var.get(),
                pe_only=True,
                scale=self._source_scale_var.get(),
            )
            self._set_source_text(render_training_plan(self._source_plan))
            return True
        except Exception as e:
            self._source_plan = None
            self._log(f"Lỗi source plan: {e}")
            messagebox.showerror("Lỗi source plan", str(e))
            return False

    def _on_create_source_plan(self):
        if self._build_current_source_plan():
            self._log(
                f"Đã tạo source plan: kind={self._source_kind_var.get()} scale={self._source_scale_var.get()}"
            )

    def _refresh_versions(self, versions: List[Dict]):
        for row in self._version_rows:
            row.destroy()
        self._version_rows.clear()
        for w in self._versions_container.grid_slaves():
            if isinstance(w, ctk.CTkLabel) and "Chưa có version model nào" in w.cget("text"):
                w.destroy()

        if not versions:
            ctk.CTkLabel(
                self._versions_container, text="Chưa có version model nào",
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
        """Compatibility wrapper for older bindings; use the unified flow."""
        self._on_auto_retrain()

    def _on_auto_retrain(self):
        if self._is_retraining:
            return

        if not self._ml_engine:
            messagebox.showwarning("Lỗi", "ML engine chưa sẵn sàng")
            return

        reply = messagebox.askyesno(
            "Retrain model",
            "Tạo dataset độ tin cậy cao từ feedback, quarantine, Honeypot và lịch sử quét,\n"
            "sau đó retrain model?\nViệc này có thể mất vài phút."
        )
        if not reply:
            return

        self._is_retraining = True
        self._btn_retrain.configure(state="disabled", text="Đang tạo dataset...")
        self._retrain_progress.set(0)
        self._progress_lbl.configure(text="Đang tạo dataset tự gán nhãn...")
        self._log("Đã bắt đầu tạo dataset tự động và retrain...")

        def auto_retrain_worker():
            try:
                result = self._ml_engine.retrain_with_auto_dataset()
                self.after(0, lambda: self._on_auto_retrain_done(result))
            except Exception as exc:
                # Snapshot the message before the lambda runs on the Tk
                # main thread — Python 3 deletes ``exc`` once we leave
                # the except block, which would otherwise raise NameError
                # inside the closure.
                err_msg = str(exc)
                self.after(0, lambda msg=err_msg: self._on_retrain_error(msg))

        threading.Thread(target=auto_retrain_worker, daemon=True).start()

    def _on_auto_retrain_done(self, result: Dict[str, Any]):
        self._is_retraining = False
        self._btn_retrain.configure(state="normal", text="Retrain model")
        self._retrain_progress.set(0)
        self._progress_lbl.configure(text="")

        if result.get("success"):
            counts = result.get("class_counts", {})
            self._log("Auto retrain thành công!")
            self._log(f"  Version: {result.get('new_model_version')}")
            self._log(f"  Auto samples: {result.get('auto_samples_used')}")
            self._log(f"  SAFE/ENC: {counts.get('SAFE', 0)}/{counts.get('ENCRYPTED', 0)}")
            self._log(f"  Dataset: {result.get('dataset_path')}")
            messagebox.showinfo(
                "Hoàn tất auto retrain",
                f"Đã retrain model thành công!\n"
                f"Version: {result.get('new_model_version')}\n"
                f"Auto samples: {result.get('auto_samples_used')}\n"
                f"SAFE/ENCRYPTED: {counts.get('SAFE', 0)}/{counts.get('ENCRYPTED', 0)}"
            )
        else:
            self._log(f"Auto retrain thất bại: {result.get('error')}")
            messagebox.showerror("Auto retrain thất bại", result.get("error"))

        self._refresh()

    def _on_source_prepare(self):
        if self._is_retraining:
            return
        if not self._build_current_source_plan():
            return

        reply = messagebox.askyesno(
            "Tải / Chuẩn bị nguồn",
            "Tạo manifest và chuẩn bị các thư mục nguồn trong plan đang có sẵn tệp?"
        )
        if not reply:
            return

        self._is_retraining = True
        self._btn_source_prepare.configure(state="disabled", text="Đang chuẩn bị...")
        self._btn_source_train.configure(state="disabled")
        self._btn_source_plan.configure(state="disabled")
        self._retrain_progress.set(0)
        self._progress_lbl.configure(text="Đang tạo manifest và chuẩn bị nguồn...")

        def worker():
            try:
                from core.training_source_planner import prepare_training_source

                entries = self._source_plan["safe_sources"] + self._source_plan["encrypted_sources"]
                results = []
                total = max(len(entries), 1)
                for idx, entry in enumerate(entries, start=1):
                    results.append(
                        prepare_training_source(
                            source_id=entry["id"],
                            kind=entry["kind"],
                            scale=self._source_plan["scale"],
                        )
                    )
                    self.after(0, lambda value=idx / total: self._retrain_progress.set(value))
                self.after(0, lambda: self._on_source_prepare_done(results))
            except Exception as exc:
                err_msg = str(exc)
                self.after(0, lambda msg=err_msg: self._on_retrain_error(msg))

        threading.Thread(target=worker, daemon=True).start()

    def _on_source_prepare_done(self, results: List[Dict[str, Any]]):
        self._is_retraining = False
        self._btn_source_prepare.configure(state="normal", text="Tải / Chuẩn bị")
        self._btn_source_train.configure(state="normal")
        self._btn_source_plan.configure(state="normal")
        self._progress_lbl.configure(text="")
        self._retrain_progress.set(0)

        lines = []
        manual = 0
        prepared = 0
        for result in results:
            if result.get("status") == "manual-acquire-required":
                manual += 1
                lines.append(
                    f"[MANUAL] {result.get('source_dir')} -> {result.get('manifest_path')}"
                )
            else:
                prepared += 1
                prep = result.get("prepare_result", {})
                lines.append(
                    f"[PREPARED] {result['source']['id']}: copied={prep.get('copied', 0)} "
                    f"non_pe={prep.get('non_pe_skipped', 0)} dup={prep.get('duplicate_skipped', 0)}"
                )

        self._set_source_text("\n".join(lines) if lines else "Không có kết quả chuẩn bị nguồn.")
        self._log(f"Đã chuẩn bị nguồn xong: prepared={prepared}, manual={manual}")
        if manual:
            messagebox.showwarning(
                "Cần lấy thủ công",
                f"Vẫn còn {manual} nguồn cần lấy thủ công. Hãy kiểm tra manifest và thư mục nguồn."
            )
        else:
            messagebox.showinfo("Chuẩn bị nguồn", "Tất cả nguồn trong plan đã được chuẩn bị thành công.")

    def _on_source_train(self):
        if self._is_retraining:
            return
        if not self._build_current_source_plan():
            return

        reply = messagebox.askyesno(
            "Train từ plan",
            "Chuẩn bị các nguồn trong plan nếu cần và train từ source plan mặc định?"
        )
        if not reply:
            return

        self._is_retraining = True
        self._btn_source_train.configure(state="disabled", text="Đang training...")
        self._btn_source_prepare.configure(state="disabled")
        self._btn_source_plan.configure(state="disabled")
        self._retrain_progress.set(0.1)
        self._progress_lbl.configure(text="Đang chuẩn bị nguồn và training...")

        def worker():
            try:
                from core.training_source_planner import render_training_plan, train_from_source_plan

                result = train_from_source_plan(
                    kind=self._source_kind_var.get(),
                    scale=self._source_scale_var.get(),
                )
                plan_text = render_training_plan(result.get("plan", self._source_plan))
                self.after(0, lambda: self._on_source_train_done(result, plan_text))
            except Exception as exc:
                err_msg = str(exc)
                self.after(0, lambda msg=err_msg: self._on_retrain_error(msg))

        threading.Thread(target=worker, daemon=True).start()

    def _on_source_train_done(self, result: Dict[str, Any], plan_text: str):
        self._is_retraining = False
        self._btn_source_train.configure(state="normal", text="Train từ plan")
        self._btn_source_prepare.configure(state="normal")
        self._btn_source_plan.configure(state="normal")
        self._progress_lbl.configure(text="")
        self._retrain_progress.set(0)

        if result.get("success"):
            dataset = result.get("dataset", {})
            metrics = result.get("metrics", {})
            self._set_source_text(
                plan_text +
                f"\n\n[TRAINED]\nSAFE={dataset.get('safe_count', 0)} "
                f"ENCRYPTED={dataset.get('encrypted_count', 0)} "
                f"Accuracy={metrics.get('accuracy', 0):.2%}"
            )
            self._log("Train từ source plan thành công")
            messagebox.showinfo(
                "Hoàn tất training",
                f"Đã hoàn tất training.\nSAFE={dataset.get('safe_count', 0)} "
                f"ENCRYPTED={dataset.get('encrypted_count', 0)}"
            )
            self._refresh()
            return

        self._set_source_text(plan_text + f"\n\n[STATUS] {result.get('status')}\n{result.get('message')}")
        self._log(f"Train từ source plan thất bại: {result.get('status')}")
        if result.get("status") == "manual-acquire-required":
            messagebox.showwarning("Cần lấy thủ công", result.get("message"))
        else:
            messagebox.showerror("Train từ plan thất bại", result.get("message"))

    def _on_retrain_error(self, error: str):
        self._is_retraining = False
        self._btn_retrain.configure(state="normal", text="Retrain model")
        if hasattr(self, "_btn_source_train"):
            self._btn_source_train.configure(state="normal", text="Train từ plan")
        if hasattr(self, "_btn_source_prepare"):
            self._btn_source_prepare.configure(state="normal", text="Tải / Chuẩn bị")
        if hasattr(self, "_btn_source_plan"):
            self._btn_source_plan.configure(state="normal")
        self._retrain_progress.set(0)
        self._progress_lbl.configure(text="")
        self._log(f"Lỗi retrain: {error}")
        messagebox.showerror("Lỗi retrain", error)

    def _on_rollback(self):
        if not hasattr(self, "_selected_version"):
            messagebox.showwarning("Chọn version", "Vui lòng chọn version model để rollback")
            return

        version = getattr(self, "_selected_version", None)
        if not version:
            messagebox.showwarning("Chọn version", "Vui lòng chọn version model để rollback")
            return

        reply = messagebox.askyesno("Rollback", f"Rollback về version {version}?")
        if not reply:
            return

        try:
            success = self._ml_engine.rollback_model(version)
            if success:
                self._log(f"Rolled back to {version}")
                messagebox.showinfo("Rollback", f"Đã rollback về {version}")
            else:
                messagebox.showerror("Rollback", "Rollback thất bại")
        except Exception as e:
            messagebox.showerror("Lỗi rollback", str(e))

        self._refresh()

    def _on_delete_old(self):
        reply = messagebox.askyesno(
            "Xóa version cũ",
            "Xóa tất cả version model trừ version đang active?"
        )
        if reply:
            self._log("Đã yêu cầu xóa version cũ (chưa triển khai)")

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
            self._log(f"Feedback: {feedback_type} - {predicted_label} -> {feedback_label}")
        except Exception as e:
            self._log(f"Lỗi feedback: {e}")
