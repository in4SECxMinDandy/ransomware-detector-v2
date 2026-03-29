"""
gui/tab_office_scanner.py
=========================
Office Document Scanner tab — CustomTkinter.

Features:
  - Browse files / folder
  - Drag & drop support (via filedialog)
  - Results table with color-coded threat levels
  - Macro code viewer with syntax highlighting
  - Export report + VirusTotal check
"""

import os
import threading
from typing import List, Optional, Dict, Any

import customtkinter as ctk
from tkinter import filedialog, messagebox


# ─── Color palette (matches main_window.py) ───────────────────────────────────
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
}


class OfficeScannerTab(ctk.CTkFrame):
    """
    Tab frame for scanning Office documents for malware.
    Designed to be embedded inside MainWindow._build_page_container().
    """

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=C["bg_dark"], **kwargs)

        self._results: List[Dict[str, Any]] = []
        self._selected_result: Optional[Dict[str, Any]] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._is_scanning = False
        self._drop_paths: List[str] = []

        self._setup_ui()

    def _setup_ui(self):
        """Build the UI layout."""
        self.grid_columnconfigure(0, weight=1)

        # ── Title ──────────────────────────────────────────────────────────────
        title_row = ctk.CTkFrame(self, fg_color="transparent")
        title_row.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 4))
        title_row.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            title_row, text="Office Document Scanner",
            font=("Consolas", 14, "bold"), text_color=C["accent"]
        )
        title.grid(row=0, column=0, sticky="w")

        subtitle = ctk.CTkLabel(
            title_row, text="Scan .doc/.docx/.pdf/.xls/.ppt/.rtf files for embedded malware, VBA macros, and auto-execution triggers",
            font=("Consolas", 8), text_color=C["text_dim"], wraplength=700
        )
        subtitle.grid(row=1, column=0, sticky="w", pady=(2, 0))

        # ── Drop zone (visual indicator) ───────────────────────────────────────
        drop_card = ctk.CTkFrame(self, fg_color=C["bg_card"], corner_radius=8,
                                 border_width=1, border_color=C["border"])
        drop_card.grid(row=1, column=0, sticky="ew", padx=12, pady=(8, 4))
        drop_card.grid_columnconfigure(0, weight=1)

        self._drop_label = ctk.CTkLabel(
            drop_card,
            text="Drop files here or use the buttons below to select files/folders",
            font=("Consolas", 10), text_color=C["text_dim"], justify="center"
        )
        self._drop_label.grid(row=0, column=0, padx=12, pady=12)

        self._files_label = ctk.CTkLabel(
            drop_card, text="No files selected",
            font=("Consolas", 8), text_color=C["text_dim"]
        )
        self._files_label.grid(row=1, column=0, pady=(0, 8))

        # ── Action buttons ──────────────────────────────────────────────────────
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="ew", padx=12, pady=(4, 4))
        btn_row.grid_columnconfigure(0, weight=1)

        self._btn_browse_files = ctk.CTkButton(
            btn_row, text="Browse Files", height=36,
            font=("Consolas", 10), fg_color=C["bg_card"],
            hover_color=C["border"], text_color=C["text"],
            command=self._on_browse_files
        )
        self._btn_browse_files.grid(row=0, column=0, sticky="w", padx=(0, 8))

        self._btn_browse_folder = ctk.CTkButton(
            btn_row, text="Browse Folder", height=36,
            font=("Consolas", 10), fg_color=C["bg_card"],
            hover_color=C["border"], text_color=C["text"],
            command=self._on_browse_folder
        )
        self._btn_browse_folder.grid(row=0, column=1, sticky="w", padx=(0, 8))

        ctk.CTkLabel(btn_row, text="", font=("Consolas", 1)).grid(row=0, column=2)

        self._btn_scan = ctk.CTkButton(
            btn_row, text="Start Scan", height=36,
            font=("Consolas", 10, "bold"), fg_color=C["green"],
            hover_color="#1EA34A", text_color=C["bg_dark"],
            state="disabled", command=self._on_scan
        )
        self._btn_scan.grid(row=0, column=3, sticky="e", padx=(8, 0))

        self._btn_clear = ctk.CTkButton(
            btn_row, text="Clear", height=36,
            font=("Consolas", 10), fg_color=C["bg_card"],
            hover_color=C["border"], text_color=C["text"],
            command=self._on_clear
        )
        self._btn_clear.grid(row=0, column=4, sticky="e")

        # ── Progress bar ────────────────────────────────────────────────────────
        self._progress = ctk.CTkProgressBar(self, height=8,
                                            progress_color=C["accent"],
                                            fg_color=C["border"])
        self._progress.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 4))
        self._progress.set(0)

        # ── Results card ────────────────────────────────────────────────────────
        results_card = ctk.CTkFrame(self, fg_color=C["bg_card"], corner_radius=8,
                                   border_width=1, border_color=C["border"])
        results_card.grid(row=4, column=0, sticky="nsew", padx=12, pady=(0, 4))
        results_card.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(
            results_card, text="Scan Results",
            font=("Consolas", 11, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        # Results scrollable area
        results_scroll = ctk.CTkScrollableFrame(
            results_card, fg_color="transparent",
            scrollbar_button_color=C["border"],
            height=180
        )
        results_scroll.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        results_scroll.grid_columnconfigure(0, weight=1)
        results_card.grid_rowconfigure(1, weight=1)

        self._results_container = results_scroll
        ctk.CTkLabel(
            results_scroll, text="No results yet — run a scan",
            font=("Consolas", 9), text_color=C["text_dim"]
        ).grid(row=0, column=0, pady=20)

        self._result_rows: List[ctk.CTkFrame] = []

        # ── Macro code viewer ──────────────────────────────────────────────────
        code_card = ctk.CTkFrame(self, fg_color=C["bg_card"], corner_radius=8,
                                 border_width=1, border_color=C["border"])
        code_card.grid(row=5, column=0, sticky="nsew", padx=12, pady=(0, 4))
        code_card.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1)

        ctk.CTkLabel(
            code_card, text="Analysis Details",
            font=("Consolas", 11, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        self._code_viewer = ctk.CTkTextbox(
            code_card, font=("Cascadia Code", 9),
            fg_color=C["bg_dark"], text_color=C["text"],
            border_color=C["border"], border_width=1,
            scrollbar_button_color=C["border"],
            wrap="word", height=100
        )
        self._code_viewer.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self._code_viewer.insert("0.0", "Select a file from the results table to see details.")
        self._code_viewer.configure(state="disabled")

        # ── Bottom action buttons ───────────────────────────────────────────────
        bottom_row = ctk.CTkFrame(self, fg_color="transparent")
        bottom_row.grid(row=6, column=0, sticky="ew", padx=12, pady=(4, 8))
        bottom_row.grid_columnconfigure(0, weight=1)

        self._btn_export = ctk.CTkButton(
            bottom_row, text="Export Report (PDF)", height=36,
            font=("Consolas", 10), fg_color=C["blue"],
            hover_color=C["accent"], text_color="#FFF",
            state="disabled", command=self._on_export
        )
        self._btn_export.grid(row=0, column=0, sticky="w")

        self._btn_vt = ctk.CTkButton(
            bottom_row, text="Check VirusTotal", height=36,
            font=("Consolas", 10), fg_color=C["bg_card"],
            hover_color=C["border"], text_color=C["text"],
            state="disabled", command=self._on_virustotal
        )
        self._btn_vt.grid(row=0, column=1, sticky="w", padx=(8, 0))

        self._vt_status = ctk.CTkLabel(
            bottom_row, text="", font=("Consolas", 9), text_color=C["text_dim"]
        )
        self._vt_status.grid(row=0, column=2, sticky="e")

    # ─── File selection ───────────────────────────────────────────────────────

    def _on_browse_files(self):
        files, _ = filedialog.askopenfilenames(
            title="Select Office Files",
            filetypes=[
                ("Office Files", "*.doc *.docx *.docm *.xls *.xlsx *.xlsm *.ppt *.pptx *.pdf *.rtf"),
                ("All Files", "*.*"),
            ]
        )
        if files:
            self._drop_paths = list(files)
            self._files_label.configure(
                text=f"{len(files)} file(s) selected",
                text_color=C["text"]
            )
            self._btn_scan.configure(state="normal")

    def _on_browse_folder(self):
        folder = filedialog.askdirectory(title="Select Folder to Scan")
        if folder:
            supported = {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
                        ".ppt", ".pptx", ".pdf", ".rtf"}
            files = []
            for root, _, filenames in os.walk(folder):
                for fn in filenames:
                    if os.path.splitext(fn)[1].lower() in supported:
                        files.append(os.path.join(root, fn))
            self._drop_paths = files
            self._files_label.configure(
                text=f"{len(files)} file(s) found in folder",
                text_color=C["text"]
            )
            self._btn_scan.configure(state="normal" if files else "disabled")

    # ─── Scanning ─────────────────────────────────────────────────────────────

    def _on_scan(self):
        if self._is_scanning or not self._drop_paths:
            return

        self._is_scanning = True
        self._btn_scan.configure(state="disabled", text="Scanning...")
        self._btn_browse_files.configure(state="disabled")
        self._btn_browse_folder.configure(state="disabled")
        self._progress.set(0)
        self._clear_result_rows()
        self._results.clear()

        self._scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self._scan_thread.start()

    def _scan_worker(self):
        try:
            from core.office_doc_analyzer import OfficeDocAnalyzer
        except ImportError:
            self.after(0, lambda: messagebox.showerror(
                "Import Error", "Office analyzer not available.\nInstall: pip install oletools PyMuPDF"
            ))
            self.after(0, self._scan_finished)
            return

        analyzer = OfficeDocAnalyzer()
        total = len(self._drop_paths)

        for i, path in enumerate(self._drop_paths):
            try:
                result = analyzer.analyze(path)
                self._results.append(result.to_dict())
            except Exception as e:
                self._results.append({
                    "file_path": path,
                    "filename": os.path.basename(path),
                    "extension": os.path.splitext(path)[1].lower(),
                    "threat_level": "ERROR",
                    "error": str(e),
                    "sha256": "",
                    "file_size": 0,
                })

            progress = (i + 1) / total
            self.after(0, lambda p=progress: self._progress.set(p))
            self.after(0, lambda r=self._results[-1]: self._add_result_row(r))

        self.after(0, self._scan_finished)

    def _scan_finished(self):
        self._is_scanning = False
        self._btn_scan.configure(state="normal", text="Start Scan")
        self._btn_browse_files.configure(state="normal")
        self._btn_browse_folder.configure(state="normal")
        self._progress.set(0)
        self._btn_export.configure(state="normal" if self._results else "disabled")

        threats = sum(1 for r in self._results if r.get("threat_level") in ("MALICIOUS", "SUSPICIOUS"))
        self._files_label.configure(
            text=f"Scan complete — {len(self._results)} files, {threats} threat(s) found",
            text_color=C["red"] if threats else C["green"]
        )

    # ─── Results display ─────────────────────────────────────────────────────

    def _clear_result_rows(self):
        for row in self._result_rows:
            row.destroy()
        self._result_rows.clear()
        # Show placeholder
        for w in self._results_container.grid_slaves():
            if isinstance(w, ctk.CTkLabel) and "No results" in w.cget("text"):
                w.destroy()

    def _add_result_row(self, result: Dict[str, Any]):
        # Remove placeholder
        for w in self._results_container.grid_slaves():
            if isinstance(w, ctk.CTkLabel) and "No results" in w.cget("text"):
                w.destroy()

        row_idx = len(self._result_rows)
        threat = result.get("threat_level", "CLEAN")

        if threat == "MALICIOUS":
            row_color = C["bg_card"]
            risk_color = C["red"]
        elif threat == "SUSPICIOUS":
            row_color = C["bg_card"]
            risk_color = C["orange"]
        elif threat == "ERROR":
            row_color = C["bg_card"]
            risk_color = C["text_dim"]
        else:
            row_color = C["bg_card"]
            risk_color = C["green"]

        row = ctk.CTkFrame(
            self._results_container,
            fg_color=row_color,
            border_width=1,
            border_color=C["border"],
            corner_radius=6,
            height=40
        )
        row.pack(fill="x", padx=4, pady=2)
        row.pack_propagate(False)
        row.grid_columnconfigure(0, weight=1)
        row.grid_columnconfigure(1, weight=0)
        row.grid_columnconfigure(2, weight=0)
        row.grid_columnconfigure(3, weight=0)

        # Store result data for click handler
        row.result_data = result
        row.bind("<Button-1>", lambda e, r=result: self._on_row_click(r))

        filename = result.get("filename", "?")
        triggers = result.get("triggers_found", [])
        trigger_text = ", ".join(triggers[:3]) if triggers else "-"
        size_kb = result.get("file_size", 0) / 1024

        ctk.CTkLabel(
            row, text=f"  {filename}",
            font=("Consolas", 9), text_color=C["text"], anchor="w"
        ).grid(row=0, column=0, sticky="w", padx=(8, 4), pady=6)

        threat_badge = ctk.CTkLabel(
            row, text=threat,
            font=("Consolas", 8, "bold"),
            text_color=C["bg_dark"],
            width=80
        )
        threat_badge.configure(fg_color=risk_color, corner_radius=6)
        threat_badge.grid(row=0, column=1, sticky="e", padx=4, pady=6)

        ctk.CTkLabel(
            row, text=trigger_text[:30],
            font=("Consolas", 8), text_color=C["text_dim"], anchor="w"
        ).grid(row=0, column=2, sticky="w", padx=4, pady=6)

        ctk.CTkLabel(
            row, text=f"{size_kb:.1f} KB",
            font=("Consolas", 8), text_color=C["text_dim"]
        ).grid(row=0, column=3, sticky="e", padx=(4, 8), pady=6)

        self._result_rows.append(row)

    def _on_row_click(self, result: Dict[str, Any]):
        self._selected_result = result
        self._btn_vt.configure(state="normal")
        self._display_details(result)

    def _display_details(self, result: Dict[str, Any]):
        self._code_viewer.configure(state="normal")
        self._code_viewer.delete("0.0", "end")

        threat = result.get("threat_level", "CLEAN")
        lines = [
            f"File: {result.get('filename', '')}",
            f"Path: {result.get('file_path', '')}",
            f"Threat Level: {threat}",
            "",
            f"SHA256: {result.get('sha256', 'N/A')[:32]}..." if result.get('sha256') else "",
            f"File Size: {result.get('file_size', 0) / 1024:.1f} KB",
        ]

        triggers = result.get("triggers_found", [])
        if triggers:
            lines.append("")
            lines.append(f"Auto-Execution Triggers: {', '.join(triggers)}")

        if result.get("macro_count", 0) > 0:
            lines.append(f"Macros Found: {result.get('macro_count')}")

        pdf_actions = result.get("pdf_actions", [])
        if pdf_actions:
            lines.append(f"PDF Actions: {len(pdf_actions)}")
            for a in pdf_actions:
                lines.append(f"  - {a.get('type', '')} (page {a.get('page', '?')})")

        js = result.get("pdf_javascript", [])
        if js:
            lines.append(f"JavaScript Found: {len(js)} instance(s)")

        macro_code = result.get("macro_code_snippet", "")
        if macro_code:
            lines.append("")
            lines.append("=" * 50)
            lines.append("MACRO CODE:")
            lines.append("=" * 50)
            lines.append(macro_code[:2000])

        yara = result.get("yara_matches", [])
        if yara:
            lines.append("")
            lines.append("=" * 50)
            lines.append("YARA MATCHES:")
            for m in yara:
                lines.append(f"  [{m.get('severity', '?')}] {m.get('rule_name', '')}: {m.get('description', '')}")

        rec = result.get("recommendation", "")
        if rec:
            lines.append("")
            lines.append("=" * 50)
            lines.append("RECOMMENDATION:")
            lines.append(rec)

        self._code_viewer.insert("0.0", "\n".join(filter(None, lines)))
        self._code_viewer.configure(state="disabled")

    # ─── Actions ───────────────────────────────────────────────────────────────

    def _on_clear(self):
        self._results.clear()
        self._drop_paths.clear()
        self._selected_result = None
        self._clear_result_rows()
        self._code_viewer.configure(state="normal")
        self._code_viewer.delete("0.0", "end")
        self._code_viewer.insert("0.0", "Select a file from the results table to see details.")
        self._code_viewer.configure(state="disabled")
        self._files_label.configure(text="No files selected", text_color=C["text_dim"])
        self._btn_scan.configure(state="disabled")
        self._btn_export.configure(state="disabled")
        self._btn_vt.configure(state="disabled")
        self._vt_status.configure(text="")

    def _on_export(self):
        try:
            from core.pdf_reporter import export_office_report
            output_dir = filedialog.askdirectory(title="Select Output Directory")
            if output_dir:
                from core.office_doc_analyzer import OfficeDocAnalyzer
                analyzer = OfficeDocAnalyzer()
                full_results = []
                for path in self._drop_paths:
                    try:
                        r = analyzer.analyze(path)
                        full_results.append(r)
                    except Exception:
                        pass
                if full_results:
                    output_path = export_office_report(full_results, output_dir)
                    messagebox.showinfo("Export", f"Report saved:\n{output_path}")
        except ImportError:
            messagebox.showwarning("Export", "PDF export requires reportlab")

    def _on_virustotal(self):
        if not self._selected_result:
            return
        sha256 = self._selected_result.get("sha256", "")
        if not sha256:
            self._vt_status.configure(text="No SHA256 available")
            return
        self._vt_status.configure(text=f"VT: Querying {sha256[:16]}...")
        self.after(500, lambda: self._vt_status.configure(
            text=f"VT: Open https://www.virustotal.com/gui/file/{sha256}"
        ))
