"""
pdf_reporter.py — v2.1 (MỚI)
================================
Export Model Analysis Report dạng PDF.

Báo cáo PDF bao gồm:
  1. Trang tiêu đề: tên tool, version, timestamp
  2. Model Summary: accuracy, precision, recall, FP rate, threshold
  3. Feature Importances: bar chart top-16 features
  4. Confusion Matrix: heatmap trực quan
  5. Precision-Recall Curve (nếu có PR data)
  6. Scan Results Summary: bảng tóm tắt kết quả scan
  7. Threat Details: danh sách files bị cảnh báo
  8. YARA Matches (nếu có)

Sử dụng matplotlib + reportlab (nếu có) hoặc matplotlib thuần.

Cài đặt:
  pip install reportlab matplotlib pillow
"""

import os
import json
import tempfile
from datetime import datetime
from typing import List, Dict, Optional, Any

import numpy as np
import matplotlib
matplotlib.use("Agg")  # non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.backends.backend_pdf import PdfPages

# ─── Try reportlab (optional, cho PDF đẹp hơn) ───
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph,
        Spacer, Image, PageBreak
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ─── Color scheme (cyber dark theme) ───
PDF_COLORS = {
    "bg":        "#0D1117",
    "panel":     "#161B22",
    "green":     "#00FF88",
    "red":       "#FF2D2D",
    "orange":    "#FF8C00",
    "yellow":    "#FFD700",
    "blue":      "#58A6FF",
    "cyan":      "#00BFFF",
    "text":      "#C9D1D9",
    "text_dim":  "#8B949E",
    "purple":    "#BC8CFF",
}

RISK_COLORS_MAP = {
    "CRITICAL": "#FF2D2D",
    "HIGH":     "#FF8C00",
    "MEDIUM":   "#FFD700",
    "LOW":      "#00BFFF",
    "SAFE":     "#00FF88",
}


def export_model_report_pdf(
    output_path: str,
    model_metadata: Dict,
    scan_results: Optional[List] = None,
    yara_summary: Optional[Dict] = None,
    scan_directory: str = "",
    scan_duration: float = 0.0,
) -> bool:
    """
    Export báo cáo phân tích model ra PDF.

    Parameters
    ----------
    output_path     : đường dẫn file PDF đầu ra
    model_metadata  : dict từ model_metadata.json
    scan_results    : list of ScanResult objects (optional)
    yara_summary    : thống kê YARA matches (optional)
    scan_directory  : thư mục đã quét
    scan_duration   : thời gian quét (giây)

    Returns
    -------
    True nếu xuất thành công
    """
    try:
        _export_matplotlib_pdf(
            output_path, model_metadata, scan_results,
            yara_summary, scan_directory, scan_duration
        )
        return True
    except Exception as e:
        print(f"[PDFReporter] Lỗi export: {e}")
        return False


def _export_matplotlib_pdf(
    output_path: str,
    meta: Dict,
    results: Optional[List],
    yara_summary: Optional[Dict],
    scan_dir: str,
    scan_duration: float,
):
    """Export PDF dùng matplotlib PdfPages."""
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    with PdfPages(output_path) as pdf:
        # ── Page 1: Title + Model Summary ──
        fig = plt.figure(figsize=(11.69, 8.27))  # A4 landscape
        fig.patch.set_facecolor(PDF_COLORS["bg"])

        gs = gridspec.GridSpec(3, 2, figure=fig, hspace=0.5, wspace=0.4)

        # Title section
        ax_title = fig.add_subplot(gs[0, :])
        ax_title.set_facecolor(PDF_COLORS["panel"])
        ax_title.axis("off")
        ax_title.text(0.5, 0.70, "RANSOMWARE ENTROPY DETECTOR",
                      ha="center", va="center", fontsize=22, fontweight="bold",
                      color=PDF_COLORS["green"], fontfamily="monospace",
                      transform=ax_title.transAxes)
        ax_title.text(0.5, 0.35, "Model Analysis Report — v2.1",
                      ha="center", va="center", fontsize=13,
                      color=PDF_COLORS["text"], fontfamily="monospace",
                      transform=ax_title.transAxes)
        ax_title.text(0.5, 0.10, f"Generated: {ts}  |  Anti-FP Edition  |  16 Features  |  Calibrated Random Forest",
                      ha="center", va="center", fontsize=8,
                      color=PDF_COLORS["text_dim"], fontfamily="monospace",
                      transform=ax_title.transAxes)

        # Metrics table
        ax_metrics = fig.add_subplot(gs[1, 0])
        ax_metrics.set_facecolor(PDF_COLORS["panel"])
        ax_metrics.axis("off")

        metrics_data = [
            ["Metric", "Value", "Target"],
            ["Accuracy",        f"{meta.get('accuracy',0)*100:.2f}%",   "≥ 95%"],
            ["Precision",       f"{meta.get('precision',0)*100:.2f}%",  "≥ 95%"],
            ["Recall",          f"{meta.get('recall',0)*100:.2f}%",     "≥ 90%"],
            ["F1-Score",        f"{meta.get('f1_score',0)*100:.2f}%",   "≥ 92%"],
            ["AUC-ROC",         f"{meta.get('auc_roc',0)*100:.2f}%",    "≥ 98%"],
            ["False Pos. Rate", f"{meta.get('false_positive_rate',0)*100:.2f}%", "< 5%"],
            ["CV F1 5-fold",    f"{meta.get('cv_mean',0)*100:.2f}%±{meta.get('cv_std',0)*100:.2f}%", "—"],
            ["Optimal Thresh.", f"{meta.get('optimal_threshold',0.65):.4f}", "Auto-tuned"],
        ]

        colors_table = []
        for i, row in enumerate(metrics_data):
            if i == 0:
                colors_table.append([PDF_COLORS["panel"]] * 3)
            else:
                val_str = row[1].replace("%", "")
                try:
                    val = float(val_str.split("±")[0])
                    target_str = row[2].replace("%", "").replace("≥", "").replace("<", "").strip()
                    if "≥" in row[2]:
                        target = float(target_str)
                        ok = val >= target
                    elif "<" in row[2]:
                        target = float(target_str)
                        ok = val < target
                    else:
                        ok = True
                    row_color = PDF_COLORS["bg"] if ok else "#3D1515"
                except Exception:
                    row_color = PDF_COLORS["bg"]
                colors_table.append([row_color] * 3)

        tbl = ax_metrics.table(
            cellText=metrics_data,
            cellLoc="center",
            loc="center",
            bbox=[0, 0, 1, 1],
        )
        tbl.auto_set_font_size(False)
        tbl.set_fontsize(8)

        for (row, col), cell in tbl.get_celld().items():
            cell.set_edgecolor(PDF_COLORS["panel"])
            if row == 0:
                cell.set_facecolor(PDF_COLORS["cyan"])
                cell.set_text_props(color="black", fontweight="bold")
            else:
                cell.set_facecolor(colors_table[row][col])
                c = (PDF_COLORS["green"] if col == 0 else
                     PDF_COLORS["yellow"] if col == 1 else
                     PDF_COLORS["text_dim"])
                cell.set_text_props(color=c, fontfamily="monospace")

        ax_metrics.set_title("Model Performance Metrics",
                              color=PDF_COLORS["cyan"], fontsize=10,
                              fontfamily="monospace", pad=8)

        # Feature importances bar chart
        ax_fi = fig.add_subplot(gs[1, 1])
        ax_fi.set_facecolor(PDF_COLORS["bg"])

        fi_raw = meta.get("feature_importances", {})
        if fi_raw:
            fi_sorted = sorted(fi_raw.items(), key=lambda x: x[1], reverse=True)[:10]
            names    = [x[0].replace(" ", "\n") for x in fi_sorted]
            values   = [x[1] for x in fi_sorted]
            bar_colors = [PDF_COLORS["green"] if v == max(values) else
                          PDF_COLORS["cyan"]  if v > 0.08 else
                          PDF_COLORS["blue"]
                          for v in values]
            bars = ax_fi.barh(range(len(names)), values, color=bar_colors, height=0.6)
            ax_fi.set_yticks(range(len(names)))
            ax_fi.set_yticklabels(names, fontsize=6, color=PDF_COLORS["text"],
                                  fontfamily="monospace")
            ax_fi.invert_yaxis()
            ax_fi.set_xlabel("Importance", color=PDF_COLORS["text_dim"], fontsize=7)
            ax_fi.tick_params(colors=PDF_COLORS["text_dim"], labelsize=6)
            ax_fi.spines[:].set_color(PDF_COLORS["panel"])
            for spine in ax_fi.spines.values():
                spine.set_edgecolor(PDF_COLORS["border"] if False else "#30363D")
            for val, bar in zip(values, bars):
                ax_fi.text(val + 0.002, bar.get_y() + bar.get_height()/2,
                           f"{val:.3f}", va="center", ha="left",
                           color=PDF_COLORS["text_dim"], fontsize=5)
        else:
            ax_fi.text(0.5, 0.5, "No feature importance data",
                       ha="center", va="center", color=PDF_COLORS["text_dim"])
            ax_fi.axis("off")

        ax_fi.set_facecolor(PDF_COLORS["bg"])
        ax_fi.set_title("Feature Importances (Top 10)",
                         color=PDF_COLORS["cyan"], fontsize=10,
                         fontfamily="monospace", pad=8)

        # Confusion Matrix
        ax_cm = fig.add_subplot(gs[2, 0])
        ax_cm.set_facecolor(PDF_COLORS["bg"])

        cm_data = meta.get("confusion_matrix")
        if cm_data and len(cm_data) == 2:
            cm_arr = np.array(cm_data)
            im = ax_cm.imshow(cm_arr, cmap="YlOrRd", aspect="auto")
            ax_cm.set_xticks([0, 1])
            ax_cm.set_yticks([0, 1])
            ax_cm.set_xticklabels(["SAFE", "ENCRYPTED"],
                                   color=PDF_COLORS["text"], fontsize=8)
            ax_cm.set_yticklabels(["SAFE", "ENCRYPTED"],
                                   color=PDF_COLORS["text"], fontsize=8)
            ax_cm.set_xlabel("Predicted", color=PDF_COLORS["text_dim"], fontsize=8)
            ax_cm.set_ylabel("Actual", color=PDF_COLORS["text_dim"], fontsize=8)
            total_cm = cm_arr.sum()
            for i in range(2):
                for j in range(2):
                    val = int(cm_arr[i, j])
                    pct = val / max(total_cm, 1) * 100
                    ax_cm.text(j, i, f"{val}\n({pct:.1f}%)",
                               ha="center", va="center",
                               fontsize=9, fontweight="bold",
                               color="black" if cm_arr[i,j] > cm_arr.max()/2 else "white")
            label_map = {(0,0): "TN", (0,1): "FP", (1,0): "FN", (1,1): "TP"}
            for (i,j), lbl in label_map.items():
                ax_cm.text(j + 0.45, i - 0.45, lbl, ha="right", va="top",
                           fontsize=6, color=PDF_COLORS["text_dim"], style="italic")
        else:
            ax_cm.text(0.5, 0.5, "Confusion matrix data unavailable",
                       ha="center", va="center", color=PDF_COLORS["text_dim"])
            ax_cm.axis("off")

        ax_cm.set_title("Confusion Matrix",
                         color=PDF_COLORS["cyan"], fontsize=10,
                         fontfamily="monospace", pad=8)

        # Scan results pie chart (if available)
        ax_pie = fig.add_subplot(gs[2, 1])
        ax_pie.set_facecolor(PDF_COLORS["bg"])

        if results and len(results) > 0:
            safe     = sum(1 for r in results if getattr(r, "label", 0) == 0)
            critical = sum(1 for r in results if getattr(r, "risk_level", "") == "CRITICAL")
            high     = sum(1 for r in results if getattr(r, "risk_level", "") == "HIGH")
            medium   = sum(1 for r in results if getattr(r, "risk_level", "") == "MEDIUM")

            labels  = ["SAFE", "CRITICAL", "HIGH", "MEDIUM"]
            sizes   = [safe, critical, high, medium]
            pie_c   = [PDF_COLORS["green"], PDF_COLORS["red"],
                       PDF_COLORS["orange"], PDF_COLORS["yellow"]]
            # Lọc bỏ slice = 0
            filtered = [(l, s, c) for l, s, c in zip(labels, sizes, pie_c) if s > 0]
            if filtered:
                fl, fs, fc = zip(*filtered)
                wedges, texts, autotexts = ax_pie.pie(
                    fs, labels=fl, colors=fc,
                    autopct="%1.1f%%", startangle=90,
                    textprops={"color": PDF_COLORS["text"], "fontsize": 8}
                )
                for at in autotexts:
                    at.set_color("black")
                    at.set_fontsize(7)
        else:
            ax_pie.text(0.5, 0.5, "No scan data",
                        ha="center", va="center", color=PDF_COLORS["text_dim"],
                        fontsize=10)
            ax_pie.axis("off")

        n_results = len(results) if results else 0
        ax_pie.set_title(f"Scan Results Distribution (n={n_results})",
                          color=PDF_COLORS["cyan"], fontsize=10,
                          fontfamily="monospace", pad=8)
        ax_pie.set_facecolor(PDF_COLORS["bg"])

        pdf.savefig(fig, facecolor=fig.get_facecolor(), bbox_inches="tight")
        plt.close(fig)

        # ── Page 2: Threat Details ──
        if results:
            threats = [r for r in results if getattr(r, "label", 0) == 1]
            if threats:
                fig2 = plt.figure(figsize=(11.69, 8.27))
                fig2.patch.set_facecolor(PDF_COLORS["bg"])

                ax2 = fig2.add_subplot(111)
                ax2.set_facecolor(PDF_COLORS["bg"])
                ax2.axis("off")

                ax2.text(0.5, 0.97, "THREAT DETAILS",
                         ha="center", va="top", fontsize=14,
                         fontweight="bold", color=PDF_COLORS["red"],
                         fontfamily="monospace",
                         transform=ax2.transAxes)
                ax2.text(0.5, 0.93,
                         f"Scan Directory: {scan_dir or 'N/A'}  |  "
                         f"Duration: {scan_duration:.1f}s  |  "
                         f"Files Flagged: {len(threats)}",
                         ha="center", va="top", fontsize=8,
                         color=PDF_COLORS["text_dim"], fontfamily="monospace",
                         transform=ax2.transAxes)

                # Table header
                table_data = [["#", "Filename", "Risk", "Prob(%)", "Entropy", "Path"]]
                for i, r in enumerate(threats[:30]):  # max 30 rows
                    fname = getattr(r, "filename", "?")
                    if len(fname) > 30:
                        fname = fname[:27] + "..."
                    path = getattr(r, "path", "?")
                    if len(path) > 40:
                        path = "..." + path[-37:]
                    table_data.append([
                        str(i + 1),
                        fname,
                        getattr(r, "risk_level", "?"),
                        f"{getattr(r, 'probability', 0)*100:.1f}%",
                        f"{getattr(r, 'entropy', 0):.3f}",
                        path,
                    ])

                if len(threats) > 30:
                    table_data.append(["...", f"({len(threats)-30} more threats)", "", "", "", ""])

                tbl2 = ax2.table(
                    cellText=table_data,
                    cellLoc="left",
                    loc="upper center",
                    bbox=[0.0, 0.0, 1.0, 0.88],
                )
                tbl2.auto_set_font_size(False)
                tbl2.set_fontsize(6.5)
                tbl2.auto_set_column_width([0, 1, 2, 3, 4, 5])

                for (row, col), cell in tbl2.get_celld().items():
                    cell.set_edgecolor("#30363D")
                    if row == 0:
                        cell.set_facecolor(PDF_COLORS["cyan"])
                        cell.set_text_props(color="black", fontweight="bold")
                    else:
                        risk = table_data[row][2] if row < len(table_data) else ""
                        bg   = {
                            "CRITICAL": "#2A0A0A",
                            "HIGH":     "#2A1A0A",
                            "MEDIUM":   "#1A1A0A",
                        }.get(risk, PDF_COLORS["bg"])
                        cell.set_facecolor(bg)
                        if col == 2 and row > 0:
                            cell.set_text_props(
                                color=RISK_COLORS_MAP.get(risk, PDF_COLORS["text"]),
                                fontweight="bold", fontfamily="monospace"
                            )
                        else:
                            cell.set_text_props(
                                color=PDF_COLORS["text"], fontfamily="monospace"
                            )

                pdf.savefig(fig2, facecolor=fig2.get_facecolor(), bbox_inches="tight")
                plt.close(fig2)

        # ── Page 3: YARA Summary + Footer ──
        if yara_summary:
            fig3 = plt.figure(figsize=(11.69, 8.27))
            fig3.patch.set_facecolor(PDF_COLORS["bg"])
            ax3 = fig3.add_subplot(111)
            ax3.set_facecolor(PDF_COLORS["bg"])
            ax3.axis("off")

            ax3.text(0.5, 0.97, "YARA SIGNATURE ANALYSIS",
                     ha="center", va="top", fontsize=14,
                     fontweight="bold", color=PDF_COLORS["orange"],
                     fontfamily="monospace", transform=ax3.transAxes)

            yara_data  = [["Rule", "Matches", "Severity", "Family"]]
            rule_stats = yara_summary.get("rule_stats", {})
            for rule_name, count in sorted(rule_stats.items(),
                                            key=lambda x: x[1], reverse=True):
                sev = yara_summary.get("rule_severities", {}).get(rule_name, "MEDIUM")
                fam = yara_summary.get("rule_families", {}).get(rule_name, "Generic")
                yara_data.append([rule_name, str(count), sev, fam])

            if len(yara_data) > 1:
                tbl3 = ax3.table(
                    cellText=yara_data,
                    cellLoc="center",
                    loc="upper center",
                    bbox=[0.1, 0.5, 0.8, 0.4],
                )
                tbl3.auto_set_font_size(False)
                tbl3.set_fontsize(8)
                for (row, col), cell in tbl3.get_celld().items():
                    cell.set_edgecolor("#30363D")
                    if row == 0:
                        cell.set_facecolor(PDF_COLORS["orange"])
                        cell.set_text_props(color="black", fontweight="bold")
                    else:
                        sev_val = yara_data[row][2]
                        cell.set_facecolor({
                            "CRITICAL": "#2A0A0A",
                            "HIGH":     "#2A1A0A",
                            "MEDIUM":   PDF_COLORS["bg"],
                        }.get(sev_val, PDF_COLORS["bg"]))
                        cell.set_text_props(
                            color=RISK_COLORS_MAP.get(sev_val, PDF_COLORS["text"]),
                            fontfamily="monospace"
                        )

            ax3.text(0.5, 0.15,
                     "* YARA rules detect known ransomware signatures\n"
                     "* Combined with ML entropy analysis for hybrid detection\n"
                     "* 10 built-in rules: WannaCry, LockBit, BlackCat, Ryuk, REvil, Conti + generics",
                     ha="center", va="center", fontsize=8,
                     color=PDF_COLORS["text_dim"], fontfamily="monospace",
                     transform=ax3.transAxes)

            pdf.savefig(fig3, facecolor=fig3.get_facecolor(), bbox_inches="tight")
            plt.close(fig3)

        # ── PDF metadata ──
        d = pdf.infodict()
        d["Title"]   = "Ransomware Entropy Detector — Model Analysis Report"
        d["Author"]  = "Ransomware Entropy Detector v2.1"
        d["Subject"] = "Cybersecurity ML Analysis"
        d["Keywords"] = "ransomware, entropy, machine learning, cybersecurity"
        d["CreationDate"] = datetime.now()
