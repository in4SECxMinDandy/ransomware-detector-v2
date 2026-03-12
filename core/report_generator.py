"""
report_generator.py
====================
Tạo báo cáo từ kết quả quét:
  1. Xuất CSV chi tiết
  2. Xuất biểu đồ PNG (Matplotlib) với 4 chart:
     - Pie chart: Phân phối Risk Level
     - Bar chart: Top 10 file nguy hiểm nhất
     - Histogram: Phân phối Entropy
     - Timeline: Entropy theo index file (trend)
"""

import os
import csv
import time
from typing import List, Dict, Any, Optional
from datetime import datetime

import numpy as np
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec

from core.scanner import ScanResult


# ─── Theme màu cybersecurity ───
THEME = {
    "bg":        "#0D1117",
    "panel":     "#161B22",
    "text":      "#C9D1D9",
    "green":     "#00FF88",
    "red":       "#FF2D2D",
    "orange":    "#FF8C00",
    "yellow":    "#FFD700",
    "blue":      "#00BFFF",
    "grid":      "#21262D",
    "accent":    "#58A6FF",
}

RISK_COLORS = {
    "CRITICAL": THEME["red"],
    "HIGH":     THEME["orange"],
    "MEDIUM":   THEME["yellow"],
    "LOW":      THEME["blue"],
    "SAFE":     THEME["green"],
    "UNKNOWN":  "#888888",
}


def export_csv(results: List[ScanResult], output_path: str) -> str:
    """
    Xuất kết quả quét ra file CSV.

    Columns: Path, Filename, Size(KB), Extension, Risk Level,
             Probability(%), Entropy, Scan Time(ms), Error
    """
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        # Header
        writer.writerow([
            "Path", "Filename", "Size (KB)", "Extension",
            "Risk Level", "Probability (%)", "Entropy (bits/byte)",
            "Scan Time (ms)", "Status", "Error"
        ])
        for r in results:
            writer.writerow([
                r.path,
                r.filename,
                round(r.size / 1024, 2) if r.size else 0,
                r.extension,
                r.risk_level,
                round(r.probability * 100, 2),
                round(r.entropy, 4),
                round(r.scan_time_ms, 2),
                "ENCRYPTED" if r.label == 1 else "SAFE",
                r.error or "",
            ])

    return output_path


def export_report_png(
    results: List[ScanResult],
    output_path: str,
    scan_directory: str = "",
    scan_mode: str = "Full Scan",
    scan_duration: float = 0.0
) -> str:
    """
    Tạo báo cáo hình ảnh PNG với 4 biểu đồ phân tích.

    Parameters
    ----------
    results       : danh sách kết quả ScanResult
    output_path   : đường dẫn file PNG đầu ra
    scan_directory: thư mục đã quét
    scan_mode     : "Full Scan" hoặc "Quick Scan"
    scan_duration : thời gian quét (giây)
    """
    if not results:
        return ""

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)

    plt.rcParams.update({
        "font.family":     "DejaVu Sans",
        "font.size":       10,
        "text.color":      THEME["text"],
        "axes.titlesize":  11,
        "axes.titleweight": "bold",
    })

    # ── Figure setup ──
    fig = plt.figure(figsize=(18, 14), facecolor=THEME["bg"])
    gs  = GridSpec(3, 3, figure=fig, hspace=0.45, wspace=0.35,
                   top=0.88, bottom=0.06, left=0.06, right=0.97)

    # ── Header ──
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total   = len(results)
    threats = sum(1 for r in results if r.label == 1)
    threat_pct = threats / total * 100 if total > 0 else 0

    header_color = THEME["red"] if threats > 0 else THEME["green"]
    status_text  = f"⚠ {threats} THREATS DETECTED ({threat_pct:.1f}%)" if threats > 0 else "✓ SYSTEM CLEAN"

    fig.text(0.5, 0.955, "RANSOMWARE ENTROPY DETECTOR — SCAN REPORT",
             ha="center", va="top", fontsize=18, fontweight="bold",
             color=THEME["green"], family="monospace")
    fig.text(0.5, 0.927, status_text,
             ha="center", va="top", fontsize=13, fontweight="bold", color=header_color)
    fig.text(0.5, 0.905, f"Directory: {scan_directory or 'N/A'}  |  Mode: {scan_mode}  |  "
             f"Files: {total}  |  Duration: {scan_duration:.1f}s  |  Generated: {now_str}",
             ha="center", va="top", fontsize=9, color=THEME["text"])

    # ─────────────────────────────────────────
    # Chart 1: Pie chart - Phân phối Risk Level (top-left, 2x1)
    # ─────────────────────────────────────────
    ax1 = fig.add_subplot(gs[0, :2])
    ax1.set_facecolor(THEME["panel"])

    risk_counts: Dict[str, int] = {}
    for r in results:
        rl = r.risk_level if r.risk_level else "UNKNOWN"
        risk_counts[rl] = risk_counts.get(rl, 0) + 1

    order    = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"]
    labels   = [k for k in order if k in risk_counts]
    sizes    = [risk_counts[k] for k in labels]
    colors   = [RISK_COLORS[k] for k in labels]
    explode  = [0.05 if k in ("CRITICAL", "HIGH") else 0 for k in labels]

    if sizes:
        wedges, texts, autotexts = ax1.pie(
            sizes, labels=None, colors=colors, explode=explode,
            autopct=lambda p: f"{p:.1f}%\n({int(p/100*sum(sizes))})",
            startangle=140, pctdistance=0.78,
            wedgeprops={"linewidth": 1.5, "edgecolor": THEME["bg"]}
        )
        for at in autotexts:
            at.set_fontsize(8)
            at.set_color(THEME["bg"])
            at.set_fontweight("bold")

        legend_patches = [
            mpatches.Patch(color=RISK_COLORS[l], label=f"{l}: {risk_counts[l]}")
            for l in labels
        ]
        ax1.legend(handles=legend_patches, loc="lower center", ncol=3,
                   bbox_to_anchor=(0.5, -0.12), frameon=False,
                   fontsize=9, labelcolor=THEME["text"])

    ax1.set_title("Risk Level Distribution", color=THEME["accent"], pad=10)

    # ─────────────────────────────────────────
    # Chart 2: Stats panel (top-right)
    # ─────────────────────────────────────────
    ax2 = fig.add_subplot(gs[0, 2])
    ax2.set_facecolor(THEME["panel"])
    ax2.axis("off")

    safe_count     = sum(1 for r in results if r.risk_level == "SAFE")
    critical_count = sum(1 for r in results if r.risk_level == "CRITICAL")
    high_count     = sum(1 for r in results if r.risk_level == "HIGH")
    medium_count   = sum(1 for r in results if r.risk_level == "MEDIUM")
    avg_entropy    = np.mean([r.entropy for r in results]) if results else 0
    max_proba      = max((r.probability for r in results), default=0)

    stats_text = [
        ("TOTAL FILES",    f"{total}",              THEME["accent"]),
        ("SAFE",           f"{safe_count}",          THEME["green"]),
        ("CRITICAL",       f"{critical_count}",      THEME["red"]),
        ("HIGH",           f"{high_count}",          THEME["orange"]),
        ("MEDIUM",         f"{medium_count}",        THEME["yellow"]),
        ("AVG ENTROPY",    f"{avg_entropy:.3f} b/B",  THEME["blue"]),
        ("MAX RISK PROB",  f"{max_proba*100:.1f}%",  THEME["red"] if max_proba >= 0.65 else THEME["yellow"]),
    ]

    y_pos = 0.95
    for label, value, color in stats_text:
        ax2.text(0.05, y_pos, label, transform=ax2.transAxes,
                 fontsize=8.5, color=THEME["text"], family="monospace")
        ax2.text(0.95, y_pos, value, transform=ax2.transAxes,
                 fontsize=10, color=color, fontweight="bold",
                 ha="right", family="monospace")
        # divider line (use plot in axes coordinates)
        ax2.plot([0, 1], [y_pos - 0.04, y_pos - 0.04],
                 color=THEME["grid"], linewidth=0.5,
                 transform=ax2.transAxes, clip_on=False)
        y_pos -= 0.13

    ax2.set_title("Summary Statistics", color=THEME["accent"], pad=10)

    # ─────────────────────────────────────────
    # Chart 3: Top 15 file nguy hiểm nhất (middle row, full width)
    # ─────────────────────────────────────────
    ax3 = fig.add_subplot(gs[1, :])
    ax3.set_facecolor(THEME["panel"])

    sorted_results = sorted(results, key=lambda r: r.probability, reverse=True)[:15]
    if sorted_results:
        filenames = [r.filename[:35] + "..." if len(r.filename) > 35 else r.filename
                     for r in sorted_results]
        probas    = [r.probability * 100 for r in sorted_results]
        bar_colors = [RISK_COLORS.get(r.risk_level, "#888") for r in sorted_results]

        y_pos_bar = range(len(filenames))
        bars = ax3.barh(list(y_pos_bar), probas, color=bar_colors, edgecolor=THEME["bg"],
                        height=0.7, linewidth=0.5)

        # Ngưỡng
        ax3.axvline(x=85, color=THEME["red"],    linestyle="--", linewidth=1.2, alpha=0.7, label="Critical (85%)")
        ax3.axvline(x=65, color=THEME["orange"], linestyle="--", linewidth=1.0, alpha=0.7, label="High (65%)")
        ax3.axvline(x=45, color=THEME["yellow"], linestyle="--", linewidth=0.8, alpha=0.7, label="Medium (45%)")

        # Labels
        ax3.set_yticks(list(y_pos_bar))
        ax3.set_yticklabels(filenames, fontsize=8, color=THEME["text"], family="monospace")
        ax3.set_xlabel("Ransomware Probability (%)", color=THEME["text"], fontsize=9)
        ax3.set_xlim(0, 110)
        ax3.tick_params(axis="x", colors=THEME["text"])
        ax3.spines["bottom"].set_color(THEME["grid"])
        ax3.spines["left"].set_color(THEME["grid"])
        ax3.spines["top"].set_visible(False)
        ax3.spines["right"].set_visible(False)
        ax3.set_facecolor(THEME["panel"])
        ax3.tick_params(colors=THEME["text"])

        # Giá trị trên bar
        for bar, p in zip(bars, probas):
            if p > 5:
                ax3.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
                         f"{p:.1f}%", va="center", ha="left", fontsize=7.5,
                         color=THEME["text"])

        ax3.legend(fontsize=8, frameon=False, labelcolor=THEME["text"],
                   loc="lower right", ncol=3)

    ax3.set_title("Top 15 Highest Risk Files", color=THEME["accent"], pad=8)

    # ─────────────────────────────────────────
    # Chart 4: Histogram entropy (bottom-left)
    # ─────────────────────────────────────────
    ax4 = fig.add_subplot(gs[2, :2])
    ax4.set_facecolor(THEME["panel"])

    safe_entropies = [r.entropy for r in results if r.label == 0 and r.entropy > 0]
    enc_entropies  = [r.entropy for r in results if r.label == 1 and r.entropy > 0]

    bins = np.linspace(0, 8, 40)
    if safe_entropies:
        ax4.hist(safe_entropies, bins=bins, color=THEME["green"], alpha=0.65,
                 label=f"SAFE ({len(safe_entropies)})", edgecolor=THEME["bg"])
    if enc_entropies:
        ax4.hist(enc_entropies, bins=bins, color=THEME["red"], alpha=0.65,
                 label=f"ENCRYPTED ({len(enc_entropies)})", edgecolor=THEME["bg"])

    ax4.axvline(x=7.2, color=THEME["yellow"], linestyle="--", linewidth=1.2,
                alpha=0.8, label="Threshold 7.2 b/B")
    ax4.set_xlabel("Shannon Entropy (bits/byte)", color=THEME["text"], fontsize=9)
    ax4.set_ylabel("File Count", color=THEME["text"], fontsize=9)
    ax4.tick_params(colors=THEME["text"])
    ax4.spines["bottom"].set_color(THEME["grid"])
    ax4.spines["left"].set_color(THEME["grid"])
    ax4.spines["top"].set_visible(False)
    ax4.spines["right"].set_visible(False)
    ax4.legend(fontsize=8, frameon=False, labelcolor=THEME["text"])
    ax4.set_title("Entropy Distribution: SAFE vs ENCRYPTED", color=THEME["accent"], pad=8)

    # ─────────────────────────────────────────
    # Chart 5: Scatter entropy vs probability (bottom-right)
    # ─────────────────────────────────────────
    ax5 = fig.add_subplot(gs[2, 2])
    ax5.set_facecolor(THEME["panel"])

    scatter_colors = [RISK_COLORS.get(r.risk_level, "#888") for r in results]
    scatter_x = [r.entropy for r in results]
    scatter_y = [r.probability * 100 for r in results]

    ax5.scatter(scatter_x, scatter_y, c=scatter_colors, alpha=0.6, s=15, linewidths=0)
    ax5.axhline(y=65, color=THEME["orange"], linestyle="--", linewidth=0.8, alpha=0.7)
    ax5.axvline(x=7.2, color=THEME["yellow"], linestyle="--", linewidth=0.8, alpha=0.7)
    ax5.set_xlabel("Shannon Entropy (b/B)", color=THEME["text"], fontsize=9)
    ax5.set_ylabel("Risk Probability (%)", color=THEME["text"], fontsize=9)
    ax5.tick_params(colors=THEME["text"])
    ax5.spines["bottom"].set_color(THEME["grid"])
    ax5.spines["left"].set_color(THEME["grid"])
    ax5.spines["top"].set_visible(False)
    ax5.spines["right"].set_visible(False)
    ax5.set_title("Entropy vs Probability", color=THEME["accent"], pad=8)

    # ── Footer ──
    fig.text(0.5, 0.01,
             "Ransomware Entropy Detector v1.0  |  Random Forest ML Engine  |  © 2026 PTIT — Security Research",
             ha="center", fontsize=8, color="#555555", style="italic")

    plt.savefig(output_path, dpi=150, bbox_inches="tight",
                facecolor=THEME["bg"], edgecolor="none")
    plt.close(fig)

    return output_path
