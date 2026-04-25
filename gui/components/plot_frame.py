"""
gui/components/plot_frame.py
==========================
Matplotlib figure embedded in CTk (CustomTkinter) frame.

Provides a reusable widget for embedding matplotlib charts.
Supports dark theme styling matching the Ransomware Detector UI.
"""

import matplotlib
matplotlib.use("Agg")

from matplotlib.figure import Figure
import numpy as np
from typing import Optional, List, Tuple

import customtkinter as ctk


class PlotFrame(ctk.CTkFrame):
    """
    A CTk frame that embeds a matplotlib Figure.

    Usage:
        plot = PlotFrame(parent, figsize=(6, 3))
        plot.plot_line([1, 2, 3], [10, 20, 15], title="Entropy Over Time")
    """

    def __init__(self, parent, figsize: Tuple[float, float] = (6, 3), **kwargs):
        self._figsize = figsize
        self._figure: Optional[Figure] = None
        self._mpl_canvas = None
        self._ax = None

        super().__init__(parent, **kwargs)

        self._setup_figure()
        self._setup_canvas()

    def _setup_figure(self):
        """Create matplotlib Figure."""
        self._figure = Figure(figsize=self._figsize, dpi=100, facecolor="#161E29")
        self._ax = self._figure.add_subplot(111)
        self._configure_axes()

    def _configure_axes(self):
        """Apply dark cybersecurity theme to axes."""
        self._ax.set_facecolor("#161E29")
        self._ax.tick_params(colors="#A3ADBD")
        self._ax.xaxis.label.set_color("#A3ADBD")
        self._ax.yaxis.label.set_color("#A3ADBD")
        for spine in self._ax.spines.values():
            spine.set_edgecolor("#263042")
        self._figure.patch.set_facecolor("#161E29")

    def _setup_canvas(self):
        """Create Matplotlib canvas inside CTk frame."""
        if self._mpl_canvas is not None:
            self._mpl_canvas.get_tk_widget().destroy()

        self._mpl_canvas = FigureCanvasTkAgg(self._figure, master=self)
        self._mpl_canvas.get_tk_widget().pack(fill="both", expand=True)
        self._figure.tight_layout()

    def clear(self):
        """Clear the figure."""
        if self._figure:
            self._figure.clear()
            self._ax = self._figure.add_subplot(111)
            self._configure_axes()

    # ─── Line Chart ──────────────────────────────────────────────────────────

    def plot(self, x, y, color="#60A5FA", label="", linewidth=1.5,
             xlabel="", ylabel="", title=""):
        """Plot a simple line chart."""
        self.clear()
        self._ax.plot(x, y, color=color, linewidth=linewidth, label=label)
        if xlabel:
            self._ax.set_xlabel(xlabel, color="#A3ADBD", fontsize=9)
        if ylabel:
            self._ax.set_ylabel(ylabel, color="#A3ADBD", fontsize=9)
        if title:
            self._ax.set_title(title, color="#60A5FA", fontsize=10, fontweight="bold", pad=6)
        if label:
            self._ax.legend(facecolor="#161E29", labelcolor="#E6EAF0",
                           edgecolor="#263042", fontsize=8)
        self._configure_axes()
        self._mpl_canvas.draw_idle()

    def plot_line(self, x: List, y: List,
                  title: str = "", xlabel: str = "", ylabel: str = "",
                  color: str = "#60A5FA", linewidth: float = 2.0,
                  threshold_line: Optional[float] = None,
                  threshold_color: str = "#EF4444"):
        """Plot a line chart with optional threshold line."""
        self.clear()
        self._ax.plot(x, y, color=color, linewidth=linewidth, marker="o", markersize=3)

        if threshold_line is not None:
            self._ax.axhline(y=threshold_line, color=threshold_color,
                            linestyle="--", linewidth=1.5, alpha=0.7,
                            label=f"Ngưỡng ({threshold_line})")
            self._ax.legend(facecolor="#161E29", labelcolor="#E6EAF0",
                           edgecolor="#263042", fontsize=8)

        if title:
            self._ax.set_title(title, color="#60A5FA", fontsize=10, fontweight="bold", pad=6)
        if xlabel:
            self._ax.set_xlabel(xlabel, color="#A3ADBD", fontsize=9)
        if ylabel:
            self._ax.set_ylabel(ylabel, color="#A3ADBD", fontsize=9)

        self._ax.tick_params(colors="#A3ADBD", labelsize=8)
        self._ax.grid(True, alpha=0.3, color="#263042")
        self._mpl_canvas.draw_idle()

    # ─── Entropy Real-time Chart ─────────────────────────────────────────────

    def plot_entropy_realtime(self, timestamps: List[str], entropy_values: List[float],
                              threshold: float = 7.5):
        """Plot real-time entropy chart with threshold line."""
        self.clear()

        x = list(range(len(entropy_values)))
        self._ax.plot(x, entropy_values, color="#60A5FA", linewidth=1.5,
                     marker="o", markersize=3)

        # Threshold line
        self._ax.axhline(y=threshold, color="#EF4444", linestyle="--",
                        linewidth=1.5, alpha=0.8, label=f"Ngưỡng cảnh báo ({threshold})")

        # Fill above threshold
        if len(x) > 0:
            self._ax.fill_between(x, entropy_values, threshold,
                                 where=[e > threshold for e in entropy_values],
                                 color="#EF4444", alpha=0.15)

        # Custom x-tick labels
        step = max(1, len(timestamps) // 5)
        tick_positions = list(range(0, len(timestamps), step))
        tick_labels = [timestamps[i] if i < len(timestamps) else "" for i in tick_positions]
        self._ax.set_xticks(tick_positions)
        self._ax.set_xticklabels(tick_labels, rotation=45, fontsize=7, color="#A3ADBD")

        self._ax.set_ylim(0, 8.5)
        self._ax.set_ylabel("Shannon Entropy (bits)", color="#A3ADBD", fontsize=9)
        self._ax.set_xlabel("Thời gian", color="#A3ADBD", fontsize=9)
        self._ax.set_title("Giám sát Entropy thời gian thực", color="#60A5FA",
                          fontsize=10, fontweight="bold", pad=6)
        self._ax.tick_params(colors="#A3ADBD", labelsize=8)
        self._ax.grid(True, alpha=0.3, color="#263042")
        self._ax.legend(loc="upper left", fontsize=8, facecolor="#161E29",
                       edgecolor="#263042", labelcolor="#E6EAF0")
        self._mpl_canvas.draw_idle()

    # ─── Bar Chart ───────────────────────────────────────────────────────────

    def bar(self, categories: List[str], values: List[float],
            colors: List[str] = None, ylabel: str = ""):
        """Plot a bar chart."""
        self.clear()
        bar_colors = colors or ["#60A5FA"] * len(values)
        self._ax.bar(categories, values, color=bar_colors,
                    edgecolor="#161E29", linewidth=0.5)
        if ylabel:
            self._ax.set_ylabel(ylabel, color="#A3ADBD", fontsize=9)
        self._ax.tick_params(axis="x", rotation=45, colors="#A3ADBD", labelsize=8)
        self._ax.tick_params(axis="y", colors="#A3ADBD", labelsize=8)
        for spine in self._ax.spines.values():
            spine.set_edgecolor("#263042")
        self._mpl_canvas.draw_idle()

    def plot_bar(self, categories: List[str], values: List[float],
                 title: str = "", xlabel: str = "", ylabel: str = "",
                 color: str = "#60A5FA"):
        """Plot a bar chart with labels."""
        self.clear()
        bars = self._ax.bar(categories, values, color=color, edgecolor="#263042", alpha=0.85)
        for bar in bars:
            height = bar.get_height()
            self._ax.text(bar.get_x() + bar.get_width() / 2., height,
                         f"{height:.0f}", ha="center", va="bottom",
                         fontsize=8, color="#E6EAF0")
        if title:
            self._ax.set_title(title, color="#60A5FA", fontsize=10, fontweight="bold", pad=6)
        if xlabel:
            self._ax.set_xlabel(xlabel, color="#A3ADBD", fontsize=9)
        if ylabel:
            self._ax.set_ylabel(ylabel, color="#A3ADBD", fontsize=9)
        self._ax.tick_params(axis="x", rotation=45, colors="#A3ADBD", labelsize=8)
        self._ax.tick_params(axis="y", colors="#A3ADBD", labelsize=8)
        self._ax.grid(True, axis="y", alpha=0.3, color="#263042")
        self._mpl_canvas.draw_idle()

    # ─── Pie Chart ───────────────────────────────────────────────────────────

    def pie(self, sizes: List[float], labels: List[str], colors: List[str],
            title: str = ""):
        """Plot a pie chart."""
        self.clear()
        # Filter zero values
        non_zero = [(label, size) for label, size in zip(labels, sizes) if size > 0]
        if not non_zero:
            non_zero = [("Chưa có dữ liệu", 1)]
        filtered_labels, filtered_sizes = zip(*non_zero)
        filtered_colors = colors[:len(filtered_labels)]

        wedges, texts, autotexts = self._ax.pie(
            filtered_sizes, labels=filtered_labels, colors=filtered_colors,
            autopct="%1.1f%%", startangle=90,
            textprops={"color": "#E6EAF0", "fontsize": 9},
            wedgeprops={"edgecolor": "#161E29", "linewidth": 2}
        )
        for at in autotexts:
            at.set_color("#161E29")
            at.set_fontweight("bold")
        if title:
            self._ax.set_title(title, color="#60A5FA", fontsize=10,
                              fontweight="bold", pad=8)
        self._mpl_canvas.draw_idle()

    def plot_pie(self, labels: List[str], sizes: List[float],
                 title: str = "", colors: List[str] = None):
        """Alias for pie()."""
        if colors is None:
            colors = ["#22C55E", "#FACC15", "#EF4444", "#60A5FA", "#A78BFA"]
        self.pie(sizes, labels, colors, title)

    # ─── Scatter Chart ───────────────────────────────────────────────────────

    def plot_scatter(self, x: List[float], y: List[float],
                     title: str = "", xlabel: str = "", ylabel: str = "",
                     color: str = "#60A5FA", alpha: float = 0.6):
        """Plot a scatter chart."""
        self.clear()
        self._ax.scatter(x, y, color=color, alpha=alpha, s=20,
                        edgecolors="#263042", linewidths=0.5)
        if title:
            self._ax.set_title(title, color="#60A5FA", fontsize=10, fontweight="bold", pad=6)
        if xlabel:
            self._ax.set_xlabel(xlabel, color="#A3ADBD", fontsize=9)
        if ylabel:
            self._ax.set_ylabel(ylabel, color="#A3ADBD", fontsize=9)
        self._ax.tick_params(colors="#A3ADBD", labelsize=8)
        self._ax.grid(True, alpha=0.3, color="#263042")
        self._mpl_canvas.draw_idle()

    def scatter_entropy(self, entropies, probabilities, risk_levels):
        """Scatter plot for scan results (entropy vs probability)."""
        self.clear()
        risk_colors = {
            "CRITICAL": "#EF4444", "HIGH": "#F59E0B",
            "MEDIUM": "#FACC15", "LOW": "#60A5FA",
            "SAFE": "#22C55E", "UNKNOWN": "#A3ADBD"
        }
        scatter_colors = [risk_colors.get(r, "#A3ADBD") for r in risk_levels]
        self._ax.scatter(entropies, probabilities, c=scatter_colors,
                        alpha=0.6, s=10, linewidths=0)
        self._ax.axhline(y=0.65, color="#F59E0B", linestyle="--",
                        linewidth=0.8, alpha=0.7)
        self._ax.axvline(x=7.2, color="#FACC15", linestyle="--",
                        linewidth=0.8, alpha=0.7)
        self._ax.set_xlabel("Entropy (b/B)", color="#A3ADBD", fontsize=9)
        self._ax.set_ylabel("Xác suất rủi ro", color="#A3ADBD", fontsize=9)
        self._ax.tick_params(colors="#A3ADBD", labelsize=8)
        self._ax.grid(True, alpha=0.3, color="#263042")
        self._mpl_canvas.draw_idle()

    # ─── Histogram ───────────────────────────────────────────────────────────

    def plot_histogram(self, data: List[float], bins: int = 20,
                       title: str = "", xlabel: str = "", ylabel: str = "Tần suất",
                       color: str = "#60A5FA"):
        """Plot a histogram."""
        self.clear()
        self._ax.hist(data, bins=bins, color=color, edgecolor="#263042", alpha=0.8)
        if title:
            self._ax.set_title(title, color="#60A5FA", fontsize=10, fontweight="bold", pad=6)
        if xlabel:
            self._ax.set_xlabel(xlabel, color="#A3ADBD", fontsize=9)
        self._ax.set_ylabel(ylabel, color="#A3ADBD", fontsize=9)
        self._ax.tick_params(colors="#A3ADBD", labelsize=8)
        self._ax.grid(True, axis="y", alpha=0.3, color="#263042")
        self._mpl_canvas.draw_idle()

    # ─── Signal Gauge ────────────────────────────────────────────────────────

    def signal_gauge(self, score: float, label: str = "Điểm đe dọa"):
        """Draw a horizontal threat score gauge."""
        self.clear()
        self._ax.set_xlim(0, 1)
        self._ax.set_ylim(0, 1)
        self._ax.axis("off")

        # Background arc
        theta = np.linspace(0, np.pi, 100)
        x_bg = 0.5 + 0.4 * np.cos(theta)
        y_bg = 0.2 + 0.15 * np.sin(theta)
        self._ax.plot(x_bg, y_bg, color="#263042", linewidth=8, solid_capstyle="butt")

        # Fill arc
        fill_idx = min(int(score * len(theta)), len(theta) - 1)
        x_fill = 0.5 + 0.4 * np.cos(theta[:fill_idx + 1])
        y_fill = 0.2 + 0.15 * np.sin(theta[:fill_idx + 1])
        fill_color = "#EF4444" if score > 0.7 else "#F59E0B" if score > 0.4 else "#22C55E"
        self._ax.plot(x_fill, y_fill, color=fill_color, linewidth=8, solid_capstyle="butt")

        self._ax.text(0.5, 0.55, f"{score:.0%}", ha="center", va="center",
                     fontsize=18, fontweight="bold", color=fill_color)
        self._ax.text(0.5, 0.38, label, ha="center", va="center",
                     fontsize=7, color="#A3ADBD")
        self._figure.patch.set_facecolor("#161E29")
        self._mpl_canvas.draw_idle()

    def plot_signal_gauge(self, score: float, max_score: float = 1.0,
                          title: str = "Điểm đe dọa"):
        """Alias for signal_gauge()."""
        self.signal_gauge(score / max_score, title)

    # ─── Feedback History ────────────────────────────────────────────────────

    def plot_feedback_history(self, dates: List[str], accuracies: List[float],
                               title: str = "Lịch sử Accuracy của model"):
        """Plot model accuracy over time."""
        self.clear()

        if not dates:
            self._ax.text(0.5, 0.5, "Chưa có lịch sử training",
                        ha="center", va="center", fontsize=10, color="#263042",
                        transform=self._ax.transAxes)
            self._mpl_canvas.draw_idle()
            return

        x = list(range(len(dates)))
        self._ax.plot(x, accuracies, color="#22C55E", linewidth=2,
                     marker="s", markersize=5, label="Accuracy")
        self._ax.fill_between(x, accuracies, alpha=0.1, color="#22C55E")

        # Reference lines
        self._ax.axhline(y=0.95, color="#60A5FA", linestyle="--",
                        linewidth=1, alpha=0.5, label="Mục tiêu (0.95)")
        self._ax.axhline(y=0.90, color="#FACC15", linestyle="--",
                        linewidth=1, alpha=0.5, label="Tối thiểu (0.90)")

        step = max(1, len(dates) // 5)
        tick_positions = list(range(0, len(dates), step))
        tick_labels = [dates[i] if i < len(dates) else "" for i in tick_positions]
        self._ax.set_xticks(tick_positions)
        self._ax.set_xticklabels(tick_labels, rotation=45, fontsize=7, color="#A3ADBD")

        self._ax.set_ylim(0.80, 1.02)
        self._ax.set_ylabel("Accuracy", color="#A3ADBD", fontsize=9)
        self._ax.set_xlabel("Ngày training", color="#A3ADBD", fontsize=9)
        self._ax.set_title(title, color="#60A5FA", fontsize=10, fontweight="bold", pad=6)
        self._ax.tick_params(colors="#A3ADBD", labelsize=8)
        self._ax.grid(True, alpha=0.3, color="#263042")
        self._ax.legend(loc="lower right", fontsize=8, facecolor="#161E29",
                       edgecolor="#263042", labelcolor="#E6EAF0")
        self._mpl_canvas.draw_idle()


# ─── Inline matplotlib backend import ────────────────────────────────────────────────
# Imported here — not at the top — because the calling module sets the
# matplotlib backend via ``matplotlib.use('Agg')`` *before* this import
# runs. Moving it to the top would force the default Tk backend during
# import time on headless test runners. Hence the deliberate E402 noqa.
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg  # noqa: E402
