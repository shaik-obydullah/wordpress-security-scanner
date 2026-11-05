"""Severity distribution chart rendered as a base64 PNG."""

import base64
import io
from typing import Dict, Tuple

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    _HAS_MPL = True
except ImportError:
    _HAS_MPL = False


def _chart_bytes(counts: Dict[str, int]) -> Tuple[str, bool]:
    """Return (b64-encoded PNG, whether a real chart was generated)."""
    if not _HAS_MPL:
        return "", False

    labels = ["Critical", "High", "Medium", "Low", "Info", "Pass"]
    values = [counts.get(l, 0) for l in labels]
    colors = ["#d32f2f", "#f44336", "#ff9800", "#ffc107", "#2196f3", "#4caf50"]

    if sum(values) == 0:
        return "", False

    fig, ax = plt.subplots(figsize=(6, 3.2), dpi=110)
    bars = ax.bar(labels, values, color=colors)
    ax.set_title("Findings by Severity")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=20)
    for bar, val in zip(bars, values):
        if val:
            ax.text(
                bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                str(val), ha="center", va="bottom", fontsize=9,
            )
    fig.tight_layout()
    buffer = io.BytesIO()
    fig.savefig(buffer, format="png")
    plt.close(fig)
    return base64.b64encode(buffer.getvalue()).decode(), True