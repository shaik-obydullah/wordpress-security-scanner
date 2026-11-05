"""Unified report generation entry point."""

import base64
import io
import tempfile
from pathlib import Path
from typing import Optional

from src.reports.html_generator import write_html_report
from src.reports.pdf_generator import generate_pdf_report
from src.scanner.models import ScanSummary

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    _HAS_MPL = True
except ImportError:
    _HAS_MPL = False


def generate_report(
    summary: ScanSummary,
    output_path: str,
    report_type: str = "html",
    include_chart: bool = True,
) -> Optional[str]:
    """Generate an HTML or PDF report. Returns the output path or None."""
    output_path = output_path.strip()
    if report_type == "html":
        if not output_path.lower().endswith(".html"):
            output_path += ".html"
        return write_html_report(summary, output_path, include_chart=include_chart)
    elif report_type == "pdf":
        if not output_path.lower().endswith(".pdf"):
            output_path += ".pdf"
        chart_path = _make_chart_file(summary) if include_chart and _HAS_MPL else None
        try:
            return generate_pdf_report(summary, output_path, chart_path=chart_path)
        except Exception:
            # Fall back to chart-less PDF if ReportLab setup is broken
            return generate_pdf_report(summary, output_path, chart_path=None)
    else:
        raise ValueError(f"Unsupported report type: {report_type}")


def _make_chart_file(summary: ScanSummary) -> Optional[str]:
    counts = {k: 0 for k in ("Critical", "High", "Medium", "Low", "Info", "Pass")}
    for r in summary.results:
        if r.severity in counts:
            counts[r.severity] += 1

    labels = list(counts.keys())
    values = [counts[k] for k in labels]
    colors = ["#d32f2f", "#f44336", "#ff9800", "#ffc107", "#2196f3", "#4caf50"]
    if sum(values) == 0:
        return None

    fig, ax = plt.subplots(figsize=(8, 4), dpi=100)
    bars = ax.bar(labels, values, color=colors)
    ax.set_title("Findings by Severity")
    for bar, val in zip(bars, values):
        if val:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.03, str(val), ha="center", fontsize=9)
    fig.tight_layout()

    tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    fig.savefig(tmp.name)
    plt.close(fig)
    return tmp.name