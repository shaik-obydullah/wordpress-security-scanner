"""HTML report generation using the bundled Jinja2 template."""

from pathlib import Path
from typing import Dict, List, Union

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.reports.charts import _chart_bytes
from src.scanner.models import ScanResult, ScanSummary

TEMPLATE_DIR = Path(__file__).parent / "templates"


def build_report_data(
    summary: ScanSummary,
    include_chart: bool = True,
) -> Dict:
    """Convert a ScanSummary into the context dict the template expects."""
    counts = {k: 0 for k in ("Critical", "High", "Medium", "Low", "Info", "Pass")}
    for r in summary.results:
        if r.severity in counts:
            counts[r.severity] += 1

    chart = ""
    if include_chart:
        chart, _ = _chart_bytes(counts)

    # Sort findings: severity desc, then category asc
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Pass": 5}
    results = sorted(
        summary.results,
        key=lambda r: (order.get(r.severity, 9), r.category),
    )

    return {
        "summary": summary,
        "counts": counts,
        "chart": chart,
        "results": results,
    }


def render_html_report(summary: ScanSummary, include_chart: bool = True) -> str:
    """Render the HTML report as a standalone string."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")
    data = build_report_data(summary, include_chart=include_chart)
    return template.render(**data)


def write_html_report(summary: ScanSummary, output_path: str, include_chart: bool = True) -> str:
    """Write the HTML report to a file and return the path."""
    html = render_html_report(summary, include_chart=include_chart)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path