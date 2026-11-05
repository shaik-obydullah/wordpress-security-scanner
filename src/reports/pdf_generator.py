"""PDF report generation using ReportLab."""

from pathlib import Path
from typing import Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from src.scanner.models import ScanSummary

SEV_COLORS = {
    "Critical": colors.HexColor("#d32f2f"),
    "High": colors.HexColor("#f44336"),
    "Medium": colors.HexColor("#ff9800"),
    "Low": colors.HexColor("#ffc107"),
    "Info": colors.HexColor("#2196f3"),
    "Pass": colors.HexColor("#4caf50"),
}


def _severity_order(sev: str) -> int:
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Pass": 5}.get(sev, 9)


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            "HeroTitle",
            parent=styles["Title"],
            fontSize=24,
            leading=28,
            textColor=colors.HexColor("#141e30"),
        )
    )
    styles.add(
        ParagraphStyle(
            "SectionTitle",
            parent=styles["Heading2"],
            fontSize=16,
            spaceBefore=14,
            spaceAfter=8,
            textColor=colors.HexColor("#243b55"),
        )
    )
    styles.add(
        ParagraphStyle(
            "Muted",
            parent=styles["BodyText"],
            textColor=colors.HexColor("#757575"),
            fontSize=9,
        )
    )
    styles.add(
        ParagraphStyle(
            "BodyJustified",
            parent=styles["BodyText"],
            alignment=TA_JUSTIFY,
        )
    )
    return styles


def generate_pdf_report(summary: ScanSummary, output_path: str, chart_path: Optional[str] = None) -> str:
    """Generate a PDF security report. Returns the output path."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    styles = _build_styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"WordPress Security Report - {summary.target}",
        author="WordPress Security Scanner",
    )

    story = []

    # Header
    story.append(Paragraph("WordPress Security Scan Report", styles["HeroTitle"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Target: <b>{summary.target}</b>", styles["BodyText"]))
    story.append(
        Paragraph(
            f"Scan time: {summary.timestamp} &nbsp;|&nbsp; "
            f"Duration: {summary.duration} seconds &nbsp;|&nbsp; "
            f"Profile: {summary.meta.get('profile', 'Full Scan')}",
            styles["Muted"],
        )
    )
    story.append(Spacer(1, 12))

    # Executive summary
    story.append(Paragraph("Executive Summary", styles["SectionTitle"]))
    story.append(
        Paragraph(
            f"A security scan of <b>{summary.target}</b> completed with "
            f"<b>{len(summary.results)}</b> findings. The overall risk score is "
            f"<b>{summary.score}</b> / 100.",
            styles["BodyJustified"],
        )
    )
    story.append(Spacer(1, 10))

    # Severity counts table
    counts = {k: 0 for k in ("Critical", "High", "Medium", "Low", "Info", "Pass")}
    for r in summary.results:
        if r.severity in counts:
            counts[r.severity] += 1

    sev_rows = [
        ["Severity", "Count", "Severity", "Count"],
        [
            "Critical",
            counts["Critical"],
            "Low",
            counts["Low"],
        ],
        [
            "High",
            counts["High"],
            "Info",
            counts["Info"],
        ],
        [
            "Medium",
            counts["Medium"],
            "Pass",
            counts["Pass"],
        ],
    ]
    t = Table(sev_rows, colWidths=[55 * mm, 35 * mm, 55 * mm, 35 * mm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f5f5f5")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                ("ALIGN", (1, 0), (2, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BACKGROUND", (0, 1), (0, 1), SEV_COLORS["Critical"].lightColor if hasattr(SEV_COLORS['Critical'], 'lightColor') else colors.HexColor("#ffecec")),
                ("BACKGROUND", (0, 2), (0, 2), SEV_COLORS["High"].lightColor if hasattr(SEV_COLORS['High'], 'lightColor') else colors.HexColor("#feeeee")),
                ("BACKGROUND", (0, 3), (0, 3), SEV_COLORS["Medium"].lightColor if hasattr(SEV_COLORS['Medium'], 'lightColor') else colors.HexColor("#fff3e0")),
            ]
        )
    )
    story.append(t)

    if chart_path and Path(chart_path).exists():
        story.append(Spacer(1, 8))
        from reportlab.platypus import Image

        story.append(Image(chart_path, width=140 * mm, height=70 * mm))
    story.append(Spacer(1, 12))

    # Detailed findings
    story.append(Paragraph("Detailed Findings", styles["SectionTitle"]))

    sorted_results = sorted(summary.results, key=lambda r: (_severity_order(r.severity), r.category))
    for idx, r in enumerate(sorted_results, start=1):
        sev_color = SEV_COLORS.get(r.severity, colors.grey)
        header = Paragraph(
            f"{idx}. <font color='{sev_color.hexval() if hasattr(sev_color, 'hexval') else 'black'}'>"
            f"[{r.severity}]</font> {r.title}",
            ParagraphStyle(
                "FindingHeader",
                parent=styles["Heading3"],
                fontSize=11,
                spaceBefore=8,
            ),
        )
        story.append(header)
        cat_line = Paragraph(
            f"<b>Category:</b> {r.category}", styles["Muted"]
        )
        story.append(cat_line)
        if r.description:
            story.append(Paragraph(r.description, styles["BodyText"]))
        if r.evidence:
            story.append(
                Paragraph(
                    f"<b>Evidence:</b> <font face='Courier'>{_escape_pdf(r.evidence)}</font>",
                    styles["Muted"],
                )
            )
        if r.remediation:
            story.append(
                Paragraph(
                    f"<b>Remediation:</b> {r.remediation}",
                    styles["BodyText"],
                )
            )
        story.append(Spacer(1, 4))

    # Legal notice
    story.append(Paragraph("Legal Notice", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "This report was generated for <b>educational and defensive purposes</b>. "
            "Only scan WordPress sites you own or have explicit written permission to test. "
            "Unauthorized scanning is illegal under computer fraud laws (CFAA, Computer "
            "Misuse Act) and similar legislation worldwide.",
            styles["Muted"],
        )
    )

    doc.build(story)
    return output_path


def _escape_pdf(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )