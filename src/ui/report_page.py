"""Report page: export findings to HTML or PDF in a user-chosen location."""

import os
from pathlib import Path
from typing import Optional

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.reports.generator import generate_report
from src.scanner.models import ScanSummary


class ReportPage(QWidget):
    """Configures and generates the security report for the last scan."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.summary: Optional[ScanSummary] = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)

        num_info = QLabel(
            "Run a scan first, then generate a PDF or HTML report. "
            "The report includes an executive summary, severity chart, and "
            "detailed remediation guidance."
        )
        num_info.setWordWrap(True)
        root.addWidget(num_info)

        # Format selection
        format_box = QGroupBox("Report Format")
        fmt = QHBoxLayout(format_box)
        fmt.addWidget(QLabel("Format:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems(["HTML", "PDF"])
        fmt.addWidget(self.format_combo)

        self.chart_check = QCheckBox("Include severity chart")
        self.chart_check.setChecked(True)
        fmt.addWidget(self.chart_check)
        fmt.addStretch(1)
        root.addWidget(format_box)

        # Output location
        out_box = QGroupBox("Output Location")
        out = QHBoxLayout(out_box)
        out.addWidget(QLabel("Save to:"))
        self.path_input = QLineEdit(str(Path.home() / "SecurityReports"))
        out.addWidget(self.path_input, 1)
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self._browse)
        out.addWidget(browse_button)
        root.addWidget(out_box)

        # Filename
        name_box = QGroupBox("Report Name")
        name = QHBoxLayout(name_box)
        name.addWidget(QLabel("Filename:"))
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("wordpress-security-report")
        name.addWidget(self.name_input, 1)
        root.addWidget(name_box)

        # Actions
        actions = QHBoxLayout()
        self.generate_button = QPushButton("Generate Report")
        self.generate_button.setStyleSheet(
            "background-color: #1976d2; color: white; font-weight: bold;"
            " padding: 8px 18px; border-radius: 4px;"
        )
        self.generate_button.clicked.connect(self._generate)
        actions.addWidget(self.generate_button)
        actions.addStretch(1)
        root.addLayout(actions)

        self.result_label = QLabel("")
        self.result_label.setWordWrap(True)
        self.result_label.setStyleSheet("color: #757575;")
        root.addWidget(self.result_label)
        root.addStretch(1)

    # ------------------------------------------------------------------
    def set_summary(self, summary: ScanSummary):
        self.summary = summary
        host = summary.target.replace("https://", "").replace("http://", "").replace("/", "_")
        if not self.name_input.text():
            self.name_input.setText(f"wpsec-{host}" if host else "wpsec-report")
        self.result_label.setText(f"Ready to generate for {summary.target}")

    def _browse(self):
        directory = QFileDialog.getExistingDirectory(self, "Choose output folder")
        if directory:
            self.path_input.setText(directory)

    def _generate(self):
        if not self.summary:
            self.result_label.setText("No scan results yet. Run a scan first.")
            return

        fmt = self.format_combo.currentText().strip().lower()
        output_dir = Path(self.path_input.text().strip() or Path.home() / "SecurityReports")
        name = self.name_input.text().strip() or "wpsec-report"
        output_path = str(output_dir / name)

        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            file_path = generate_report(
                self.summary,
                output_path,
                report_type=fmt,
                include_chart=self.chart_check.isChecked(),
            )
            self.result_label.setText(f"Report saved to: {file_path}")
        except Exception as exc:
            self.result_label.setText(f"Report generation failed: {exc}")