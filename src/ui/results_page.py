"""Results page: tree view of findings with severity grouping and detail panel."""

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QSplitter,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.scanner.models import ScanResult, ScanSummary
from src.utils.helpers import severity_color


class ResultsPage(QWidget):
    """Displays the findings from the most recent scan."""

    export_requested = Signal(object)  # ScanSummary

    def __init__(self, parent=None):
        super().__init__(parent)
        self.summary: Optional[ScanSummary] = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)

        top = QHBoxLayout()
        top.addWidget(QLabel("Target:"))
        self.target_label = QLabel("-")
        self.target_label.setStyleSheet("font-weight: bold;")
        top.addWidget(self.target_label)
        top.addStretch(1)

        top.addWidget(QLabel("Filter:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(
            ["All", "Critical", "High", "Medium", "Low", "Info", "Pass"]
        )
        self.filter_combo.currentTextChanged.connect(self.rebuild_tree)
        top.addWidget(self.filter_combo)

        self.count_label = QLabel("")
        top.addWidget(self.count_label)
        root.addLayout(top)

        splitter = QSplitter(Qt.Horizontal)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Severity", "Category", "Finding"])
        self.tree.setColumnWidth(0, 90)
        self.tree.setColumnWidth(1, 160)
        self.tree.currentItemChanged.connect(self._on_current_changed)
        splitter.addWidget(self.tree)

        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(True)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)

        root.addWidget(splitter, 1)

    # ------------------------------------------------------------------
    def set_summary(self, summary: ScanSummary):
        self.summary = summary
        self.target_label.setText(summary.target or "-")
        self.rebuild_tree()

    def rebuild_tree(self):
        self.tree.clear()
        if not self.summary:
            self.count_label.setText("")
            return

        severity_order = {
            "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Pass": 5,
        }
        results = sorted(
            self.summary.results,
            key=lambda r: (severity_order.get(r.severity, 9), r.category, r.title),
        )

        filter_text = self.filter_combo.currentText()
        groups: dict[str, list[ScanResult]] = {}
        for r in results:
            if filter_text != "All":
                sev_key = next(
                    (f for f in ("Critical", "High", "Medium", "Low", "Info", "Pass")
                     if r.severity.title() == f),
                    None,
                )
                if sev_key != filter_text:
                    continue
            groups.setdefault(r.severity, []).append(r)

        counts = self.summary.counts
        shown = sum(len(v) for v in groups.values())
        self.count_label.setText(
            f"{shown} shown &middot; "
            f"C:{counts['Critical']} H:{counts['High']} "
            f"M:{counts['Medium']} L:{counts['Low']}"
        )

        for severity in ("Critical", "High", "Medium", "Low", "Info", "Pass"):
            items = groups.get(severity)
            if not items:
                continue
            group_item = QTreeWidgetItem([severity, "", f"{len(items)} finding(s)"])
            group_item.setForeground(0, Qt.GlobalColor.red if severity in ("Critical", "High") else self._qt_color(severity))
            group_item.setData(0, Qt.ItemDataRole.UserRole, None)
            for r in items:
                child = QTreeWidgetItem(
                    [severity, r.category, r.title]
                )
                child.setForeground(0, self._qt_color(severity))
                child.setData(0, Qt.ItemDataRole.UserRole, r)
                group_item.addChild(child)
            self.tree.addTopLevelItem(group_item)
            group_item.setExpanded(severity in ("Critical", "High"))
        self.tree.resizeColumnToContents(0)

    def _qt_color(self, severity: str):
        from PySide6.QtGui import QColor

        return QColor(severity_color(severity))

    def _on_current_changed(self, current: QTreeWidgetItem, _previous):
        self.detail.setHtml("")
        if current is None:
            return
        r: Optional[ScanResult] = current.data(0, Qt.ItemDataRole.UserRole)
        if r is None:
            return

        html = [
            f"<h2 style='margin-bottom:2px'>{r.title}</h2>",
            f"<p style='color:#757575;margin:0'>{r.category}</p>",
            f"<p><span style='color:{severity_color(r.severity)};font-weight:bold'>"
            f"{r.severity}</span></p>",
        ]
        if r.description:
            html.append(f"<p>{r.description}</p>")
        if r.evidence:
            html.append(
                "<p><b>Evidence:</b></p>"
                f"<pre style='background:#f5f5f5;padding:8px;border-left:3px solid #ccc;"
                f"white-space:pre-wrap;word-break:break-word'>{r.evidence}</pre>"
            )
        if r.remediation:
            html.append(
                "<p><b>Remediation:</b></p>"
                f"<div style='background:#e8f5e9;padding:8px;border-left:3px solid #4caf50'>"
                f"{r.remediation}</div>"
            )
        self.detail.setHtml("".join(html))