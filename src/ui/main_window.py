"""Main application window: tabs + scan worker orchestration."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QMainWindow,
    QMessageBox,
    QTabWidget,
)

from src import APP_NAME, LEGAL_DISCLAIMER, __version__
from src.database import operations as db
from src.scanner.models import CheckStatus, ScanSummary
from src.ui.report_page import ReportPage
from src.ui.results_page import ResultsPage
from src.ui.scan_page import ScanPage
from src.ui.scan_worker import ScanWorker
from src.ui.settings_page import SettingsPage


class MainWindow(QMainWindow):
    """Top-level window bundling scan, results, reports and settings tabs."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{__version__}")
        self.resize(960, 680)
        self.worker: ScanWorker | None = None
        self.current_summary: ScanSummary | None = None
        self._build_ui()
        self._show_disclaimer_once()

    def _build_ui(self):
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        self.scan_page = ScanPage()
        self.results_page = ResultsPage()
        self.report_page = ReportPage()
        self.settings_page = SettingsPage()

        self.tabs.addTab(self.scan_page, "Scan")
        self.tabs.addTab(self.results_page, "Results")
        self.tabs.addTab(self.report_page, "Reports")
        self.tabs.addTab(self.settings_page, "Settings")

        self.setCentralWidget(self.tabs)

        self.statusBar().showMessage("Ready")
        self._font = QFont()
        self._setup_menu()

        # Wiring
        self.scan_page.start_scanned.connect(self._start_scan)
        self.scan_page.stop_requested.connect(self._stop_scan)

    def _setup_menu(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("&File")
        exit_action = file_menu.addAction("E&xit")
        exit_action.triggered.connect(self.close)

        help_menu = menubar.addMenu("&Help")
        about_action = help_menu.addAction("&About")
        about_action.triggered.connect(self._show_about)
        legal_action = help_menu.addAction("&Legal Disclaimer")
        legal_action.triggered.connect(self._show_disclaimer)

    # ------------------------------------------------------------------
    def _start_scan(self, target: str, profile: str, extras):
        if self.worker is not None and self.worker.isRunning():
            QMessageBox.warning(self, "Scan in progress", "A scan is already running.")
            return

        checks, delay, timeout, workers = extras

        self.worker = ScanWorker(
            target=target,
            profile=profile,
            selected_checks=checks,
            request_delay=delay,
            timeout=timeout,
            max_workers=workers,
            parent=self,
        )
        self.worker.progress.connect(self._on_progress)
        self.worker.finished_scan.connect(self._on_finished)
        self.worker.start()
        self.statusBar().showMessage(f"Scanning {target} ...")

    def _stop_scan(self):
        if self.worker is not None and self.worker.isRunning():
            self.worker.cancel()
            self.worker.terminate()
            self.statusBar().showMessage("Scan stopped.")

    def _on_progress(self, status: CheckStatus):
        self.scan_page.set_progress(status)

    def _on_finished(self, summary: ScanSummary):
        self.current_summary = summary
        self.results_page.set_summary(summary)
        self.report_page.set_summary(summary)
        self.scan_page.on_scan_finished(summary)

        # Persist to DB for history
        try:
            db.save_scan(
                target=summary.target,
                profile=summary.meta.get("profile", "Full Scan"),
                timestamp=summary.timestamp or "",
                duration=summary.duration,
                score=summary.score(),
                findings=[r.to_dict() for r in summary.results],
            )
            self.settings_page.refresh_history()
        except Exception:
            pass

        self.statusBar().showMessage(
            f"Scan complete - {len(summary.results)} findings "
            f"(risk score {summary.score()}/100)"
        )
        self.tabs.setCurrentWidget(self.results_page)
        self.worker = None

    # ------------------------------------------------------------------
    def _show_disclaimer_once(self):
        if db.get_setting("disclaimer_seen") != "1":
            self._show_disclaimer()
            db.set_setting("disclaimer_seen", "1")

    def _show_disclaimer(self):
        QMessageBox.information(self, "Legal Disclaimer", LEGAL_DISCLAIMER)

    def _show_about(self):
        QMessageBox.about(
            self,
            "About",
            f"<b>{APP_NAME}</b> v{__version__}<br><br>"
            "A desktop application for automated WordPress security testing "
            "with PDF/HTML report generation.<br><br>"
            "For educational and defensive use only.",
        )

    def closeEvent(self, event):
        if self.worker is not None and self.worker.isRunning():
            self.worker.cancel()
            self.worker.terminate()
            self.worker.wait(2000)
        super().closeEvent(event)