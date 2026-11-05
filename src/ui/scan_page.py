"""Scan page: target input, profile selection, check picker, progress log."""

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.scanner.scan_manager import ALL_CHECKS, PROFILES, SCANNERS
from src.scanner.models import CheckStatus
from src.utils.validators import is_valid_url


class ScanPage(QWidget):
    """Tab that configures and launches a scan."""

    start_scanned = Signal(str, str, object)  # target, profile, checks
    stop_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(12)

        # --- Target section -------------------------------------------------
        target_box = QGroupBox("Target")
        target_layout = QVBoxLayout(target_box)

        url_row = QHBoxLayout()
        url_row.addWidget(QLabel("WordPress URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        self.url_input.setClearButtonEnabled(True)
        url_row.addWidget(self.url_input, 1)
        target_layout.addLayout(url_row)

        hint = QLabel("Only scan sites you own or have written permission to test.")
        hint.setStyleSheet("color: #757575; font-size: 11px;")
        target_layout.addWidget(hint)
        root.addWidget(target_box)

        # --- Profile section -------------------------------------------------
        profile_box = QGroupBox("Scan Profile")
        profile_layout = QGridLayout(profile_box)

        profile_layout.addWidget(QLabel("Profile:"), 0, 0)
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(list(PROFILES.keys()) + ["Custom Scan"])
        self.profile_combo.currentTextChanged.connect(self._on_profile_changed)
        profile_layout.addWidget(self.profile_combo, 0, 1)

        root.addWidget(profile_box)

        # --- Check picker (custom) --------------------------------------------
        self.checks_box = QGroupBox("Checks")
        checks_layout = QVBoxLayout(self.checks_box)
        self.check_boxes: dict[str, QCheckBox] = {}
        for check in ALL_CHECKS:
            cb = QCheckBox(SCANNERS[check].label)
            cb.setChecked(True)
            self.check_boxes[check] = cb
            checks_layout.addWidget(cb)
        checks_layout.addStretch(1)
        self.checks_box.setVisible(False)
        root.addWidget(self.checks_box, 1)

        # --- Settings row --------------------------------------------------
        settings_box = QGroupBox("Scan Settings")
        settings_layout = QGridLayout(settings_box)

        settings_layout.addWidget(QLabel("Request delay (s):"), 0, 0)
        self.delay_input = QLineEdit("1.0")
        self.delay_input.setFixedWidth(80)
        settings_layout.addWidget(self.delay_input, 0, 1)

        settings_layout.addWidget(QLabel("Timeout (s):"), 0, 2)
        self.timeout_input = QLineEdit("15")
        self.timeout_input.setFixedWidth(80)
        settings_layout.addWidget(self.timeout_input, 0, 3)

        settings_layout.addWidget(QLabel("Parallel checks:"), 0, 4)
        self.workers_input = QLineEdit("3")
        self.workers_input.setFixedWidth(80)
        settings_layout.addWidget(self.workers_input, 0, 5)

        settings_layout.setColumnStretch(6, 1)
        root.addWidget(settings_box)

        # --- Actions --------------------------------------------------------
        actions = QHBoxLayout()
        self.start_button = QPushButton("Start Scan")
        self.start_button.setStyleSheet(
            "background-color: #4caf50; color: white; font-weight: bold;"
            " padding: 8px 18px; border-radius: 4px;"
        )
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet(
            "background-color: #f44336; color: white; font-weight: bold;"
            " padding: 8px 18px; border-radius: 4px;"
        )
        actions.addWidget(self.start_button)
        actions.addWidget(self.stop_button)
        actions.addStretch(1)
        root.addLayout(actions)

        # --- Progress ---------------------------------------------------------
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # busy indicator while running
        self.progress_bar.setVisible(False)
        root.addWidget(self.progress_bar)

        self.status_label = QLabel("Ready.")
        self.status_label.setStyleSheet("color: #757575;")
        root.addWidget(self.status_label)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(2000)
        font = QFont("Monospace")
        font.setStyleHint(QFont.TypeWriter)
        self.log_view.setFont(font)
        root.addWidget(self.log_view, 1)

        # Wiring
        self.start_button.clicked.connect(self._start_clicked)
        self.stop_button.clicked.connect(self._stop_clicked)

    def _stop_clicked(self):
        self.log_message("Stop requested - waiting for in-flight requests...")
        self.stop_requested.emit()

    # ------------------------------------------------------------------
    def _on_profile_changed(self, text: str):
        self.checks_box.setVisible(text == "Custom Scan")

    def _selected_checks(self) -> Optional[list]:
        profile = self.profile_combo.currentText()
        if profile == "Custom Scan":
            return [k for k, cb in self.check_boxes.items() if cb.isChecked()]
        return None

    def _read_settings(self):
        try:
            delay = float(self.delay_input.text().strip() or "1.0")
        except ValueError:
            delay = 1.0
        try:
            timeout = float(self.timeout_input.text().strip() or "15")
        except ValueError:
            timeout = 15.0
        try:
            workers = int(self.workers_input.text().strip() or "3")
        except ValueError:
            workers = 3
        workers = max(1, min(10, workers))
        return delay, timeout, workers

    def _start_clicked(self):
        target = self.url_input.text().strip()
        if not is_valid_url(target):
            QMessageBox.warning(
                self,
                "Invalid target",
                "Please enter a valid WordPress URL, e.g. https://example.com",
            )
            return

        profile = self.profile_combo.currentText()
        checks = self._selected_checks()
        if profile == "Custom Scan" and not checks:
            QMessageBox.warning(self, "No checks selected", "Select at least one check.")
            return

        delay, timeout, workers = self._read_settings()
        self._set_running(True)
        self.log_message(f"Starting {profile} on {target} ...")
        self.start_scanned.emit(target, profile, (checks, delay, timeout, workers))

    def log_message(self, message: str):
        self.log_view.appendPlainText(message)
        self.status_label.setText(message)

    def set_progress(self, status: CheckStatus):
        if status.status == "running":
            self.status_label.setText(f"Running: {status.name}")
        elif status.status == "complete":
            self.status_label.setText(status.message or f"Complete: {status.name}")
        elif status.status == "error":
            self.status_label.setText(f"Error: {status.message}")

    def _set_running(self, running: bool):
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.progress_bar.setVisible(running)
        self.url_input.setEnabled(not running)
        self.profile_combo.setEnabled(not running)

    def on_scan_finished(self, summary):
        self._set_running(False)
        self.progress_bar.setValue(100)
        self.log_message(
            f"Scan complete: {len(summary.results)} findings in "
            f"{summary.duration} s. Risk score: {summary.score}/100"
        )