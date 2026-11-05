"""Settings page: API token, defaults, and scan history."""

from typing import List

from PySide6.QtWidgets import (
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.database import operations as db


class SettingsPage(QWidget):
    """Application settings + stored scan history."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self.refresh_history()

    def _build_ui(self):
        root = QVBoxLayout(self)

        # WPScan API
        api_box = QGroupBox("WPScan API (optional)")
        api = QHBoxLayout(api_box)
        api.addWidget(
            QLabel("API token (checks known plugin vulnerabilities against WPVulnDB):")
        )
        self.api_token_input = QLineEdit()
        self.api_token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_token_input.setText(db.get_setting("wpscan_api_token"))
        api.addWidget(self.api_token_input, 1)
        save_api = QPushButton("Save Token")
        save_api.clicked.connect(self._save_api_token)
        api.addWidget(save_api)
        root.addWidget(api_box)

        # Defaults
        defaults_box = QGroupBox("Default Scan Settings")
        defaults = QHBoxLayout(defaults_box)
        defaults.addWidget(QLabel("Default profile:"))
        self.default_profile_input = QLineEdit("Full Scan")
        defaults.addWidget(self.default_profile_input)
        save_defaults = QPushButton("Save Defaults")
        save_defaults.clicked.connect(self._save_defaults)
        defaults.addWidget(save_defaults)
        defaults.addStretch(1)
        root.addWidget(defaults_box)

        # Disclaimer
        disclaimer = QLabel(
            "LEGAL NOTICE: This tool is for educational and defensive purposes "
            "only. Only scan WordPress sites you own or have written permission "
            "to test. Unauthorized scanning is illegal under computer fraud laws."
        )
        disclaimer.setWordWrap(True)
        disclaimer.setStyleSheet("color: #757575; font-size: 11px;")
        root.addWidget(disclaimer)

        root.addStretch(1)
        self.history_label = QLabel("")
        root.addWidget(self.history_label)

    def _save_api_token(self):
        db.set_setting("wpscan_api_token", self.api_token_input.text().strip())
        QMessageBox.information(self, "Saved", "WPScan API token saved.")

    def _save_defaults(self):
        db.set_setting("default_profile", self.default_profile_input.text().strip())
        QMessageBox.information(self, "Saved", "Default settings saved.")

    def refresh_history(self):
        scans = db.get_scans()
        if not scans:
            self.history_label.setText("No saved scans yet.")
            return
        lines = []
        for s in scans[:20]:
            lines.append(
                f"#{s['id']}  {s['target']}  {s['timestamp']}  "
                f"score={s['score']}  findings={s['finding_count']}"
            )
        self.history_label.setText("Recent scans:\n" + "\n".join(lines))