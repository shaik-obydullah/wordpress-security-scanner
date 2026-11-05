"""Application entry point for the WordPress Security Scanner."""

import sys
from pathlib import Path

# Ensure the src package is importable regardless of working directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.database import operations as db  # noqa: E402
from src.utils.helpers import setup_logging  # noqa: E402


def main() -> int:
    """Launch the desktop application."""
    logger = setup_logging()

    # Ensure DB tables exist before the UI starts.
    try:
        db.init_db()
    except Exception as exc:  # pragma: no cover - environmental
        logger.warning("Could not initialise database: %s", exc)

    try:
        from PySide6.QtWidgets import QApplication

        from src.ui.main_window import MainWindow

        app = QApplication(sys.argv)
        app.setApplicationName("WordPress Security Scanner")
        app.setOrganizationName("WPSS")

        window = MainWindow()
        window.show()
        return app.exec()
    except ImportError as exc:
        logger.error("Missing dependency: %s", exc)
        print(
            "\nMissing required dependency. Install them with:\n"
            "    pip install -r requirements.txt\n",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())