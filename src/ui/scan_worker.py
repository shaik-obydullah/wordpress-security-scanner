"""QThread worker that runs an async scan and emits progress/results."""

import asyncio
from typing import Optional

from PySide6.QtCore import QThread, Signal

from src.scanner.scan_manager import ScanManager
from src.scanner.models import CheckStatus, ScanSummary


class ScanWorker(QThread):
    """Runs a ScanManager in a background thread with an asyncio loop."""

    progress = Signal(object)      # CheckStatus
    finished_scan = Signal(object)  # ScanSummary

    def __init__(
        self,
        target: str,
        profile: str,
        selected_checks: Optional[list] = None,
        request_delay: float = 1.0,
        timeout: float = 15.0,
        max_workers: int = 3,
        parent=None,
    ):
        super().__init__(parent)
        self._manager = ScanManager(
            target=target,
            profile=profile,
            selected_checks=selected_checks,
            request_delay=request_delay,
            timeout=timeout,
            max_workers=max_workers,
            progress_callback=self._on_progress,
        )
        self._cancelled = False

    def _on_progress(self, status: CheckStatus):
        self.progress.emit(status)

    def cancel(self):
        self._cancelled = True

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            summary: ScanSummary = loop.run_until_complete(self._manager.run())
            self.finished_scan.emit(summary)
        except asyncio.CancelledError:
            summary = ScanSummary(target=self._manager.target)
            self.finished_scan.emit(summary)
        except Exception as exc:
            summary = ScanSummary(target=self._manager.target)
            summary.results.append(
                CheckStatusToResult("Scan failed", str(exc))
            )
            self.finished_scan.emit(summary)
        finally:
            loop.close()


def CheckStatusToResult(title: str, description: str):
    from src.scanner.models import ScanResult

    return ScanResult(
        category="Engine",
        severity="High",
        title=title,
        description=description,
        remediation="Review the error and retry the scan.",
    )