"""End-to-end verification of the scanner engine against a local mock server."""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.scanner.scan_manager import ScanManager  # noqa: E402
from src.reports.generator import generate_report  # noqa: E402

from tests.mock_server import start_mock_server  # noqa: E402


async def main():
    server = start_mock_server(8807)
    try:
        manager = ScanManager(
            target="http://127.0.0.1:8807",
            profile="Full Scan",
            request_delay=0.0,
            timeout=5,
        )
        summary = await manager.run()

        print(f"Target: {summary.target}")
        print(f"Duration: {summary.duration}s")
        print(f"Findings: {len(summary.results)}")
        print(f"Risk score: {summary.score()}/100")
        print("-" * 60)
        counts = summary.counts
        print(f"Severity counts: {counts}")
        print("-" * 60)
        for r in summary.results:
            print(f"[{r.severity:>8}] {r.category:<24} {r.title}")

        # Generate both report formats into /tmp
        out_html = "/tmp/opencode/test-report.html"
        out_pdf = "/tmp/opencode/test-report.pdf"
        generate_report(summary, out_html, "html")
        generate_report(summary, out_pdf, "pdf", include_chart=True)
        h_exists = os.path.exists(out_html)
        p_exists = os.path.exists(out_pdf)
        print("-" * 60)
        print(f"HTML report: {'OK' if h_exists else 'FAIL'} ({out_html})")
        print(f"PDF report:  {'OK' if p_exists else 'FAIL'} ({out_pdf})")

        assert len(summary.results) > 0, "Expected at least some findings"
        assert counts["Medium"] > 0, "Expected medium findings (dir listing, users)"
        assert h_exists, "HTML report missing"
        assert p_exists, "PDF report missing"
        print("-" * 60)
        print("END-TO-END TEST PASSED")
    finally:
        server.shutdown()


if __name__ == "__main__":
    asyncio.run(main())