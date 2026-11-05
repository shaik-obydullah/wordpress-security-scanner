"""Directory listing & uploads checks."""

from typing import List

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import ScanResult

DIRECTORY_PROBES = [
    "wp-content/",
    "wp-content/plugins/",
    "wp-content/themes/",
    "wp-content/uploads/",
    "wp-includes/",
    "uploads/",
    "backup/",
    "wp-admin/",
    "wp-json/",
]

INDEX_OF_RE = (
    ("index of", "Apache"),
    ("listing", "Generic"),
    ("parent directory", "Apache"),
)


class DirectoryScanner(BaseScanner):
    """Check common WordPress directories for listing exposure."""

    name = "directory"
    label = "Directory Listing"

    async def run(self) -> List[ScanResult]:
        self._running()
        results: List[ScanResult] = []
        found = 0

        for path in DIRECTORY_PROBES:
            resp = await self.request(path)
            if resp is None:
                continue
            try:
                status = resp.status
                body = await resp.text() if status == 200 else ""
            except Exception:
                status = 0
                body = ""
            finally:
                await resp.release() if hasattr(resp, "release") else None

            if status != 200:
                continue

            body_lower = body.lower()
            listed = any(key in body_lower for key, _ in INDEX_OF_RE)
            if listed:
                found += 1
                server = next(
                    (server for key, server in INDEX_OF_RE if key in body_lower),
                    "unknown",
                )
                results.append(
                    ScanResult(
                        category="Directory Listing",
                        severity="Medium",
                        title=f"Directory listing enabled: /{path}",
                        description=(
                            "The directory discloses its file listing, which "
                            "reveals backups, versioned assets, and other "
                            "sensitive paths."
                        ),
                        evidence=f"Server style: {server}",
                        remediation=(
                            "Disable directory listings (Options -Indexes "
                            "for Apache, autoindex off for Nginx)."
                        ),
                    )
                )

        if found == 0:
            results.append(
                ScanResult(
                    category="Directory Listing",
                    severity="Pass",
                    title="No directory listing exposed",
                    description="None of the checked directories returned automatic listings.",
                )
            )

        self._complete(f"{found} listings found")
        return results