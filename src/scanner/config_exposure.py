"""Sensitive file & config exposure checks (wp-config.php, backups, logs)."""

from typing import List, Optional

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import ScanResult

# (probe path, severity, description, remediation)
EXPOSURE_PROBES = [
    (
        "wp-config.php",
        "Critical",
        "The WordPress configuration file appears to be directly accessible.",
        "Block direct access to wp-config.php at the web server level.",
    ),
    (
        "wp-config.php.bak",
        "Critical",
        "A backup of wp-config.php is accessible (contains DB credentials).",
        "Remove backups from web root and block *.bak/*.save files.",
    ),
    (
        "wp-config.php~",
        "Critical",
        "A backup/temp copy of wp-config.php is web-accessible.",
        "Remove editor/IDE backup files from the web root.",
    ),
    (
        "wp-config.php.old",
        "Critical",
        "An old copy of wp-config.php is accessible.",
        "Remove old copies of config files from the web root.",
    ),
    (
        ".env",
        "High",
        "The .env file (often containing secrets) is web-accessible.",
        "Block dotfiles in the web server configuration.",
    ),
    (
        "backup.sql",
        "High",
        "A database backup file is publicly accessible.",
        "Move database backups outside the web root and protect them.",
    ),
    (
        "db.sql",
        "High",
        "A database backup file is publicly accessible.",
        "Move database backups outside the web root and protect them.",
    ),
    (
        "wordpress.sql",
        "High",
        "A database backup file is publicly accessible.",
        "Move database backups outside the web root and protect them.",
    ),
    (
        "wp-content/debug.log",
        "Medium",
        "The WordPress debug log is web-accessible and may leak stack traces.",
        "Keep WP_DEBUG off in production and deny access to debug.log.",
    ),
    (
        "debug.log",
        "Medium",
        "A debug log is web-accessible.",
        "Remove debug logs from the web root.",
    ),
    (
        ".git/HEAD",
        "Medium",
        "A .git directory is exposed, allowing source code recovery.",
        "Remove .git from web root and block dotfiles.",
    ),
    (
        "readme.html",
        "Info",
        "The default WordPress readme (version disclosure) is present.",
        "Remove readme.html to reduce fingerprinting.",
    ),
    (
        "license.txt",
        "Info",
        "A license file is accessible (minor fingerprinting).",
        "Optionally remove license.txt.",
    ),
    (
        "phpinfo.php",
        "High",
        "A phpinfo() page is publicly accessible.",
        "Remove phpinfo.php from the web root immediately.",
    ),
    (
        "info.php",
        "High",
        "A phpinfo() page is publicly accessible.",
        "Remove info.php from the web root immediately.",
    ),
]


class ConfigExposureScanner(BaseScanner):
    """Probe for exposed sensitive files/backups."""

    name = "config_exposure"
    label = "Config & Info Exposure"

    async def run(self) -> List[ScanResult]:
        self._running()
        results: List[ScanResult] = []
        exposed = 0

        for path, severity, description, remediation in EXPOSURE_PROBES:
            status = await self.get_status(path)
            if status in (200, 301, 302, 403, 500):
                # 200/301/302 = accessible/revealing; 403 = file exists but blocked
                if status == 403:
                    blocking = "Access denied (403) - the file may exist but is blocked"
                elif status == 500:
                    blocking = "Server error (500) - often a PHP file executed"
                else:
                    blocking = f"HTTP {status} - file is accessible"
                exposed += 1
                results.append(
                    ScanResult(
                        category="Config & Info Exposure",
                        severity=severity,
                        title=f"Exposed: {path}",
                        description=description,
                        evidence=blocking,
                        remediation=remediation,
                    )
                )

        if exposed == 0:
            results.append(
                ScanResult(
                    category="Config & Info Exposure",
                    severity="Pass",
                    title="No sensitive files exposed",
                    description="None of the probed sensitive paths were accessible.",
                )
            )

        self._complete(f"{exposed} exposed paths")
        return results