"""Scan orchestration: runs all selected scanner modules and aggregates results."""

import asyncio
import time
from typing import Callable, Dict, List, Optional

import aiohttp

from src.scanner.base_scanner import BaseScanner
from src.scanner.config_exposure import ConfigExposureScanner
from src.scanner.directory_scanner import DirectoryScanner
from src.scanner.models import CheckStatus, ScanResult, ScanSummary
from src.scanner.plugin_scanner import PluginScanner
from src.scanner.rest_api_scanner import RestApiScanner
from src.scanner.security_headers import SecurityHeadersScanner
from src.scanner.ssl_scanner import SslScanner
from src.scanner.user_enum import UserEnumScanner
from src.scanner.wordpress_detection import WordPressDetector
from src.scanner.xmlrpc_scanner import XmlrpcScanner
from src.utils.helpers import utc_now_iso

# Map module name -> factory (class + kwargs)
SCANNERS = {
    "wordpress_detection": WordPressDetector,
    "plugin_theme": PluginScanner,
    "user_enum": UserEnumScanner,
    "xmlrpc": XmlrpcScanner,
    "rest_api": RestApiScanner,
    "security_headers": SecurityHeadersScanner,
    "config_exposure": ConfigExposureScanner,
    "ssl": SslScanner,
    "directory": DirectoryScanner,
}

# Scan profile presets
PROFILES = {
    "Quick Scan": [
        "wordpress_detection",
        "plugin_theme",
        "security_headers",
        "xmlrpc",
    ],
    "Database Scan": [
        "user_enum",
        "rest_api",
        "config_exposure",
        "directory",
        "ssl",
    ],
    "Full Scan": list(SCANNERS.keys()),
}

ALL_CHECKS = list(SCANNERS.keys())


class ScanManager:
    """Runs the requested checks and produces a ScanSummary."""

    def __init__(
        self,
        target: str,
        profile: str = "Full Scan",
        selected_checks: Optional[List[str]] = None,
        request_delay: float = 1.0,
        timeout: float = 15.0,
        max_workers: int = 3,
        progress_callback: Optional[Callable[[CheckStatus], None]] = None,
        cookie_jar: Optional[aiohttp.CookieJar] = None,
    ):
        self.target = target
        self.profile = profile
        self.request_delay = request_delay
        self.timeout = timeout
        self.max_workers = max_workers
        self._progress_callback = progress_callback
        self._cookie_jar = cookie_jar

        if selected_checks:
            self.checks = [c for c in ALL_CHECKS if c in selected_checks]
        elif profile and profile not in ("Custom Scan",):
            self.checks = PROFILES.get(profile, ALL_CHECKS)
        else:
            self.checks = ALL_CHECKS

    async def run(self) -> ScanSummary:
        start = time.monotonic()
        summary = ScanSummary(
            target=self.target,
            timestamp=utc_now_iso(),
            meta={"profile": self.profile},
        )

        if self._progress_callback:
            self._progress_callback(
                CheckStatus(
                    name=f"Starting scan on {self.target}",
                    status="running",
                )
            )

        # Share one session + cookie jar across all scanners
        jar = self._cookie_jar or aiohttp.CookieJar()
        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
        shared_session = aiohttp.ClientSession(cookie_jar=jar, timeout=timeout_obj)

        try:
            semaphore = asyncio.Semaphore(self.max_workers)

            def make_scanner(check_name: str) -> BaseScanner:
                cls = SCANNERS[check_name]
                return cls(
                    target=self.target,
                    request_delay=self.request_delay,
                    timeout=self.timeout,
                    session=shared_session,
                    progress_callback=self._progress_callback,
                    cookie_jar=jar,
                )

            async def run_one(check_name: str) -> List[ScanResult]:
                async with semaphore:
                    scanner = make_scanner(check_name)
                    try:
                        return await scanner.run()
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        return [
                            ScanResult(
                                category=check_name,
                                severity="Medium",
                                title=f"Check '{check_name}' failed",
                                description="The module raised an unexpected error.",
                                evidence="",
                                remediation="Retry the scan or check network connectivity.",
                            )
                        ]

            results = await asyncio.gather(*(run_one(c) for c in self.checks))
            for group in results:
                summary.results.extend(group)
        finally:
            await shared_session.close()

        summary.duration = round(time.monotonic() - start, 2)
        if self._progress_callback:
            self._progress_callback(
                CheckStatus(
                    name="Scan complete",
                    status="complete",
                    message=(
                        f"{len(summary.results)} findings in "
                        f"{summary.duration}s"
                    ),
                )
            )
        return summary