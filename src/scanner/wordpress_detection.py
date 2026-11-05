"""WordPress core detection & version fingerprinting."""

import re
from typing import List, Optional

from bs4 import BeautifulSoup

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import ScanResult

VERSION_PATTERNS = [
    re.compile(r"""(?:wordpress)[\s\-]*([0-9]{1,2}(?:\.[0-9]{1,2}){1,3})""", re.I),
    re.compile(r"ver=([0-9]{1,2}(?:\.[0-9]{1,2}){1,3})"),
    re.compile(r"wp-emoji-release(?:\.min)?\.js\?ver=([0-9.]{3,})"),
]

GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
README_VERSION_RE = re.compile(r"Version ([0-9]{1,2}(?:\.[0-9]{1,2}){1,3})", re.I)


class WordPressDetector(BaseScanner):
    """Detect whether the target is WordPress and fingerprint its version."""

    name = "wordpress_detection"
    label = "WordPress Detection"

    async def run(self) -> List[ScanResult]:
        self._running()
        results: List[ScanResult] = []

        homepage = await self.get_text("")
        if not homepage:
            self._error("No response from homepage")
            results.append(
                ScanResult(
                    category="WordPress Detection",
                    severity="Medium",
                    title="Unreachable homepage",
                    description="The target did not return an HTTP response for the homepage.",
                    remediation="Check the target URL and that the site is online.",
                )
            )
            self._complete()
            return results

        is_wordpress = self._looks_like_wordpress(homepage)
        version = await self._detect_version(homepage)

        if not is_wordpress:
            results.append(
                ScanResult(
                    category="WordPress Detection",
                    severity="Info",
                    title="Not WordPress",
                    description=(
                        "The target does not appear to run WordPress "
                        "based on common fingerprints."
                    ),
                )
            )
            self._complete()
            return results

        results.append(
            ScanResult(
                category="WordPress Detection",
                severity="Info",
                title="WordPress site detected",
                description="The target runs WordPress.",
                evidence=f"Version identified: {version or 'unknown'}",
            )
        )

        if version:
            results.append(
                ScanResult(
                    category="WordPress Detection",
                    severity="Info",
                    title="WordPress version disclosed",
                    description="The WordPress version was identified via public fingerprints.",
                    evidence=f"Detected version: {version}",
                    remediation=(
                        "Remove the generator meta tag and hide version strings in "
                        "assets to reduce fingerprinting."
                    ),
                )
            )

            outdated = self._is_outdated(version)
            if outdated:
                results.append(
                    ScanResult(
                        category="WordPress Detection",
                        severity="High",
                        title="Outdated WordPress core",
                        description=(
                            f"The detected version ({version}) is no longer supported "
                            "and may contain known, publicly-documented vulnerabilities."
                        ),
                        evidence=f"Detected version: {version}",
                        remediation="Update WordPress core to the latest stable release.",
                    )
                )

        return results

    # ------------------------------------------------------------------
    @staticmethod
    def _looks_like_wordpress(html: str) -> bool:
        markers = [
            "wp-content",
            "wp-includes",
            "wp-emoji",
            'name="generator" content="WordPress',
            "/wp-json/",
            "/wp-admin/",
            "wp-login.php",
        ]
        lowered = html.lower()
        return any(m in lowered for m in markers)

    async def _detect_version(self, homepage_html: str) -> Optional[str]:
        # 1) Generator meta tag
        match = re.search(r'content="WordPress ([0-9][0-9.]*)"', homepage_html, re.I)
        candidate = match.group(1) if match else None
        if candidate:
            return candidate

        # 2) Feed generator
        try:
            feed = await self.get_text("feed/")
            feed_match = re.search(r'<generator>[^<]*https://wordpress.org/\?v=([0-9.]+)</generator>', feed)
            if feed_match:
                return feed_match.group(1)
        except Exception:
            pass

        # 3) readme.html
        readme = await self.get_text("readme.html")
        if readme:
            r_match = README_VERSION_RE.search(readme)
            if r_match:
                return r_match.group(1)

        # 4) Asset version strings in homepage
        asset = VERSION_PATTERNS[2].search(homepage_html)
        if asset:
            return asset.group(1)

        return None

    @staticmethod
    def _is_outdated(version: str) -> bool:
        """Heuristic: treat < 6.0 as outdated (adjust as needed)."""
        try:
            parts = [int(p) for p in version.split(".")]
            major = parts[0]
            minor = parts[1] if len(parts) > 1 else 0
            return (major, minor) < (6, 0)
        except Exception:
            return False