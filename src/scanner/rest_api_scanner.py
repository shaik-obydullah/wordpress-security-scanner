"""REST API exposure & info-disclosure checks."""

import re
from typing import List, Optional

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import ScanResult

ROUTE_RE = re.compile(r'"(/[^"]+)"\s*:')


class RestApiScanner(BaseScanner):
    """Probe the /wp-json/ endpoints for sensitive data exposure."""

    name = "rest_api"
    label = "REST API"

    CHECK_ENDPOINTS = [
        "wp-json/",
        "wp-json/wp/v2/users",
        "wp-json/wp/v2/posts",
        "wp-json/wp/v2/comments",
        "wp-json/wp/v2/media",
        "?rest_route=/wp/v2/users",
    ]

    async def run(self) -> List[ScanResult]:
        self._running()
        results: List[ScanResult] = []

        root_text = await self.get_text("wp-json/")
        if not root_text:
            results.append(
                ScanResult(
                    category="REST API",
                    severity="Pass",
                    title="REST API not exposed",
                    description="The REST API index returned no usable response.",
                )
            )
            self._complete()
            return results

        self._complete()
        if '"routes"' in root_text:
            results.append(
                ScanResult(
                    category="REST API",
                    severity="Info",
                    title="REST API enabled",
                    description="The WordPress REST API is enabled and returns its route index.",
                    evidence="wp-json/ returned a valid routes object.",
                )
            )

        # Probe sensitive endpoints
        for endpoint in self.CHECK_ENDPOINTS:
            finding = await self._check_endpoint(endpoint)
            if finding:
                results.append(finding)

        return results

    async def _check_endpoint(self, endpoint: str) -> Optional[ScanResult]:
        text = await self.get_text(endpoint)
        if not text:
            return None

        status = await self.get_status(endpoint)
        if status is None:
            return None

        usernames = re.findall(r'"slug"\s*:\s*"([^"]+)"', text)
        has_users = "users" in endpoint or "rest_route=/wp/v2/users" in endpoint

        if usernames:
            return ScanResult(
                category="REST API",
                severity="High" if has_users else "Medium",
                title=f"Exposed endpoint returns data: {endpoint}",
                description=(
                    f"The public endpoint '{endpoint}' returned data "
                    "including user identifiers."
                ),
                evidence=", ".join(usernames[:10]),
                remediation=(
                    "Restrict public access to sensitive REST endpoints "
                    "with authentication requirements."
                ),
            )

        return ScanResult(
            category="REST API",
            severity="Info",
            title=f"REST endpoint accessible: {endpoint}",
            description=f"The endpoint '{endpoint}' is publicly accessible (HTTP {status}).",
        )