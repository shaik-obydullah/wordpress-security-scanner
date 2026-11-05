"""Security headers audit."""

from typing import List, Optional

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import ScanResult

REQUIRED_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "severity": "High",
        "remediation": (
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
            "once HTTPS is fully working."
        ),
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "Medium",
        "remediation": "Add 'X-Frame-Options: SAMEORIGIN' (or a frame-ancestors CSP directive).",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "Medium",
        "remediation": "Add 'X-Content-Type-Options: nosniff'.",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "Low",
        "remediation": "Add 'X-XSS-Protection: 1; mode=block' (legacy defense-in-depth).",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "Low",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "severity": "Medium",
        "remediation": (
            "Consider adding a Content-Security-Policy tuned for your theme/plugins."
        ),
    },
}


class SecurityHeadersScanner(BaseScanner):
    """Check the target's HTTP security headers."""

    name = "security_headers"
    label = "Security Headers"

    async def run(self) -> List[ScanResult]:
        self._running()
        results: List[ScanResult] = []

        headers = await self.get_headers()
        if headers is None:
            self._error("Could not retrieve headers")
            results.append(
                ScanResult(
                    category="Security Headers",
                    severity="Medium",
                    title="Could not inspect security headers",
                    description="The homepage did not return usable response headers.",
                )
            )
            self._complete()
            return results

        missing = []
        for header_key, info in REQUIRED_HEADERS.items():
            present = header_key in headers
            if present:
                value = headers[header_key]
                results.append(
                    ScanResult(
                        category="Security Headers",
                        severity="Pass",
                        title=f"{info['name']} present",
                        description=f"Header found with value: {value[:80]}",
                    )
                )
            else:
                missing.append(header_key)
                results.append(
                    ScanResult(
                        category="Security Headers",
                        severity=info["severity"],
                        title=f"Missing: {info['name']}",
                        description=(
                            f"The '{header_key}' header was not set on the homepage."
                        ),
                        remediation=info["remediation"],
                    )
                )

        if "x-powered-by" in headers:
            results.append(
                ScanResult(
                    category="Security Headers",
                    severity="Low",
                    title="X-Powered-By exposes server technology",
                    description="The X-Powered-By header reveals server-side technology details.",
                    evidence=f"Value: {headers['x-powered-by'][:80]}",
                    remediation="Disable server banner / X-Powered-By header output.",
                )
            )

        self._complete(f"{len(missing)} headers missing")
        return results