"""SSL/TLS certificate validation for HTTPS targets."""

import ssl
from datetime import datetime, timezone
from typing import List, Optional, Tuple

import socket

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import ScanResult
from src.utils.validators import hostname_of


class SslScanner(BaseScanner):
    """Validate the TLS certificate of an HTTPS target."""

    name = "ssl"
    label = "SSL/TLS"

    async def run(self) -> List[ScanResult]:
        self._running()
        results: List[ScanResult] = []

        if not self.base_target.startswith("https://"):
            results.append(
                ScanResult(
                    category="SSL/TLS",
                    severity="Info",
                    title="HTTP target (no TLS check)",
                    description=(
                        "The target uses HTTP. SSL/TLS checks only apply "
                        "to HTTPS hosts."
                    ),
                )
            )
            self._complete()
            return results

        info = await self._get_certificate_info()
        if info is None:
            results.append(
                ScanResult(
                    category="SSL/TLS",
                    severity="High",
                    title="Could not validate TLS certificate",
                    description=(
                        "The site did not present a valid TLS certificate. "
                        "This may indicate a badly configured or missing certificate."
                    ),
                    remediation="Install and configure a valid TLS certificate.",
                )
            )
            self._complete()
            return results

        hostname, not_before, not_after, days_left = info

        if days_left < 0:
            results.append(
                ScanResult(
                    category="SSL/TLS",
                    severity="Critical",
                    title="TLS certificate expired",
                    description=f"Certificate expired {abs(days_left)} days ago.",
                    evidence=f"Not valid after: {not_after}",
                    remediation="Renew the TLS certificate immediately.",
                )
            )
        elif days_left <= 30:
            results.append(
                ScanResult(
                    category="SSL/TLS",
                    severity="High",
                    title="TLS certificate expiring soon",
                    description=f"The certificate expires in {days_left} days.",
                    evidence=f"Not valid after: {not_after}",
                    remediation="Renew the TLS certificate before it expires.",
                )
            )
        else:
            results.append(
                ScanResult(
                    category="SSL/TLS",
                    severity="Pass",
                    title="TLS certificate valid",
                    description=(
                        f"Certificate is valid for {days_left} more days."
                    ),
                    evidence=(
                        f"Hostname: {hostname}; valid to {not_after}"
                    ),
                )
            )

        self._complete(f"{days_left} days left")
        return results

    # ------------------------------------------------------------------
    async def _get_certificate_info(self) -> Optional[Tuple[str, str, str, int]]:
        hostname = hostname_of(self.base_target)
        port = 443
        context = ssl.create_default_context()

        try:
            loop = asyncio_get_running_loop()
            conn = await asyncio_open_connection(
                hostname, port, loop, ssl=context, server_hostname=hostname
            )
            ssl_obj = conn
            peer = None
            writer = None
            if hasattr(conn, "__aenter__"):
                pass
            cert = ssl_obj.getpeercert() if hasattr(ssl_obj, "getpeercert") else None
        except Exception:
            try:
                raw = socket.create_connection((hostname, port), timeout=self.timeout)
                wrapped = context.wrap_socket(raw, server_hostname=hostname)
                cert = wrapped.getpeercert()
                wrapped.close()
            except Exception:
                return None

        return self._extract_cert(cert)

    @staticmethod
    def _extract_cert(cert: Optional[dict]):
        if not cert:
            return None
        try:
            subject = dict(x[0] for x in cert["subject"])
            issuer = dict(x[0] for x in cert["issuer"])
            hostname = subject.get("commonName", "")
            not_before = cert.get("notBefore")
            not_after = cert.get("notAfter")
            if not_after is None:
                return None

            not_after_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = (not_after_dt - datetime.now(timezone.utc)).days
            return hostname, str(not_before), str(not_after), days_left
        except Exception:
            return None


def asyncio_get_running_loop():
    import asyncio

    return asyncio.get_running_loop()


def asyncio_open_connection(host, port, loop, ssl=None, server_hostname=None):
    import asyncio

    # For compatibility, just use open_connection directly
    return asyncio.open_connection(
        host, port, ssl=ssl, server_hostname=server_hostname
    )