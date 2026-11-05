"""XML-RPC endpoint status & abuse checks."""

from typing import List, Optional

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import ScanResult

LIST_METHODS_PAYLOAD = (
    '<?xml version="1.0"?><methodCall><methodName>system.listMethods'
    "</methodName><params></params></methodCall>"
)

SYSTEM_MULTICALL = "system.multicall"
PINGBACK_PING = "pingback.ping"
HTTP_HEADERS = {"Content-Type": "text/xml"}


class XmlrpcScanner(BaseScanner):
    """Check whether xmlrpc.php is enabled and whether it's dangerous."""

    name = "xmlrpc"
    label = "XML-RPC"

    async def run(self) -> List[ScanResult]:
        self._running()
        results: List[ScanResult] = []

        enabled, methods = await self._probe_methods()
        if not enabled:
            results.append(
                ScanResult(
                    category="XML-RPC",
                    severity="Pass",
                    title="XML-RPC disabled",
                    description=(
                        "xmlrpc.php did not respond with a method list, "
                        "so it is likely disabled or blocked."
                    ),
                )
            )
            self._complete("disabled")
            return results

        dangerous = [m for m in methods if m in (SYSTEM_MULTICALL, PINGBACK_PING)]
        dbg = ", ".join(dangerous) if dangerous else "none"
        results.append(
            ScanResult(
                category="XML-RPC",
                severity="High" if dangerous else "Medium",
                title="XML-RPC is enabled",
                description=(
                    "xmlrpc.php is accessible and responds to method calls. "
                    "If system.multicall or pingback.ping are available, "
                    "attackers can brute-force passwords or perform SSRF/DDoS "
                    "amplification."
                ),
                evidence=(
                    f"Enabled. Dangerous methods present: {dbg}. "
                    f"Methods listed: {min(len(methods), 20)}"
                ),
                remediation=(
                    "Disable XML-RPC via add_filter('xmlrpc_enabled', "
                    "'__return_false') if not required."
                ),
            )
        )

        self._complete(f"{len(methods)} methods exposed")
        return results

    # ------------------------------------------------------------------
    async def _probe_methods(self) -> tuple[bool, List[str]]:
        resp = await self.request(
            "xmlrpc.php",
            method="POST",
            data=LIST_METHODS_PAYLOAD.encode(),
            headers=HTTP_HEADERS,
        )
        if resp is None:
            return False, []
        try:
            status = resp.status
            body = await resp.text()
        except Exception:
            status = 0
            body = ""
        finally:
            await resp.release() if hasattr(resp, "release") else None

        if status not in (200,) or "<methodResponse>" not in body:
            return False, []

        methods = _parse_method_names(body)
        return True, methods


def _parse_method_names(body: str) -> List[str]:
    """Extract <string>...</string> method names from XML-RPC response."""
    import re

    return re.findall(r"<string>\s*([a-zA-Z0-9._]+)\s*</string>", body)