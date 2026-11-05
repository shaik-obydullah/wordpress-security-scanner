"""User & username enumeration checks."""

import json
import re
from typing import List, Optional

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import ScanResult

AUTHOR_RE = re.compile(r"/author/([a-zA-Z0-9_.\-]+)/", re.I)
REST_USER_RE = re.compile(r'"slug"\s*:\s*"([^"]+)"')


class UserEnumScanner(BaseScanner):
    """Detect user enumeration vectors: REST API, author archives, comment authors."""

    name = "user_enum"
    label = "User Enumeration"

    async def run(self) -> List[ScanResult]:
        self._running()
        results: List[ScanResult] = []
        usernames: set[str] = set()

        # 1) REST API users endpoint
        rest_users = await self._check_rest_users()
        if rest_users:
            result, usernames_found = rest_users
            usernames.update(usernames_found)
            results.append(result)

        # 2) Author archive redirects (?author=N)
        author_hits = await self._check_author_enumeration()
        if author_hits:
            usernames.update(author_hits)
            results.append(
                ScanResult(
                    category="User Enumeration",
                    severity="Medium",
                    title="Usernames leaked via author archives",
                    description=(
                        "The ?author=N redirect reveals usernames in "
                        "author archive URLs, enabling targeted brute force."
                    ),
                    evidence=", ".join(author_hits),
                    remediation=(
                        "Redirect /?author=N to homepage, disable author archives, "
                        "and block the REST users endpoint."
                    ),
                )
            )
        else:
            results.append(
                ScanResult(
                    category="User Enumeration",
                    severity="Pass",
                    title="No usernames leaked via author archives",
                    description="Author archive enumeration did not reveal usernames.",
                )
            )

        # 3) Login error messages
        login_info = await self._check_login_errors()
        if login_info:
            usernames.update(login_info[1])
            results.append(login_info[0])

        if usernames:
            results.append(
                ScanResult(
                    category="User Enumeration",
                    severity="Info",
                    title="Usernames identified",
                    description=(
                        "Usernames were collected, which is the first step in "
                        "a targeted brute-force attack."
                    ),
                    evidence=", ".join(sorted(usernames)),
                    remediation="See remediation for each enumeration vector above.",
                )
            )

        self._complete(f"{len(usernames)} usernames found")
        return results

    # ------------------------------------------------------------------
    async def _check_rest_users(self) -> Optional[tuple[ScanResult, List[str]]]:
        for endpoint in ("wp-json/wp/v2/users", "wp-json/wp/v2/users?per_page=100"):
            text = await self.get_text(endpoint)
            if not text:
                continue
            usernames = REST_USER_RE.findall(text)
            if usernames:
                return ScanResult(
                    category="User Enumeration",
                    severity="Medium",
                    title="REST API exposes user list",
                    description=(
                        "The /wp-json/wp/v2/users endpoint returns user "
                        "identifiers. This makes targeted attacks trivial."
                    ),
                    evidence=", ".join(usernames[:10]),
                    remediation=(
                        "Restrict the REST users endpoint via "
                        "rest_authentication_errors filter or a security plugin."
                    ),
                ), usernames
        return None

    async def _check_author_enumeration(self) -> List[str]:
        hits: List[str] = []
        for i in range(1, 11):
            resp = await self.request(
                f"?author={i}", allow_redirects=False
            )
            if resp is None:
                continue
            try:
                location = resp.headers.get("Location", "")
                status = resp.status
            finally:
                await resp.release() if hasattr(resp, "release") else None

            if status in (301, 302) and location:
                match = AUTHOR_RE.search(location)
                if match and match.group(1) not in ("author",):
                    hits.append(match.group(1))
        return hits

    async def _check_login_errors(self) -> Optional[tuple[ScanResult, List[str]]]:
        body_name = "nonexistent_user_x7y9"
        resp = await self.request(
            "wp-login.php",
            method="POST",
            data=f"log={body_name}&pwd=wrongpass&wp-submit=Log+In".encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp is None:
            return None
        try:
            text = await resp.text()
        except Exception:
            text = ""
        finally:
            await resp.release() if hasattr(resp, "release") else None

        if "Invalid username" in text or "Unknown username" in text:
            return ScanResult(
                category="User Enumeration",
                severity="Low",
                title="Login page reveals user existence",
                description=(
                    "The login error message distinguishes valid vs invalid "
                    "usernames, enabling username enumeration."
                ),
                evidence="Error message: 'Invalid username'",
                remediation=(
                    "Return a generic 'Invalid username or password' message "
                    "via the 'login_errors' filter."
                ),
            ), [body_name]
        return None