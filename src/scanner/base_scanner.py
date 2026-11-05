"""Base scanner engine: async HTTP handling, rate limiting, and result orchestration."""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Awaitable, Callable, List, Optional

import aiohttp
from bs4 import BeautifulSoup

from src.scanner.models import ScanResult, ScanSummary, CheckStatus
from src.utils.helpers import random_user_agent, setup_logging, utc_now_iso
from src.utils.validators import join_path, normalize_url

logger = setup_logging()


class BaseScanner:
    """Shared foundation for all security check modules.

    Subclasses implement ``async def run(self) -> List[ScanResult]`` and may call
    ``self.request(...)`` to fetch pages with automatic rate limiting and a
    rotating, realistic User-Agent.
    """

    name = "base"
    label = "Base Check"

    def __init__(
        self,
        target: str,
        request_delay: float = 1.0,
        timeout: float = 15.0,
        max_redirects: int = 5,
        user_agent: Optional[str] = None,
        session: Optional[aiohttp.ClientSession] = None,
        progress_callback: Optional[Callable[[CheckStatus], None]] = None,
        cookie_jar: Optional[aiohttp.CookieJar] = None,
    ):
        self.base_target = normalize_url(target)
        self.request_delay = request_delay
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = user_agent or random_user_agent()
        self.session = session
        self._owns_session = session is None
        self._progress_callback = progress_callback
        self._cookie_jar = cookie_jar
        self._last_request_time = 0.0
        self._request_lock: Optional[asyncio.Lock] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Create the HTTP session + lock if not provided externally."""
        if self._owns_session:
            jar = self._cookie_jar if self._cookie_jar else aiohttp.CookieJar()
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(
                cookie_jar=jar,
                timeout=timeout_obj,
            )
        self._request_lock = asyncio.Lock()

    async def stop(self) -> None:
        """Close the HTTP session if we created it."""
        if self._owns_session and self.session is not None:
            await self.session.close()

    async def __aenter__(self) -> "BaseScanner":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()

    # ------------------------------------------------------------------
    # Progress reporting
    # ------------------------------------------------------------------
    def _report(self, status: CheckStatus) -> None:
        if self._progress_callback is not None:
            try:
                self._progress_callback(status)
            except Exception:
                logger.exception("Progress callback failed")

    def _running(self) -> None:
        self._report(CheckStatus(name=self.label, status="running"))

    def _complete(self, message: str = "") -> None:
        self._report(CheckStatus(name=self.label, status="complete", message=message))

    def _error(self, message: str) -> None:
        self._report(CheckStatus(name=self.label, status="error", message=message))

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    async def _rate_limit(self) -> None:
        """Enforce the configured delay between requests."""
        if self._request_lock is None:
            self._request_lock = asyncio.Lock()
        async with self._request_lock:
            now = time.monotonic()
            wait = self._last_request_time + self.request_delay - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_time = time.monotonic()

    async def request(
        self,
        path: str = "",
        method: str = "GET",
        data: Optional[bytes] = None,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        allow_redirects: bool = True,
        full_url: Optional[str] = None,
    ) -> Optional[aiohttp.ClientResponse]:
        """Issue a rate-limited HTTP request against the target.

        Returns None on network failure (caller should degrade gracefully).
        """
        if self.session is None:
            await self.start()

        url = full_url or join_path(self.base_target, path)

        request_headers = {"User-Agent": self.user_agent}
        if headers:
            request_headers.update(headers)

        for attempt in range(3):
            await self._rate_limit()
            try:
                kwargs = dict(
                    method=method,
                    headers=request_headers,
                    params=params,
                    allow_redirects=allow_redirects,
                )
                if data is not None:
                    kwargs["data"] = data
                resp = await self.session.request(url=url, **kwargs)
                return resp
            except (aiohttp.ClientConnectorError, aiohttp.ClientPayloadError) as exc:
                logger.debug("Request failed (attempt %s): %s", attempt + 1, exc)
            except asyncio.TimeoutError:
                logger.debug("Request timed out (attempt %s): %s", attempt + 1, url)
            except aiohttp.ClientError as exc:
                logger.debug("Client error: %s", exc)
            if attempt == 2:
                break
            await asyncio.sleep(1 + attempt)
        self._error(f"Failed to reach {url}")
        return None

    async def get_text(
        self,
        path: str = "",
        params: Optional[dict] = None,
        full_url: Optional[str] = None,
        encoding: Optional[str] = None,
    ) -> str:
        """GET and return the response body text ('' on failure)."""
        resp = await self.request(path=path, params=params, full_url=full_url)
        if resp is None:
            return ""
        try:
            text = await resp.text()
        except Exception:
            text = ""
        finally:
            await resp.release() if hasattr(resp, "release") else None
        if encoding:
            try:
                text = resp.release if False else text
            except Exception:
                pass
        return text

    async def get_soup(
        self,
        path: str = "",
        params: Optional[dict] = None,
        full_url: Optional[str] = None,
    ) -> BeautifulSoup:
        """GET and return a BeautifulSoup document (empty soup on failure)."""
        text = await self.get_text(path=path, params=params, full_url=full_url)
        if not text:
            return BeautifulSoup("", "html.parser")
        return BeautifulSoup(text, "html.parser")

    async def get_status(self, path: str = "") -> Optional[int]:
        """GET and return the HTTP status code (None on failure)."""
        resp = await self.request(path=path)
        if resp is None:
            return None
        try:
            return resp.status
        finally:
            await resp.release() if hasattr(resp, "release") else None

    async def get_headers(self, path: str = "") -> Optional[dict]:
        """HEAD/GET and return the response headers dict ({} on failure)."""
        resp = await self.request(path=path, method="GET")
        if resp is None:
            return None
        try:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            # Deduplicate multiple headers of the same name
            return headers
        finally:
            await resp.release() if hasattr(resp, "release") else None

    # ------------------------------------------------------------------
    # Public API (subclasses override)
    # ------------------------------------------------------------------
    async def run(self) -> List[ScanResult]:
        raise NotImplementedError("Subclasses must implement run()")


def run_parallel(total: int, coro: Callable[[int], Awaitable[List[ScanResult]]], workers=4):
    """Run ``coro(i)`` for i in range(total) concurrently.

    Returns a flat list of results.
    """

    async def _fanout():
        semaphore = asyncio.Semaphore(workers)

        async def _guarded(i):
            async with semaphore:
                return await coro(i)

        results = await asyncio.gather(*(_guarded(i) for i in range(total)))
        flat = []
        for group in results:
            flat.extend(group)
        return flat

    return _fanout()