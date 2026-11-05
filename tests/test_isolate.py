"""Isolate which scanner hangs against the mock server."""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.mock_server import start_mock_server
from src.scanner.wordpress_detection import WordPressDetector
from src.scanner.security_headers import SecurityHeadersScanner
from src.scanner.plugin_scanner import PluginScanner


async def timed(name, coro, timeout=10):
    started = time.monotonic()
    try:
        results = await asyncio.wait_for(coro, timeout)
        print(f"{name}: OK ({len(results)} results) in {time.monotonic()-started:.1f}s")
        for r in results:
            print(f"   [{r.severity}] {r.title}")
    except asyncio.TimeoutError:
        print(f"{name}: TIMEOUT after {timeout}s")
    except Exception as e:
        print(f"{name}: ERROR {type(e).__name__}: {e}")


async def main():
    server = start_mock_server(8807)
    try:
        await timed("WordPressDetector", WordPressDetector(target="http://127.0.0.1:8807", request_delay=0.0, timeout=3).run())
        await timed("SecurityHeaders", SecurityHeadersScanner(target="http://127.0.0.1:8807", request_delay=0.0, timeout=3).run())
    finally:
        server.shutdown()


if __name__ == "__main__":
    asyncio.run(main())