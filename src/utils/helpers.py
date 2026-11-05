"""Miscellaneous helper utilities."""

import hashlib
import logging
import random
import re
import socket
import time
from datetime import datetime, timezone

# A rotating pool of realistic User-Agent strings to reduce detection
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


def random_user_agent() -> str:
    """Return a random realistic User-Agent."""
    agent = random.choice(USER_AGENTS)
    hasher = hashlib.md5()
    hasher.update(f"{time.time()}{random.random()}".encode())
    return f"{agent} WPScanner/{hasher.hexdigest()[:8]}"


def severity_rank(severity: str) -> int:
    """Map a severity label to a numeric rank for sorting."""
    ranks = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Info": 0,
    }
    return ranks.get(severity, 0)


def severity_color(severity: str) -> str:
    """Return a hex colour for a severity label."""
    colors = {
        "Critical": "#d32f2f",
        "High": "#f44336",
        "Medium": "#ff9800",
        "Low": "#ffc107",
        "Info": "#2196f3",
        "Pass": "#4caf50",
    }
    return colors.get(severity, "#9e9e9e")


def utc_now_iso() -> str:
    """Return the current UTC time in ISO-8601 form."""
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def resolve_ip(target: str) -> str:
    """Best-effort resolve of a hostname to an IP."""
    from src.utils.validators import hostname_of

    try:
        return socket.gethostbyname(hostname_of(target))
    except Exception:
        return ""


def strip_html(text: str) -> str:
    """Remove HTML tags and collapse whitespace."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure a module-level logger."""
    logger = logging.getLogger("wpscanner")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger