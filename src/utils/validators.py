"""Input validation and URL handling utilities."""

from urllib.parse import urlparse


SUPPORTED_PROTOCOLS = ("http", "https")


def normalize_url(target: str) -> str:
    """Normalize a user-provided target into a clean base URL."""
    target = target.strip().rstrip("/")
    if not target:
        raise ValueError("Target URL cannot be empty.")
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if parsed.scheme not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"Unsupported protocol: {parsed.scheme}")
    if not parsed.netloc:
        raise ValueError("Target URL must include a hostname (e.g. example.com).")
    return f"{parsed.scheme}://{parsed.netloc}"


def is_valid_url(target: str) -> bool:
    """Return True if the string looks like a usable HTTP(S) URL."""
    try:
        normalize_url(target)
        return True
    except ValueError:
        return False


def hostname_of(target: str) -> str:
    """Return just the hostname (no scheme) from a normalized URL."""
    return urlparse(normalize_url(target)).netloc


def join_path(base: str, path: str) -> str:
    """Join a base URL and a path safely."""
    base = normalize_url(base)
    path = path.lstrip("/")
    return f"{base}/{path}"