"""Plugin & theme enumeration via probe paths and public fingerprints."""

import re
from typing import List

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import ScanResult

# Well-known plugin slugs. In a fuller version you'd load a large database;
# this set covers extremely common targets.
COMMON_PLUGINS = [
    "akismet",
    "all-in-one-seo-pack",
    "autoptimize",
    "classic-editor",
    "contact-form-7",
    "duplicator",
    "elementor",
    "google-analytics-for-wordpress",
    "gravityforms",
    "jetpack",
    "limit-login-attempts-reloaded",
    "litespeed-cache",
    "mailchimp-for-wp",
    "newsletter",
    "ninja-forms",
    "one-click-demo-import",
    "redux-framework",
    "redirection",
    "revisr",
    "shortcodes-ultimate",
    "siteorigin-panels",
    "so-widgets-bundle",
    "updraftplus",
    "woocommerce",
    "wordfence",
    "wp-fastest-cache",
    "wp-mail-smtp",
    "wp-super-cache",
    "wpforms-lite",
    "wpforms",
    "wps-hide-login",
    "yoast-seo",
]

COMMON_THEMES = [
    "astra",
    "avada",
    "betheme",
    "divi",
    "enfold",
    "flatsome",
    "hello-elementor",
    "generatepress",
    "hestia",
    "kadence",
    "neve",
    "oceanwp",
    "salient",
    "shopkeeper",
    "storefront",
    "total",
    "twentyeleven",
    "twentytwelve",
    "twentythirteen",
    "twentyfourteen",
    "twentyfifteen",
    "twentysixteen",
    "twentyseventeen",
    "twentytwenty",
    "twentytwentytwo",
    "twentytwentythree",
    "twentytwentyfour",
    "x-store",
]

STABLE_TAG_RE = re.compile(r"Stable tag:\s*([0-9][0-9.]*)", re.I)
VERSION_RE = re.compile(r"Version:\s*([0-9][0-9.]*)", re.I)


class PluginScanner(BaseScanner):
    """Enumerate installed plugins/themes and their versions."""

    name = "plugin_scanner"
    label = "Plugin & Theme Enumeration"

    def __init__(self, *args, aggressive: bool = True, **kwargs):
        super().__init__(*args, **kwargs)
        self.aggressive = aggressive

    async def run(self) -> List[ScanResult]:
        self._running()
        results: List[ScanResult] = []

        plugins = await self._detect_plugins()
        themes = await self._detect_themes()

        if plugins:
            names = ", ".join(sorted(p["slug"] for p in plugins))
            results.append(
                ScanResult(
                    category="Plugin Enumeration",
                    severity="Info",
                    title="Installed plugins discovered",
                    description=(
                        "Public probe paths revealed installed plugins. "
                        "Attackers use this to target known vulnerabilities "
                        "in specific plugin versions."
                    ),
                    evidence=names,
                    remediation=(
                        "Keep plugins updated, remove unused ones, and consider "
                        "blocking readme.txt/style.css access."
                    ),
                )
            )
            for plugin in plugins:
                results.append(
                    ScanResult(
                        category="Plugin Enumeration",
                        severity="Info",
                        title=f"Plugin: {plugin['slug']}",
                        description=plugin["slug"],
                        evidence=f"Version: {plugin.get('version', 'unknown')}",
                    )
                )
        else:
            results.append(
                ScanResult(
                    category="Plugin Enumeration",
                    severity="Pass",
                    title="No plugins detected via public probes",
                    description="No common plugins were found through public README probes.",
                )
            )

        if themes:
            names = ", ".join(sorted(t["slug"] for t in themes))
            results.append(
                ScanResult(
                    category="Theme Enumeration",
                    severity="Info",
                    title="Theme discovered",
                    description=(
                        "The active WordPress theme was identified. Themes "
                        "can carry vulnerabilities too."
                    ),
                    evidence=names,
                    remediation=(
                        "Update themes regularly and remove unused ones."
                    ),
                )
            )
        else:
            results.append(
                ScanResult(
                    category="Theme Enumeration",
                    severity="Pass",
                    title="No theme detected",
                    description="No themes were identified via public style.css probes.",
                )
            )

        self._complete(
            f"{len(plugins)} plugins, {len(themes)} themes detected"
        )
        return results

    # ------------------------------------------------------------------
    async def _detect_plugins(self) -> List[dict]:
        found = []
        for slug in COMMON_PLUGINS:
            plugin = await self._probe_plugin(slug)
            if plugin:
                found.append(plugin)
        return found

    async def _probe_plugin(self, slug: str) -> dict | None:
        paths = [
            f"wp-content/plugins/{slug}/readme.txt",
            f"wp-content/plugins/{slug}/",
        ]
        for path in paths:
            resp = await self.request(path)
            if resp is None:
                continue
            try:
                status = resp.status
                body = ""
                if status < 300 and "readme" in path:
                    body = await resp.text()
            except Exception:
                status = 0
                body = ""
            finally:
                await resp.release() if hasattr(resp, "release") else None

            if status not in (200, 301, 302):
                continue

            version = None
            if body:
                match = STABLE_TAG_RE.search(body) or VERSION_RE.search(body)
                if match:
                    version = match.group(1)
            return {"slug": slug, "version": version}
        return None

    async def _detect_themes(self) -> List[dict]:
        found = []
        for slug in COMMON_THEMES:
            theme = await self._probe_theme(slug)
            if theme:
                found.append(theme)
        return found

    async def _probe_theme(self, slug: str) -> dict | None:
        path = f"wp-content/themes/{slug}/style.css"
        resp = await self.request(path)
        if resp is None:
            return None
        try:
            status = resp.status
            body = await resp.text() if status == 200 else ""
        except Exception:
            status = 0
            body = ""
        finally:
            await resp.release() if hasattr(resp, "release") else None

        if status != 200 or not body:
            return None

        version = None
        match = VERSION_RE.search(body)
        if match:
            version = match.group(1)
        return {"slug": slug, "version": version}