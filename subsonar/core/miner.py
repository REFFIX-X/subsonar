"""Fetch the few well-known files worth mining (robots/sitemap/security.txt).

Kept separate from :mod:`subsonar.core.mining` (which is pure parsing) so the
parsers stay unit-testable without a network, and separate from the web prober so
a mining failure can never disturb the verification path.

Only the paths an organisation *publishes on purpose* are fetched, once, with a
64 KB cap and a short timeout:

* ``/robots.txt``
* ``/sitemap.xml`` (plus up to three ``<sitemapindex>`` children)
* ``/.well-known/security.txt``
"""

from __future__ import annotations

import asyncio
from typing import Any, Iterable, Sequence

from .config import USER_AGENT
from .mining import (
    extract_robots_sitemaps,
    extract_sitemap_locations,
    mine_sitemap_entries,
    mine_text,
)

try:  # pragma: no cover - mirrors subsonar.core.osint
    import aiohttp
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore[assignment]

__all__ = ["MAX_BODY", "PATHS", "fetch_and_mine", "fetch_paths"]

#: Byte cap per fetched file (these files are always small).
MAX_BODY = 64 * 1024
#: Paths worth fetching, in order.
PATHS: tuple[str, ...] = ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")
#: Sitemap-index children to follow.
MAX_SITEMAP_CHILDREN = 3


def _base_url(scheme: str, host: str, port: int) -> str:
    scheme = (scheme or "https").lower()
    default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    return f"{scheme}://{host}" + ("" if default else f":{port}")


async def fetch_paths(
    targets: Sequence[tuple[str, str, int]],
    *,
    paths: Sequence[str] = PATHS,
    timeout: float = 6.0,
) -> list[tuple[str, str, str]]:
    """Fetch *paths* from every target — returns ``[(host, path, body), …]``."""
    if aiohttp is None or not targets:
        return []
    out: list[tuple[str, str, str]] = []
    client_timeout = aiohttp.ClientTimeout(total=timeout, connect=4)
    connector = aiohttp.TCPConnector(ssl=False, limit=8)
    async with aiohttp.ClientSession(
        timeout=client_timeout,
        connector=connector,
        headers={"User-Agent": USER_AGENT},
        trust_env=False,
    ) as session:

        async def one(scheme: str, host: str, port: int, path: str) -> None:
            url = _base_url(scheme, host, port) + path
            try:
                async with session.get(url) as response:
                    if int(getattr(response, "status", 0) or 0) != 200:
                        return
                    body = await response.content.read(MAX_BODY)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - one bad path is not a failure
                return
            out.append((host, path, body.decode("utf-8", "replace")))

        await asyncio.gather(
            *(
                one(scheme, host, port, path)
                for scheme, host, port in targets
                for path in paths
            ),
            return_exceptions=True,
        )
    return out


async def fetch_urls(
    urls: Sequence[str], *, timeout: float = 6.0
) -> list[tuple[str, str]]:
    """Fetch absolute URLs and return ``[(url, body), …]`` (lazy/small files)."""
    if aiohttp is None or not urls:
        return []
    out: list[tuple[str, str]] = []
    client_timeout = aiohttp.ClientTimeout(total=timeout, connect=4)
    connector = aiohttp.TCPConnector(ssl=False, limit=4)
    async with aiohttp.ClientSession(
        timeout=client_timeout,
        connector=connector,
        headers={"User-Agent": USER_AGENT},
        trust_env=False,
    ) as session:

        async def one(url: str) -> None:
            try:
                async with session.get(url) as response:
                    if int(getattr(response, "status", 0) or 0) != 200:
                        return
                    body = await response.content.read(MAX_BODY)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - one bad URL is not a failure
                return
            out.append((url, body.decode("utf-8", "replace")))

        await asyncio.gather(*(one(url) for url in urls), return_exceptions=True)
    return out


async def fetch_and_mine(
    targets: Sequence[tuple[str, str, int]],
    domain: str,
    *,
    bus: Any = None,
    concurrency: int = 6,
    timeout: float = 6.0,
) -> list[str]:
    """Fetch the well-known files and return every in-scope hostname in them."""
    del concurrency  # the session limit already bounds the parallelism
    fetched = await fetch_paths(list(targets[:24]), timeout=timeout)
    if not fetched:
        return []
    found: list[str] = []

    # A sitemap *index* names child sitemaps rather than hosts: follow a few of
    # them (bounded) so a robots.txt → sitemapindex → hosts chain is mined too.
    children: list[str] = []
    for _host, path, body in fetched:
        if not body:
            continue
        candidates: list[str] = []
        if path.endswith("sitemap.xml"):
            candidates = extract_sitemap_locations(body)
        elif path.endswith("robots.txt"):
            candidates = extract_robots_sitemaps(body)
        for url in candidates:
            lowered = url.lower()
            if lowered.endswith((".xml", ".xml.gz")) and url not in children:
                children.append(url)
    if children:
        for url, body in await fetch_urls(
            children[:MAX_SITEMAP_CHILDREN], timeout=timeout
        ):
            fetched.append((url.split("/")[2], "/sitemap.xml", body))

    for host, path, body in fetched:
        if not body:
            continue
        hosts: Iterable[str]
        if path.endswith("sitemap.xml"):
            hosts = mine_sitemap_entries(body, domain)
        elif path.endswith("robots.txt"):
            hosts = [
                *mine_text(body, domain),
                *[
                    item
                    for url in [*extract_sitemap_locations(body), *extract_robots_sitemaps(body)]
                    for item in mine_text(url, domain)
                ],
            ]
        else:
            hosts = mine_text(body, domain)
        for candidate in hosts:
            if candidate not in found:
                found.append(candidate)
        if bus is not None and hosts:
            try:
                bus.emit(
                    f"mined {len(hosts)} in-scope host(s) from {path} on {host}",
                    "debug",
                    "osint",
                    host=host,
                )
            except Exception:  # pragma: no cover - logging is best effort
                pass
    return found
