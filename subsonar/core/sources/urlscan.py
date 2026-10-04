"""urlscan.io search-API plugin (free, no API key for public results)."""

from __future__ import annotations

import json
from typing import Any, AsyncIterator
from urllib.parse import quote

from ._base import DiscoverySource, register

ENDPOINT = "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"


def parse_page(text: str) -> tuple[list[str], str | None]:
    """Parse one urlscan page into ``(hosts, next_cursor)``.

    The search API returns at most ``size`` results and paginates with a
    ``search_after`` cursor (echoed in the response) while ``has_more`` is true.
    """
    out: list[str] = []
    try:
        payload: Any = json.loads(text)
    except Exception:
        return out, None
    if not isinstance(payload, dict):
        return out, None
    results = payload.get("results")
    if isinstance(results, list):
        for entry in results:
            if not isinstance(entry, dict):
                continue
            page = entry.get("page")
            if not isinstance(page, dict):
                continue
            domain = page.get("domain")
            if isinstance(domain, str) and domain.strip():
                out.append(domain.strip())
    cursor = payload.get("search_after")
    if not payload.get("has_more") or not isinstance(cursor, str) or not cursor:
        return out, None
    return out, cursor


def parse_results(text: str) -> list[str]:
    """Extract ``results[].page.domain`` values from a urlscan search response."""
    return parse_page(text)[0]


@register
class UrlScanSource(DiscoverySource):
    """Hostnames observed by urlscan.io for the target domain."""

    name = "urlscan"
    free = True
    requires_key = False
    description = "urlscan.io public scan search (no key for public results)"
    ENDPOINT = ENDPOINT
    #: urlscan caps a page at ``size`` results and paginates with ``search_after``.
    MAX_PAGES = 10

    async def fetch_hosts(self, domain: str) -> AsyncIterator[str]:
        cursor: str | None = None
        for _ in range(self.MAX_PAGES):
            url = self.ENDPOINT.format(domain=domain)
            if cursor:
                url += f"&search_after={quote(cursor, safe='')}"
            status, text = await self.get_text(url)
            if status != 200:
                if cursor is None:
                    raise RuntimeError(f"urlscan.io returned HTTP {status}")
                break
            hosts, cursor = parse_page(text)
            for host in hosts:
                yield host
            if not cursor:
                break


__all__ = ["ENDPOINT", "UrlScanSource", "parse_results"]
