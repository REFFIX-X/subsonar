"""urlscan.io search-API plugin (free, no API key for public results)."""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

from ._base import DiscoverySource, register

ENDPOINT = "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"


def parse_results(text: str) -> list[str]:
    """Extract ``results[].page.domain`` values from a urlscan search response."""
    out: list[str] = []
    try:
        payload: Any = json.loads(text)
    except Exception:
        return out
    if not isinstance(payload, dict):
        return out
    results = payload.get("results")
    if not isinstance(results, list):
        return out
    for entry in results:
        if not isinstance(entry, dict):
            continue
        page = entry.get("page")
        if not isinstance(page, dict):
            continue
        domain = page.get("domain")
        if isinstance(domain, str) and domain.strip():
            out.append(domain.strip())
    return out


@register
class UrlScanSource(DiscoverySource):
    """Hostnames observed by urlscan.io for the target domain."""

    name = "urlscan"
    free = True
    requires_key = False
    description = "urlscan.io public scan search (no key for public results)"
    ENDPOINT = ENDPOINT

    async def fetch_hosts(self, domain: str) -> AsyncIterator[str]:
        status, text = await self.get_text(self.ENDPOINT.format(domain=domain))
        if status != 200:
            raise RuntimeError(f"urlscan.io returned HTTP {status}")
        for host in parse_results(text):
            yield host


__all__ = ["ENDPOINT", "UrlScanSource", "parse_results"]
