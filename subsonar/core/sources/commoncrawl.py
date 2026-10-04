"""Common Crawl index plugin (free, no API key).

Two steps:

1. ``collinfo.json`` lists every published crawl index; the most recent one is
   selected (numerically, not by string order, so ``CC-MAIN-2024-5`` never wins
   over ``CC-MAIN-2024-33``).
2. ``{index}-index?url=*.{domain}&output=json&limit=…`` returns
   newline-delimited JSON whose ``url`` fields are mined for hostnames.

The CDX endpoint answers ``404`` with ``No Captures found for: …`` when a domain
was never crawled; that is a normal empty result, not an error.
"""

from __future__ import annotations

import json
import re
from typing import Any, AsyncIterator
from urllib.parse import urlencode, urlsplit

from ._base import DiscoverySource, register

COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"
INDEX_TEMPLATE = "https://index.commoncrawl.org/{index}-index"

#: Maximum number of CDX rows requested per query.
QUERY_LIMIT = 5000
#: Marker used by the CDX API for "this domain was never captured".
NO_CAPTURES = "no captures found"

_INDEX_ID_RE = re.compile(r"^CC-MAIN-(\d{4})-(\d{1,2})$", re.IGNORECASE)


def parse_collinfo(text: str) -> str | None:
    """Return the most recent index id from a ``collinfo.json`` body."""
    try:
        payload: Any = json.loads(text)
    except Exception:
        return None
    if not isinstance(payload, list):
        return None
    best: tuple[tuple[int, int], str] | None = None
    fallback: str | None = None
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        index_id = entry.get("id")
        if not isinstance(index_id, str) or not index_id.strip():
            continue
        index_id = index_id.strip()
        if fallback is None:
            # The API lists newest first — used when an id is unparseable.
            fallback = index_id
        match = _INDEX_ID_RE.match(index_id)
        if not match:
            continue
        rank = (int(match.group(1)), int(match.group(2)))
        if best is None or rank > best[0]:
            best = (rank, index_id)
    return best[1] if best else fallback


def parse_index_hosts(text: str) -> list[str]:
    """Extract hostnames from the newline-delimited JSON of a CDX query."""
    out: list[str] = []
    if NO_CAPTURES in text.lower():
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry: Any = json.loads(line)
        except Exception:
            continue
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        host = urlsplit(url.strip()).hostname
        if host:
            out.append(host)
    return out


@register
class CommonCrawlSource(DiscoverySource):
    """Hostnames found in the most recent Common Crawl index."""

    name = "commoncrawl"
    free = True
    requires_key = False
    description = "Common Crawl index (most recent crawl, no key)"
    COLLINFO_URL = COLLINFO_URL
    INDEX_TEMPLATE = INDEX_TEMPLATE
    QUERY_LIMIT = QUERY_LIMIT

    async def fetch_hosts(self, domain: str) -> AsyncIterator[str]:
        status, text = await self.get_text(self.COLLINFO_URL)
        if status != 200:
            raise RuntimeError(f"Common Crawl collinfo returned HTTP {status}")
        index_id = parse_collinfo(text)
        if not index_id:
            self.bus.warn(
                "Common Crawl index list could not be parsed — skipping",
                host=domain,
                source=self.name,
            )
            return
        limit = max(1, min(int(self.max_results), int(self.QUERY_LIMIT)))
        query = urlencode(
            {"url": f"*.{domain}", "output": "json", "limit": limit}
        )
        url = f"{self.INDEX_TEMPLATE.format(index=index_id)}?{query}"
        status, text = await self.get_text(url)
        if status == 404 or NO_CAPTURES in text.lower():
            # Never crawled / no captures — an empty result, not a failure.
            self.bus.osint(
                f"Common Crawl has no captures for {domain}",
                host=domain,
                source=self.name,
            )
            return
        if status != 200:
            raise RuntimeError(f"Common Crawl index returned HTTP {status}")
        for host in parse_index_hosts(text):
            yield host


__all__ = [
    "COLLINFO_URL",
    "INDEX_TEMPLATE",
    "NO_CAPTURES",
    "QUERY_LIMIT",
    "CommonCrawlSource",
    "parse_collinfo",
    "parse_index_hosts",
]
