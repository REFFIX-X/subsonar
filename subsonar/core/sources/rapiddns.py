"""RapidDNS subdomain-table scraper plugin (free, no API key).

The site serves an HTML table of passive-DNS records.  Because the column order
is not contractual (it has changed between deployments and the first column is a
row counter), the parser is *column-agnostic*: for every ``<tr>`` it collects all
``<td>`` cells, picks the first cell that looks like a hostname and the first
cell that looks like an IP literal.
"""

from __future__ import annotations

import html
import re
from typing import Any, AsyncIterator

from ._base import DiscoverySource, register

#: ``?full=1`` first, then the plain variant.
ENDPOINTS: tuple[str, ...] = (
    "https://rapiddns.io/subdomain/{domain}?full=1",
    "https://rapiddns.io/subdomain/{domain}",
)

_ROW_RE = re.compile(r"<tr[^>]*>(.*?)</tr>", re.IGNORECASE | re.DOTALL)
_CELL_RE = re.compile(r"<td[^>]*>(.*?)</td>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HOSTISH_RE = re.compile(
    r"^(?:\*\.)?[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?\.[A-Za-z]{2,}$"
)


def _clean(cell: str) -> str:
    """Strip nested markup / entities from one table cell."""
    return html.unescape(_TAG_RE.sub("", cell)).strip()


def parse_table(text: str) -> list[tuple[str, str | None]]:
    """Extract ``(host, ip_or_None)`` pairs from a RapidDNS HTML table."""
    out: list[tuple[str, str | None]] = []
    rows = _ROW_RE.findall(text)
    if not rows:
        # Degenerate markup (or a JSON/plain error body): fall back to a flat
        # ``<td>`` scan as required by the source contract.
        rows = [text]
    for row in rows:
        cells = [_clean(cell) for cell in _CELL_RE.findall(row)]
        host = next((cell for cell in cells if _HOSTISH_RE.match(cell)), None)
        if not host:
            continue
        ip = next((cell for cell in cells if _IPV4_RE.match(cell)), None)
        out.append((host, ip))
    return out


@register
class RapidDNSSource(DiscoverySource):
    """RapidDNS passive-DNS table scrape (HTML, no key)."""

    name = "rapiddns"
    free = True
    requires_key = False
    description = "RapidDNS passive-DNS HTML table scrape (no key)"
    ENDPOINTS = ENDPOINTS

    async def fetch_hosts(self, domain: str) -> AsyncIterator[Any]:
        for template in self.ENDPOINTS:
            url = template.format(domain=domain)
            status, text = await self.get_text(url)
            if status != 200:
                self.bus.warn(
                    f"RapidDNS returned HTTP {status} for {url}",
                    host=domain,
                    source=self.name,
                )
                continue
            rows = parse_table(text)
            if not rows:
                continue
            for host, ip in rows:
                yield host, ip
            return


__all__ = ["ENDPOINTS", "RapidDNSSource", "parse_table"]
