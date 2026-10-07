"""CertSpotter certificate-transparency log plugin (free, no API key)."""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

from ._base import DiscoverySource, register

#: Public CT-log search endpoint (documented, key-less, rate-limited).
ENDPOINT = (
    "https://api.certspotter.com/v1/issuances"
    "?domain={domain}&include_subdomains=true&expand=dns_names"
)


def _loads(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _names_from(payload: Any) -> list[str]:
    out: list[str] = []
    if not isinstance(payload, list):
        return out
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        names = entry.get("dns_names")
        if not isinstance(names, list):
            continue
        for raw in names:
            if isinstance(raw, str) and raw.strip():
                out.append(raw.strip())
    return out


def parse_dns_names(text: str) -> list[str]:
    """Extract every ``dns_names`` entry from a CertSpotter JSON response.

    The API answers with a JSON array of issuance objects; anything malformed
    (HTML error page, rate-limit notice, truncated body) yields ``[]``.
    """
    return _names_from(_loads(text))


@register
class CertSpotterSource(DiscoverySource):
    """Certificate Transparency hostnames via the CertSpotter issuances API."""

    name = "certspotter"
    free = True
    requires_key = False
    description = "CertSpotter certificate-transparency log search (no key)"
    ENDPOINT = ENDPOINT
    #: The issuances API caps a page (and paginates with an ``after`` cursor);
    #: a single GET silently loses everything past the first page.
    PAGE_SIZE = 100
    MAX_PAGES = 10

    async def fetch_hosts(self, domain: str) -> AsyncIterator[str]:
        after: int | None = None
        for _ in range(self.MAX_PAGES):
            url = self.ENDPOINT.format(domain=domain)
            if after is not None:
                url += f"&after={after}"
            status, text = await self.get_text(url)
            if status != 200:
                # A failure on a *later* page keeps what we already have.
                if after is None:
                    raise RuntimeError(f"CertSpotter returned HTTP {status}")
                break
            payload = _loads(text)
            if not isinstance(payload, list):
                if after is None and text.strip():
                    self._warn_unparseable(domain)
                break
            if not payload:
                break
            for host in _names_from(payload):
                yield host
            last = payload[-1]
            cursor = last.get("id") if isinstance(last, dict) else None
            if len(payload) < self.PAGE_SIZE or not isinstance(cursor, int):
                break
            after = cursor


__all__ = ["ENDPOINT", "CertSpotterSource", "parse_dns_names"]
