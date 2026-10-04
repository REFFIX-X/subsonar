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


def parse_dns_names(text: str) -> list[str]:
    """Extract every ``dns_names`` entry from a CertSpotter JSON response.

    The API answers with a JSON array of issuance objects; anything malformed
    (HTML error page, rate-limit notice, truncated body) yields ``[]``.
    """
    out: list[str] = []
    try:
        payload: Any = json.loads(text)
    except Exception:
        return out
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


@register
class CertSpotterSource(DiscoverySource):
    """Certificate Transparency hostnames via the CertSpotter issuances API."""

    name = "certspotter"
    free = True
    requires_key = False
    description = "CertSpotter certificate-transparency log search (no key)"
    ENDPOINT = ENDPOINT

    async def fetch_hosts(self, domain: str) -> AsyncIterator[str]:
        status, text = await self.get_text(self.ENDPOINT.format(domain=domain))
        if status != 200:
            raise RuntimeError(f"CertSpotter returned HTTP {status}")
        for host in parse_dns_names(text):
            yield host


__all__ = ["ENDPOINT", "CertSpotterSource", "parse_dns_names"]
