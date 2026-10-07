"""AlienVault OTX passive-DNS plugin (free, no API key)."""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

from ._base import DiscoverySource, register

ENDPOINT = (
    "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
)


def parse_page(text: str) -> tuple[list[tuple[str, str | None]], bool]:
    """Parse one OTX passive-DNS page into ``(pairs, has_next)``."""
    out: list[tuple[str, str | None]] = []
    try:
        payload: Any = json.loads(text)
    except Exception:
        return out, False
    if not isinstance(payload, dict):
        return out, False
    records = payload.get("passive_dns")
    if isinstance(records, list):
        for entry in records:
            if not isinstance(entry, dict):
                continue
            host = entry.get("hostname")
            if not isinstance(host, str) or not host.strip():
                continue
            address = entry.get("address")
            out.append(
                (host.strip(), address.strip() if isinstance(address, str) else None)
            )
    return out, bool(payload.get("has_next"))


def parse_passive_dns(text: str) -> list[tuple[str, str | None]]:
    """Extract ``(hostname, address)`` pairs from an OTX passive-DNS response.

    ``passive_dns[].address`` is usually present but not guaranteed; a missing or
    non-literal address is reported as ``None``.
    """
    return parse_page(text)[0]


@register
class OTXSource(DiscoverySource):
    """AlienVault OTX passive DNS for the target domain."""

    name = "otx"
    free = True
    requires_key = False
    description = "AlienVault OTX passive DNS (no key)"
    ENDPOINT = ENDPOINT
    #: OTX paginates passive-DNS results and signals more pages with ``has_next``.
    MAX_PAGES = 10

    async def fetch_hosts(self, domain: str) -> AsyncIterator[tuple[str, str | None]]:
        for page in range(1, self.MAX_PAGES + 1):
            url = self.ENDPOINT.format(domain=domain)
            if page > 1:
                url += f"?page={page}"
            status, text = await self.get_text(url)
            if status != 200:
                if page == 1:
                    raise RuntimeError(f"OTX returned HTTP {status}")
                break
            pairs, has_next = parse_page(text)
            if page == 1 and not pairs and text.strip():
                try:
                    json.loads(text)
                except Exception:
                    self._warn_unparseable(domain)
            for host, address in pairs:
                yield host, address
            if not has_next or not pairs:
                break


__all__ = ["ENDPOINT", "OTXSource", "parse_passive_dns"]
