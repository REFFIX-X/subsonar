"""AlienVault OTX passive-DNS plugin (free, no API key)."""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

from ._base import DiscoverySource, register

ENDPOINT = (
    "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
)


def parse_passive_dns(text: str) -> list[tuple[str, str | None]]:
    """Extract ``(hostname, address)`` pairs from an OTX passive-DNS response.

    ``passive_dns[].address`` is usually present but not guaranteed; a missing or
    non-literal address is reported as ``None``.
    """
    out: list[tuple[str, str | None]] = []
    try:
        payload: Any = json.loads(text)
    except Exception:
        return out
    if not isinstance(payload, dict):
        return out
    records = payload.get("passive_dns")
    if not isinstance(records, list):
        return out
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
    return out


@register
class OTXSource(DiscoverySource):
    """AlienVault OTX passive DNS for the target domain."""

    name = "otx"
    free = True
    requires_key = False
    description = "AlienVault OTX passive DNS (no key)"
    ENDPOINT = ENDPOINT

    async def fetch_hosts(self, domain: str) -> AsyncIterator[tuple[str, str | None]]:
        status, text = await self.get_text(self.ENDPOINT.format(domain=domain))
        if status != 200:
            raise RuntimeError(f"OTX returned HTTP {status}")
        for host, address in parse_passive_dns(text):
            yield host, address


__all__ = ["ENDPOINT", "OTXSource", "parse_passive_dns"]
