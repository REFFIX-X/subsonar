"""ThreatMiner passive-DNS plugin (free, no API key)."""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

from ._base import DiscoverySource, register

#: ``rt=5`` selects the passive-DNS dataset of the domain endpoint.
ENDPOINT = "https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"


def parse_results(text: str) -> list[str]:
    """Extract the flat ``results`` hostname list from a ThreatMiner response.

    ThreatMiner reports ``status_code`` ``"404"`` (with an empty ``results``
    list) when it has nothing for a domain; that, and any malformed body, yields
    ``[]`` rather than an error.
    """
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
        if isinstance(entry, str) and entry.strip():
            out.append(entry.strip())
    return out


@register
class ThreatMinerSource(DiscoverySource):
    """ThreatMiner passive-DNS hostnames for the target domain."""

    name = "threatminer"
    free = True
    requires_key = False
    description = "ThreatMiner passive DNS (no key)"
    ENDPOINT = ENDPOINT

    async def fetch_hosts(self, domain: str) -> AsyncIterator[str]:
        status, text = await self.get_text(self.ENDPOINT.format(domain=domain))
        if status != 200:
            raise RuntimeError(f"ThreatMiner returned HTTP {status}")
        for host in parse_results(text):
            yield host


__all__ = ["ENDPOINT", "ThreatMinerSource", "parse_results"]
