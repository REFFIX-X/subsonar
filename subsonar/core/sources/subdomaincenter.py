"""subdomain.center plugin — keyless aggregator of public subdomain data.

``api.subdomain.center`` is a free, signup-less JSON endpoint that merges
certificate-transparency feeds, passive DNS and public crawl data.  It is a
plain ``GET`` that answers with a JSON array of hostnames — no key, no account,
no quota page.

The parser accepts both the array form and the (older) object form with a
``subdomains``/``results``/``data``/``hosts`` key, because the shape of a free
service is not contractual.
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

from ._base import DiscoverySource, register

#: One endpoint; the parameter name is ``domain``.
ENDPOINT = "https://api.subdomain.center/?domain={domain}"

#: Object keys a wrapped response may use.
LIST_KEYS: tuple[str, ...] = ("subdomains", "results", "data", "hosts", "items")


def parse_payload(payload: Any) -> list[str]:
    """Hostnames from either response shape (order preserved, deduplicated)."""
    values: Any = payload
    if isinstance(payload, dict):
        values = None
        for key in LIST_KEYS:
            candidate = payload.get(key)
            if isinstance(candidate, list):
                values = candidate
                break
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for item in values:
        if isinstance(item, dict):
            item = item.get("host") or item.get("name") or item.get("subdomain") or ""
        text = str(item or "").strip().lower()
        if text and text not in out:
            out.append(text)
    return out


@register
class SubdomainCenterSource(DiscoverySource):
    """Keyless aggregation of public subdomain datasets."""

    name = "subdomain-center"
    free = True
    requires_key = False
    description = "subdomain.center aggregator (keyless JSON, no signup)"
    ENDPOINT = ENDPOINT
    DEFAULT_TIMEOUT = 30.0

    async def fetch_hosts(self, domain: str) -> AsyncIterator[Any]:
        url = self.ENDPOINT.format(domain=domain)
        status, payload = await self.get_json(url)
        if status == 200 and payload is None:
            # A free endpoint's content type is not contractual: some deployments
            # answer JSON as text/plain, which makes ``response.json()`` fail.
            # Parse the body ourselves before giving up.
            status, text = await self.get_text(url)
            if status == 200 and text.strip():
                try:
                    payload = json.loads(text)
                except ValueError:
                    payload = None
        if status != 200 or payload is None:
            self.bus.warn(
                f"subdomain.center returned HTTP {status} for {domain}",
                host=domain,
                source=self.name,
            )
            return
        hosts = parse_payload(payload)
        if not hosts:
            return
        self.bus.emit(
            f"subdomain.center answered with {len(hosts)} hostname(s) for {domain}",
            "debug",
            "osint",
            host=domain,
            source=self.name,
        )
        for host in hosts:
            yield host


__all__ = ["ENDPOINT", "LIST_KEYS", "SubdomainCenterSource", "parse_payload"]
