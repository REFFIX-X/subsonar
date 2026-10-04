"""100% free OSINT collection — no paid APIs, ever.

Each source streams results asynchronously and degrades gracefully when the
upstream service is slow, rate-limited or offline.  Every network event is
reported to the live console.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Any, AsyncIterator, Iterable

try:  # pragma: no cover
    import aiohttp

    AIOHTTP_AVAILABLE = True
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore[assignment]
    AIOHTTP_AVAILABLE = False

from .config import (
    ANUBIS_ENDPOINT,
    CRTSH_ENDPOINT,
    CRTSH_FALLBACK_ENDPOINT,
    HACKERTARGET_ENDPOINT,
    USER_AGENT,
)
from .events import BUS, EventBus

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$"
)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@dataclass(slots=True)
class OSINTResult:
    """A single discovered hostname tagged with its provenance."""

    host: str
    source: str
    target: str
    ip: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"host": self.host, "source": self.source, "ip": self.ip}


@dataclass
class SourceReport:
    """Per-source statistics for the final report."""

    name: str
    hosts: int = 0
    requests: int = 0
    errors: int = 0
    duration: float = 0.0
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "hosts": self.hosts,
            "requests": self.requests,
            "errors": self.errors,
            "duration": round(self.duration, 2),
            "note": self.note,
        }


def is_valid_hostname(host: str, domain: str) -> bool:
    """Validate a harvested hostname and keep only in-scope names."""
    host = host.strip().lower().lstrip("*.").rstrip(".")
    if not host or len(host) > 253 or "." not in host:
        return False
    if _IP_RE.match(host):
        return False
    if not _HOST_RE.match(host):
        return False
    return host == domain or host.endswith("." + domain)


class OSINTCollector:
    """Async collector for CRT.sh, HackerTarget and Anubis."""

    def __init__(
        self,
        domain: str,
        *,
        bus: EventBus | None = None,
        timeout: float = 30.0,
        session: Any | None = None,
    ) -> None:
        self.domain = domain.strip().lower()
        self.bus = bus or BUS
        self.timeout = timeout
        self._session = session
        self._owns_session = session is None
        self.reports: dict[str, SourceReport] = {}

    # -- lifecycle --------------------------------------------------------- #
    async def __aenter__(self) -> "OSINTCollector":
        await self._ensure_session()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def _ensure_session(self) -> Any | None:
        if self._session is not None:
            return self._session
        if not AIOHTTP_AVAILABLE:
            self.bus.warn("aiohttp unavailable — OSINT sources disabled")
            return None
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout, connect=10),
            headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*"},
            trust_env=False,
        )
        return self._session

    async def close(self) -> None:
        if self._session is not None and self._owns_session:
            try:
                await self._session.close()
            except Exception:  # pragma: no cover
                pass
        self._session = None

    # -- sources ----------------------------------------------------------- #
    async def crtsh(self) -> AsyncIterator[OSINTResult]:
        """Certificate Transparency logs via crt.sh (async JSON)."""
        report = self.reports.setdefault("crt.sh", SourceReport("crt.sh"))
        self.bus.osint(
            "Querying CRT.sh API asynchronously...", host=self.domain, source="crt.sh"
        )
        for endpoint in (
            CRTSH_ENDPOINT.format(domain=self.domain),
            CRTSH_FALLBACK_ENDPOINT.format(domain=self.domain),
        ):
            session = await self._ensure_session()
            if session is None:
                return
            started = asyncio.get_running_loop().time()
            report.requests += 1
            try:
                async with session.get(endpoint) as response:
                    if response.status != 200:
                        report.errors += 1
                        self.bus.warn(
                            f"CRT.sh returned HTTP {response.status} — trying fallback",
                            host=self.domain,
                        )
                        continue
                    text = await response.text()
                if text.lstrip().startswith("<"):
                    report.errors += 1
                    self.bus.warn(
                        "CRT.sh responded with HTML (rate limit) — trying fallback",
                        host=self.domain,
                    )
                    continue
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    payload = _salvage_json(text)
                seen: set[str] = set()
                for entry in payload:
                    names = str(entry.get("name_value", "")).split("\n")
                    names.append(str(entry.get("common_name", "")))
                    for raw in names:
                        host = raw.strip().lower().lstrip("*.").rstrip(".")
                        if host in seen or not is_valid_hostname(host, self.domain):
                            continue
                        seen.add(host)
                        report.hosts += 1
                        yield OSINTResult(host=host, source="crt.sh", target=self.domain)
                report.duration += asyncio.get_running_loop().time() - started
                self.bus.osint(
                    f"CRT.sh returned {report.hosts} in-scope hostname(s) for "
                    f"{self.domain}",
                    host=self.domain,
                    source="crt.sh",
                    count=report.hosts,
                )
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                report.errors += 1
                report.duration += asyncio.get_running_loop().time() - started
                self.bus.warn(
                    f"CRT.sh query failed ({exc.__class__.__name__}: {exc}) — "
                    f"trying fallback endpoint",
                    host=self.domain,
                )
        report.note = report.note or "no data returned"

    async def hackertarget(self) -> AsyncIterator[OSINTResult]:
        """HackerTarget free-tier host search API (CSV)."""
        report = self.reports.setdefault(
            "hackertarget", SourceReport("hackertarget")
        )
        self.bus.osint(
            "Querying HackerTarget free API asynchronously...",
            host=self.domain,
            source="hackertarget",
        )
        session = await self._ensure_session()
        if session is None:
            return
        endpoint = HACKERTARGET_ENDPOINT.format(domain=self.domain)
        started = asyncio.get_running_loop().time()
        report.requests += 1
        try:
            async with session.get(endpoint) as response:
                if response.status != 200:
                    report.errors += 1
                    report.duration += asyncio.get_running_loop().time() - started
                    self.bus.warn(
                        f"HackerTarget returned HTTP {response.status}",
                        host=self.domain,
                    )
                    return
                text = await response.text()
            report.duration += asyncio.get_running_loop().time() - started
            if "API count exceeded" in text or ("," not in text and "error" in text.lower()):
                report.errors += 1
                report.note = "rate limited"
                self.bus.warn(
                    f"HackerTarget rate limit reached: {text.strip()[:90]}",
                    host=self.domain,
                )
                return
            seen: set[str] = set()
            for line in text.splitlines():
                line = line.strip()
                if not line or "," not in line:
                    continue
                host, _, ip = line.partition(",")
                host = host.strip().lower().rstrip(".")
                ip = ip.strip()
                if host in seen or not is_valid_hostname(host, self.domain):
                    continue
                seen.add(host)
                report.hosts += 1
                yield OSINTResult(
                    host=host,
                    source="hackertarget",
                    target=self.domain,
                    ip=ip if _IP_RE.match(ip) else None,
                )
            self.bus.osint(
                f"HackerTarget returned {report.hosts} in-scope hostname(s)",
                host=self.domain,
                source="hackertarget",
                count=report.hosts,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            report.errors += 1
            report.duration += asyncio.get_running_loop().time() - started
            self.bus.warn(
                f"HackerTarget query failed ({exc.__class__.__name__}: {exc})",
                host=self.domain,
            )

    async def anubis(self) -> AsyncIterator[OSINTResult]:
        """Anubis (jldc.me) passive subdomain dataset."""
        report = self.reports.setdefault("anubis", SourceReport("anubis"))
        self.bus.osint(
            "Querying Anubis passive DNS dataset asynchronously...",
            host=self.domain,
            source="anubis",
        )
        session = await self._ensure_session()
        if session is None:
            return
        endpoint = ANUBIS_ENDPOINT.format(domain=self.domain)
        started = asyncio.get_running_loop().time()
        report.requests += 1
        try:
            async with session.get(endpoint) as response:
                if response.status != 200:
                    report.errors += 1
                    self.bus.warn(
                        f"Anubis returned HTTP {response.status}",
                        host=self.domain,
                    )
                    return
                text = await response.text()
            report.duration += asyncio.get_running_loop().time() - started
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = []
            seen: set[str] = set()
            for raw in payload if isinstance(payload, list) else []:
                host = str(raw).strip().lower().lstrip("*.").rstrip(".")
                if host in seen or not is_valid_hostname(host, self.domain):
                    continue
                seen.add(host)
                report.hosts += 1
                yield OSINTResult(host=host, source="anubis", target=self.domain)
            self.bus.osint(
                f"Anubis returned {report.hosts} in-scope hostname(s)",
                host=self.domain,
                source="anubis",
                count=report.hosts,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            report.errors += 1
            report.duration += asyncio.get_running_loop().time() - started
            self.bus.warn(
                f"Anubis query failed ({exc.__class__.__name__}: {exc})",
                host=self.domain,
            )

    def sources(self, names: Iterable[str]) -> list[Any]:
        mapping = {
            "crt.sh": self.crtsh,
            "hackertarget": self.hackertarget,
            "anubis": self.anubis,
        }
        return [mapping[name] for name in names if name in mapping]


def _salvage_json(text: str) -> list[dict[str, Any]]:
    """Best-effort recovery for slightly malformed crt.sh payloads."""
    out: list[dict[str, Any]] = []
    for match in re.finditer(r"\{[^{}]*\"name_value\"\s*:\s*\"([^\"]+)\"[^{}]*\}", text):
        out.append({"name_value": match.group(1)})
    if not out:
        for match in re.finditer(r"\"name_value\"\s*:\s*\"([^\"]+)\"", text):
            out.append({"name_value": match.group(1)})
    return out
