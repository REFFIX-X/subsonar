"""subsonar scan engine — orchestration, filtering and result aggregation.

Pipeline
--------
1. **OSINT** — CRT.sh / HackerTarget / Anubis stream candidates concurrently.
2. **Wildcard check** — randomised non-existent labels detect wildcard DNS (and
   wildcard HTTP responders) before brute-force traffic is generated.
3. **Wordlist** — SecLists is streamed/cached and sliced to the profile size.
4. **DNS** — every candidate is resolved through the anonymous resolver pool.
5. **Ports** — the embedded Top-50 matrix is probed with async TCP connects.
6. **HTTP** — every open port is verified with a real HTTP/HTTPS GET.
7. **Filter** — only hosts with a confirmed web interface become findings.

Everything above emits granular events onto the :class:`EventBus`, which is what
feeds the live scanning log in the TUI, the Streamlit dashboard and the headless
console renderer.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from collections import Counter
from collections.abc import Mapping
from typing import Any, Callable, Sequence

from .config import ScanConfig
from .discovery import expand_discovery
from .dns import AnonymousResolver, DNSResult, WildcardReport
from .events import BUS, EventBus
from .osint import OSINTCollector, SourceReport, is_valid_hostname
from .ports import describe
from .profiles import PROFILE_DELAY, Profile, apply_profile, get_profile
from .providers import Provider, detect_provider
from .scanner import AsyncPortScanner, PortResult
from .web_probe import WebProbe, WebProbeResult
from .wordlist import WordlistManager, WordlistResult
from .wordlists import resolve_wordlist

# --------------------------------------------------------------------------- #
# Result containers
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class Finding:
    """A confirmed web interface — the only thing subsonar ever reports."""

    subdomain: str
    ip: str
    port: int
    scheme: str
    url: str
    status: int | None
    title: str | None
    server: str | None = None
    tls: bool = False
    tls_version: str | None = None
    content_type: str | None = None
    content_length: int = 0
    #: ``Content-Length`` the server declared (``content_length`` is what we read).
    declared_length: int | None = None
    redirect_chain: list[str] = field(default_factory=list)
    port_label: str = ""
    sources: list[str] = field(default_factory=list)
    fingerprint: str | None = None
    kind: str = "interface"
    initial_status: int | None = None
    final_url: str | None = None
    aliases: list[int] = field(default_factory=list)
    #: Fingerprint output (favicon hash, technologies, probed data files).
    favicon_hash: str | None = None
    technologies: list[str] = field(default_factory=list)
    data_files: dict[str, int] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    #: Confidence score and its human-readable label.
    confidence: int = 0
    confidence_label: str = ""
    confidence_reasons: list[str] = field(default_factory=list)
    confidence_penalties: list[str] = field(default_factory=list)
    #: Third-party hosting provider, when the host is not on the target's own
    #: infrastructure (``None`` = own infrastructure).
    provider: str | None = None
    #: Country (ISO-3166 alpha-2) and ASN of the resolved address, when the
    #: offline geo index is available.
    country_code: str | None = None
    country: str | None = None
    asn: int | None = None
    as_org: str | None = None
    #: Reverse-DNS name of the resolved address, when looked up.
    ptr: str | None = None
    #: Template-style exposure checks that matched (severity-labelled).
    exposures: list[dict[str, str]] = field(default_factory=list)
    #: True when the row came from a previous report of the same domain and was
    #: merged into this run instead of being cleared.
    from_previous_scan: bool = False
    latency_ms: float = 0.0
    discovered_at: float = field(default_factory=time.time)

    @property
    def link(self) -> str:
        """Actionable hyperlink: ``http(s)://domain:port``.

        For a redirect-only entry this is the destination that actually serves
        the site — pointing at the bouncing port would hand the user a link that
        cannot be opened (browsers force HTTPS on it and get no TLS listener).
        """
        if self.kind == "redirect" and self.final_url:
            return self.final_url
        return self.url

    @property
    def host_port(self) -> str:
        return f"{self.subdomain}:{self.port}"

    @property
    def flag(self) -> str:
        """Flag emoji for :attr:`country_code` (``""`` when unknown)."""
        from .geoip import flag_emoji

        return flag_emoji(self.country_code)

    @property
    def geo_label(self) -> str:
        """``🇩🇰 DK`` style label for the resolved address."""
        flag = self.flag
        return f"{flag} {self.country_code}".strip()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Finding":
        """Rebuild a finding from a report row / JSON payload (lenient).

        Used to merge a previous scan's findings into a new run, so nothing the
        user already found disappears when the profile changes.
        """

        def _int(value: Any, default: int | None = None) -> int | None:
            try:
                return int(str(value).strip())
            except (TypeError, ValueError):
                return default

        def _float(value: Any, default: float = 0.0) -> float:
            try:
                return float(str(value).strip())
            except (TypeError, ValueError):
                return default

        aliases = [
            port
            for port in (
                _int(token) for token in str(data.get("also_on_ports") or "").split(",")
            )
            if port
        ]
        data_files: dict[str, int] = {}
        for token in str(data.get("data_files") or "").split(","):
            name, _, status = token.partition(":")
            if not name.strip():
                continue
            code = _int(status, 0) or 0
            data_files[name.strip()] = code
        return cls(
            subdomain=str(data.get("subdomain") or "").strip(),
            ip=str(data.get("ip") or "").strip(),
            port=_int(data.get("port"), 0) or 0,
            scheme=str(data.get("scheme") or "http").strip() or "http",
            url=str(data.get("url") or "").strip(),
            status=_int(data.get("status")),
            title=(str(data.get("title")).strip() or None) if data.get("title") else None,
            server=(str(data.get("server")).strip() or None) if data.get("server") else None,
            tls=bool(data.get("tls")),
            tls_version=(str(data.get("tls_version")).strip() or None)
            if data.get("tls_version")
            else None,
            content_type=(str(data.get("content_type")).strip() or None)
            if data.get("content_type")
            else None,
            content_length=_int(data.get("content_length"), 0) or 0,
            declared_length=_int(data.get("declared_length")),
            redirect_chain=[str(item) for item in (data.get("redirect_chain") or [])],
            port_label=str(data.get("port_label") or "").strip(),
            sources=[
                token
                for token in str(data.get("sources") or "").split(",")
                if token.strip()
            ],
            fingerprint=(str(data.get("fingerprint")).strip() or None)
            if data.get("fingerprint")
            else None,
            kind=str(data.get("kind") or "interface").strip() or "interface",
            initial_status=_int(data.get("initial_status")),
            final_url=(str(data.get("final_url")).strip() or None)
            if data.get("final_url")
            else None,
            aliases=sorted(aliases),
            favicon_hash=(str(data.get("favicon_hash")).strip() or None)
            if data.get("favicon_hash")
            else None,
            data_files=data_files,
            technologies=[
                token.strip()
                for token in str(data.get("technologies") or "").split(",")
                if token.strip()
            ],
            headers=dict(data.get("headers") or {}),
            confidence=_int(data.get("confidence"), 0) or 0,
            confidence_label=str(data.get("confidence_label") or "").strip(),
            confidence_reasons=list(data.get("confidence_reasons") or []),
            confidence_penalties=list(data.get("confidence_penalties") or []),
            provider=(str(data.get("provider")).strip() or None)
            if data.get("provider")
            else None,
            country_code=(str(data.get("country_code")).strip() or None)
            if data.get("country_code")
            else None,
            country=(str(data.get("country")).strip() or None)
            if data.get("country")
            else None,
            asn=_int(data.get("asn")),
            as_org=(str(data.get("as_org")).strip() or None)
            if data.get("as_org")
            else None,
            ptr=(str(data.get("ptr")).strip() or None) if data.get("ptr") else None,
            from_previous_scan=True,
            latency_ms=_float(data.get("latency_ms")),
            exposures=[
                dict(item) if isinstance(item, Mapping) else {}
                for item in (data.get("exposures") or [])
            ],
        )

    def to_row(self) -> dict[str, Any]:
        return {
            "subdomain": self.subdomain,
            "ip": self.ip,
            "port": self.port,
            "port_label": self.port_label,
            "status": self.status,
            "kind": self.kind,
            "title": self.title or "",
            "scheme": self.scheme,
            "url": self.link,
            "final_url": self.final_url or "",
            "server": self.server or "",
            "tls": self.tls,
            "tls_version": self.tls_version or "",
            "also_on_ports": ",".join(str(port) for port in self.aliases),
            "favicon_hash": self.favicon_hash or "",
            "technologies": ",".join(self.technologies),
            "data_files": ",".join(f"{p}:{s}" for p, s in sorted(self.data_files.items())),
            "confidence": self.confidence,
            "confidence_label": self.confidence_label,
            "confidence_why": "; ".join(self.confidence_reasons[:3]),
            "sources": ",".join(self.sources),
            "provider": self.provider or "",
            "country_code": self.country_code or "",
            "country": self.country or "",
            "asn": self.asn or "",
            "as_org": self.as_org or "",
            "ptr": self.ptr or "",
            "carried_over": "yes" if self.from_previous_scan else "",
            "latency_ms": round(self.latency_ms, 1),
            "checks": " | ".join(
                f"{e.get('severity', '?')} {e.get('name', '')}".strip()
                for e in self.exposures
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.to_row()
        data.update(
            {
                "content_type": self.content_type,
                "content_length": self.content_length,
                "declared_length": self.declared_length,
                "redirect_chain": self.redirect_chain,
                "fingerprint": self.fingerprint,
                "headers": self.headers,
                "confidence_reasons": self.confidence_reasons,
                "confidence_penalties": self.confidence_penalties,
                "from_previous_scan": self.from_previous_scan,
                "discovered_at": self.discovered_at,
                "exposures": list(self.exposures),
            }
        )
        return data


class ScanResult:
    """Aggregated output of a complete scan."""

    def __init__(self, config: ScanConfig, profile: Profile) -> None:
        self.config = config
        self.profile = profile
        self.findings: list[Finding] = []
        self.resolutions: dict[str, DNSResult] = {}
        self.open_ports: dict[str, list[PortResult]] = {}
        self.wildcard: WildcardReport | None = None
        self.sources: dict[str, SourceReport] = {}
        self.wordlist: WordlistResult | None = None
        self.filtered: dict[str, str] = {}
        self.osint_hosts: set[str] = set()
        self.brute_hosts: set[str] = set()
        #: Hosts found by active discovery (SAN, CNAME, permutations).
        self.discovered_hosts: set[str] = set()
        #: Hosts contributed by the plugin source registry.
        self.plugin_hosts: set[str] = set()
        #: ``{host: provider}`` for the hosts that were **skipped** because they
        #: are Office 365-style shared tenants (mail / identity / collaboration).
        #: Provider-fronted hosts that *were* scanned (CDN, PaaS, hosting) carry
        #: their provider on the finding instead.
        self.provider_hosts: dict[str, str] = {}
        #: Findings merged from the previous report of the same domain.
        self.carried_over: int = 0
        #: DNS intelligence (MX/SPF/DMARC/CAA/DNSSEC) for the apex, when enabled.
        self.dns_intel: Any = None
        #: Extra in-scope hostnames mined from robots.txt/sitemap/CSP/headers.
        self.mined_hosts: set[str] = set()
        #: Hosts that were resolved and scanned in the mining second wave.
        self.wave2_hosts: set[str] = set()
        #: ``{ip: ptr_name}`` for the addresses that answered with a PTR record.
        self.ptr: dict[str, str] = {}
        #: Offline geo index statistics (entries, age, sources).
        self.geo: dict[str, Any] = {}
        self.discovery: Any = None
        #: Ports that only bounced elsewhere, kept as a fallback signal.
        self.redirects: list[Finding] = []
        self.started_at = time.time()
        self.finished_at: float | None = None
        self.notes: list[str] = []
        #: Shared filename stem (``subsonar_<domain>_<timestamp>``) so the live
        #: JSONL sink and the final reports land in the same file set.
        self.stem: str | None = None

    # -- accessors --------------------------------------------------------- #
    @property
    def duration(self) -> float:
        end = self.finished_at if self.finished_at is not None else time.time()
        return max(0.0, end - self.started_at)

    @property
    def subdomain_count(self) -> int:
        return len({finding.subdomain for finding in self.findings})

    @property
    def resolved_count(self) -> int:
        return len(self.resolutions)

    @property
    def open_port_count(self) -> int:
        return sum(len(ports) for ports in self.open_ports.values())

    def urls(self) -> list[str]:
        return [finding.url for finding in self.findings]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "subsonar",
            "version": _version(),
            "target": self.config.domain,
            "profile": self.profile.to_dict(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration, 2),
            "statistics": {
                "findings": len(self.findings),
                "unique_subdomains": self.subdomain_count,
                "resolved_hosts": self.resolved_count,
                "open_ports": self.open_port_count,
                "osint_hosts": len(self.osint_hosts),
                "brute_hosts": len(self.brute_hosts),
                "filtered_no_web": len(self.filtered),
            },
            "wildcard": self.wildcard.to_dict() if self.wildcard else None,
            "wordlist": self.wordlist.to_dict() if self.wordlist else None,
            "sources": {name: rep.to_dict() for name, rep in self.sources.items()},
            "provider_hosts": dict(self.provider_hosts),
            "carried_over": self.carried_over,
            "dns_intel": self.dns_intel.to_dict() if self.dns_intel else None,
            "mined_hosts": sorted(self.mined_hosts),
            "wave2_hosts": sorted(self.wave2_hosts),
            "ptr": dict(self.ptr),
            "geo": dict(self.geo),
            "findings": [finding.to_dict() for finding in self.findings],
            "filtered": dict(list(self.filtered.items())[:500]),
            "notes": self.notes,
        }

    def summary_lines(self) -> list[str]:
        lines = [
            f"target          : {self.config.domain}",
            f"profile         : {self.profile.id}. {self.profile.name}",
            f"duration        : {self.duration:.1f}s",
            f"web interfaces  : {len(self.findings)}",
            f"unique hosts    : {self.subdomain_count}",
            f"resolved hosts  : {self.resolved_count}",
            f"open ports      : {self.open_port_count}",
            f"filtered (no web): {len(self.filtered)}",
        ]
        if self.carried_over:
            lines.append(
                f"from prev. scan : {self.carried_over} finding(s) merged "
                f"(nothing was cleared)"
            )
        if self.wave2_hosts:
            lines.append(f"second wave     : {len(self.wave2_hosts)} mined host(s) scanned")
        if self.geo.get("entries"):
            lines.append(
                f"geo index       : {self.geo['entries']:,} range(s), "
                f"{self.geo.get('age_days', 0):.0f} day(s) old (offline lookups)"
            )
        if self.dns_intel is not None and self.dns_intel.mail_providers:
            lines.append(
                f"mail platform   : {', '.join(self.dns_intel.mail_providers)}"
            )
        if self.provider_hosts:
            lines.append(
                f"skipped (3rd-party): {len(self.provider_hosts)} host(s) not scanned "
                f"(Office 365-style tenants)"
            )
        return lines


def _duplicate_count(values: Any) -> int:
    """How many *extra* findings share a value with at least one other finding.

    A high number is a uniformity signal: the same page answering on many ports.
    """
    seen: dict[Any, int] = {}
    for value in values:
        if value in (None, 0, ""):
            continue
        seen[value] = seen.get(value, 0) + 1
    return sum(count - 1 for count in seen.values() if count > 1)


def _version() -> str:
    from .. import __version__

    return __version__


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #


class ScanEngine:
    """The asynchronous subsonar engine."""

    def __init__(
        self,
        config: ScanConfig,
        *,
        profile: Profile | int | str | None = None,
        bus: EventBus | None = None,
        on_finding: Callable[[Finding], Any] | None = None,
    ) -> None:
        self.config = config
        self.profile = (
            profile
            if isinstance(profile, Profile)
            else get_profile(profile if profile is not None else config.profile_id)
        )
        apply_profile(self.profile, self.config)
        self.bus = bus or BUS
        self.on_finding = on_finding
        self.result = ScanResult(config, self.profile)
        self._stop = asyncio.Event()
        self._resolver = AnonymousResolver(
            servers=config.resolver_pool,
            timeout=config.dns_timeout,
            concurrency=config.dns_concurrency,
            bus=self.bus,
            multiplex=config.multiplex_dns,
            disk_cache_enabled=config.disk_cache,
            rate_limit=config.dns_rate_limit,
            rate_burst=config.dns_rate_burst or None,
            rate_per_server=config.dns_rate_per_server,
            name_deadline=config.dns_name_deadline,
        )
        self._scanner = AsyncPortScanner(
            timeout=config.tcp_timeout,
            fast_timeout=config.tcp_fast_timeout,
            concurrency=config.port_concurrency,
            ports=config.ports,
            bus=self.bus,
            stealth_delay=config.stealth_delay,
            verify_tls=config.verify_tls,
            adaptive_timeout=config.adaptive_timeout,
            host_batch=config.host_batch,
            log_attempts=self.profile.id != 8,
            rate_limit=config.port_rate_limit,
            rate_burst=config.port_rate_burst or None,
            per_host_rate=config.port_rate_per_host,
        )
        self._probe = WebProbe(
            resolver=self._resolver,
            timeout=config.http_timeout,
            concurrency=config.http_concurrency,
            bus=self.bus,
            verify_tls=config.verify_tls,
        )
        self._wordlists = WordlistManager(
            spec=resolve_wordlist(config.wordlist),
            cache_dir=config.cache_dir,
            bus=self.bus,
        )
        self._delay = PROFILE_DELAY[self.profile.id]
        self._progress_interval = 25 if self.profile.id != 8 else 5
        self._host_batch = max(1, config.host_batch)
        self._host_batch_workers = max(1, config.host_batch_workers)
        #: Offline geo index (country/ASN) — opened in :meth:`_phase_geo`.
        self._geo: Any = None
        #: Live NDJSON sink when :attr:`ScanConfig.jsonl` is enabled.
        self._jsonl: Any = None

    # -- lifecycle --------------------------------------------------------- #
    def stop(self) -> None:
        """Request a cooperative shutdown."""
        self._stop.set()
        self.bus.warn("Stop requested — draining in-flight tasks...")

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    async def _sleep_delay(self) -> None:
        lo, hi = self._delay
        if hi > 0:
            import random

            await asyncio.sleep(random.uniform(lo, hi))

    # -- main -------------------------------------------------------------- #
    async def run(self) -> ScanResult:
        """Execute the full pipeline and return the scan result."""
        bus = self.bus
        started = time.perf_counter()
        self._banner()
        self._open_jsonl()
        self._seed_previous_findings()
        await self._probe.start()
        bus.phase(f"Engine start — profile {self.profile.id}: {self.profile.name}")
        # Print the *effective* configuration up front: after profile + CLI/TOML
        # merging, so the log itself records which wordlist slice, port matrix and
        # pacing this run really used (and a later report can be trusted).
        for line in self.describe_plan():
            bus.emit(line, "info", "config")
        try:
            await self._phase_health()
            await self._phase_geo()
            await self._phase_dns_intel()
            candidates = await self._collect_candidates()
            if self._stop.is_set():
                self.result.notes.append("scan cancelled during collection")
                return self._finish()
            resolved = await self._phase_resolve(candidates)
            if self._stop.is_set():
                self.result.notes.append("scan cancelled during resolution")
                return self._finish()
            await self._phase_scan(resolved)
            await self._phase_mining()
            await self._enrich_findings()
        except asyncio.CancelledError:
            bus.warn("Scan cancelled")
            self.result.notes.append("scan cancelled")
            raise
        except Exception as exc:  # pragma: no cover - defensive top-level
            bus.error(f"Engine failure: {exc.__class__.__name__}: {exc}")
            self.result.notes.append(f"engine failure: {exc}")
        finally:
            await self._probe.close()
            self._resolver.stop_health_loop()
            await self._resolver.flush_disk_cache()
        elapsed = time.perf_counter() - started
        bus.emit(
            f"Scan finished in {elapsed:.1f}s", "success", "done",
            duration=round(elapsed, 2),
        )
        return self._finish()

    async def _phase_health(self) -> None:
        """Probe the anonymous resolver pool before any target traffic."""
        bus = self.bus
        bus.phase(
            f"Resolver pre-flight — probing {len(self.config.resolver_pool)} anonymous "
            f"DNS nodes (no Google, no Cloudflare)"
        )
        reports: list[str] = []
        for server in self.config.resolver_pool:
            reports.append(server)
        bus.emit(
            "Configured resolver pool: " + ", ".join(reports),
            "debug",
            "dns",
        )
        try:
            health = await self._resolver.health_check(
                timeout=min(2.5, max(1.0, self.config.dns_timeout)), log=True
            )
            live = [node for node, error in health.items() if error is None]
            self.result.notes.append(
                f"resolver health: {len(live)}/{len(health)} nodes answering"
            )
            if not live:
                bus.warn(
                    "No anonymous resolver answered the pre-flight check — "
                    "falling back to the full pool with extended retries"
                )
            await self._resolver.start_health_loop(interval=600.0)
        except Exception as exc:
            bus.warn(
                f"Resolver pre-flight failed ({exc.__class__.__name__}: {exc}) — "
                f"continuing with the full pool"
            )

    # -- offline enrichment / free OSINT ----------------------------------- #
    async def _phase_geo(self) -> None:
        """Open (or build once) the offline country/ASN index.

        The BGP/RIR dumps are downloaded once and parsed locally; every lookup
        afterwards is a local SQLite query, so no scanned address is ever sent
        to a third party for enrichment.
        """
        if not self.config.geoip:
            self.bus.emit("Offline geo enrichment disabled (--no-geo)", "debug", "geo")
            return
        try:
            from . import geoip
        except Exception as exc:  # pragma: no cover - module unavailable
            self.bus.warn(f"Geo module unavailable ({exc.__class__.__name__}: {exc})")
            return
        try:
            index = await geoip.ensure_index_async(
                self.config.cache_dir,
                bus=self.bus,
                offline=self.config.offline,
                allow_download=self.config.geoip_download,
                max_age_days=self.config.geoip_max_age_days,
            )
        except Exception as exc:  # noqa: BLE001 - enrichment must never be fatal
            self.bus.warn(
                f"Geo enrichment unavailable ({exc.__class__.__name__}: {exc})"
            )
            return
        if index is None:
            self.bus.warn("No offline geo index — flags/ASN will be omitted")
            return
        self._geo = index
        stats = index.stats()
        self.result.geo = stats
        age = stats.get("age_days")
        self.bus.phase(
            f"Offline geo index ready — {stats['entries']:,} range(s) "
            f"({stats['ipv4']:,} IPv4 / {stats['ipv6']:,} IPv6"
            + (f", {age:.0f} day(s) old" if isinstance(age, (int, float)) else "")
            + "), lookups are local"
        )

    def _geo_label(self, address: str | None) -> str:
        """``🇩🇰 DK · AS15133 MCI`` for one address (``""`` when unknown)."""
        if self._geo is None or not address:
            return ""
        try:
            record = self._geo.lookup(address)
        except Exception:  # pragma: no cover - defensive
            return ""
        return record.label if record is not None else ""

    def _annotate(self, target: Any) -> None:
        """Attach country/ASN to anything with an ``ip`` attribute."""
        if self._geo is None:
            return
        address = getattr(target, "ip", None)
        if not address or getattr(target, "country_code", None):
            return
        try:
            record = self._geo.lookup(str(address))
        except Exception:  # pragma: no cover - defensive
            return
        if record is None:
            return
        target.country_code = record.country_code or None
        target.country = record.country
        target.asn = record.asn or None
        target.as_org = record.as_org or None

    async def _phase_dns_intel(self) -> None:
        """Apex DNS intelligence — MX/SPF/DKIM/DMARC/CAA/NS/SOA/DNSSEC.

        All DNS, all free, no API: what the organisation publishes about its own
        zone (mail platform, sending infrastructure, allowed CAs, SaaS
        verifications, DNSSEC posture).
        """
        if not self.config.dns_intel:
            return
        try:
            from .dnsintel import collect_dns_intel
        except Exception:  # pragma: no cover - module unavailable
            return
        self.bus.phase("Phase 0b — apex DNS intelligence (free, DNS only)")
        try:
            intel = await collect_dns_intel(
                self.config.domain, self._resolver, bus=self.bus
            )
        except Exception as exc:  # noqa: BLE001 - intel is best effort
            self.bus.warn(f"DNS intelligence failed ({exc.__class__.__name__}: {exc})")
            return
        self.result.dns_intel = intel
        for line in intel.signals():
            self.bus.emit(
                f"DNS intel · {line}", "info", "osint", host=self.config.domain
            )
        for note in intel.notes:
            self.bus.warn(f"Mail/DNS posture — {note}", host=self.config.domain)

    async def _enrich_findings(self) -> None:
        """Geo-annotate every finding and look up reverse DNS for its address."""
        findings = [*self.result.findings, *self.result.redirects]
        if self._geo is not None:
            for finding in findings:
                self._annotate(finding)
            if findings:
                flagged = sum(1 for f in findings if f.country_code)
                countries = sorted({f.country_code for f in findings if f.country_code})
                self.bus.emit(
                    f"Geo — {flagged}/{len(findings)} finding(s) located"
                    + (f" in {', '.join(countries)}" if countries else ""),
                    "info",
                    "geo",
                )
        if self.config.reverse_dns:
            await self._annotate_ptr(findings)

    async def _annotate_ptr(self, findings: Sequence[Finding]) -> None:
        """Reverse-DNS (PTR) enrichment, capped and deduplicated per address."""
        if not findings or self.config.max_ptr_lookups <= 0:
            return
        counts: Counter[str] = Counter()
        addresses: list[str] = []
        seen: set[str] = set()
        for finding in findings:
            if not finding.ip:
                continue
            counts[finding.ip] += 1
            if finding.ip not in seen:
                seen.add(finding.ip)
                addresses.append(finding.ip)
        # Most common address first: shared hosting means many hosts, one PTR.
        # (One pass over the findings, not a nested scan per comparison.)
        addresses.sort(key=lambda ip: (-counts[ip], ip))
        addresses = addresses[: self.config.max_ptr_lookups]
        if not addresses:
            return
        results = await asyncio.gather(
            *(self._resolver.reverse(ip, log=False) for ip in addresses),
            return_exceptions=True,
        )
        names: dict[str, str] = {}
        for address, name in zip(addresses, results):
            if isinstance(name, str) and name:
                names[address] = name
        if not names:
            return
        for finding in findings:
            ptr = names.get(finding.ip)
            if ptr:
                finding.ptr = ptr
        self.result.ptr = names
        self.bus.emit(
            f"Reverse DNS — {len(names)}/{len(addresses)} address(es) have a PTR "
            "record: " + ", ".join(f"{ip} → {name}" for ip, name in list(names.items())[:3]),
            "info",
            "osint",
        )

    async def _phase_mining(self) -> None:
        """Mine extra in-scope hostnames from responses the scan already has."""
        if not self.config.web_mining:
            return
        try:
            from . import mining
        except Exception:  # pragma: no cover
            return
        bus = self.bus
        found: list[str] = []
        seen = set(self.result.resolutions) | set(self.result.filtered)

        # 1. Response headers of everything that answered (CSP, Link, Location…).
        for finding in [*self.result.findings, *self.result.redirects]:
            for host in mining.mine_headers(finding.headers or {}, self.config.domain):
                if host not in found:
                    found.append(host)
        if found:
            bus.emit(
                mining.summarise(found, self.config.domain, source="headers"),
                "debug",
                "osint",
            )

        # 2. robots.txt / sitemap.xml / security.txt of the confirmed interfaces.
        fetch_and_mine = None
        try:
            from .miner import fetch_and_mine as _fetch_and_mine

            fetch_and_mine = _fetch_and_mine
        except Exception:  # pragma: no cover - optional helper
            fetch_and_mine = None
        if fetch_and_mine is not None and self.result.findings:
            targets = [
                (finding.scheme, finding.subdomain, finding.port)
                for finding in self.result.findings[:24]
            ]
            try:
                mined = await fetch_and_mine(
                    targets, self.config.domain, bus=bus, concurrency=6
                )
            except Exception as exc:  # noqa: BLE001 - mining is best effort
                bus.warn(f"Web mining failed ({exc.__class__.__name__}: {exc})")
                mined = []
            for host in mined:
                if host not in found:
                    found.append(host)

        new_hosts = [host for host in found if host not in seen]
        if not new_hosts:
            bus.emit(
                "Web mining — no additional in-scope hostname found", "debug", "osint"
            )
            return
        self.result.mined_hosts.update(new_hosts)
        for host in new_hosts:
            self.result.osint_hosts.add(host)
        bus.phase(
            f"Web mining found {len(new_hosts)} new in-scope hostname(s) — "
            + ", ".join(new_hosts[:6])
        )
        if not self.config.mining_wave2 or self._stop.is_set():
            return
        await self._phase_wave2(new_hosts[: self.config.max_wave2_hosts])

    async def _phase_wave2(self, hosts: Sequence[str]) -> None:
        """Second wave: resolve and sweep the hosts mining uncovered."""
        bus = self.bus
        hosts = [host for host in hosts if host not in self.result.resolutions]
        if not hosts:
            return
        bus.phase(
            f"Phase 5 — second wave over {len(hosts)} mined host(s) "
            f"(resolve + port sweep + HTTP verification)"
        )
        resolved = await self._resolve_batch(hosts, label="wave 2")
        if not resolved or self._stop.is_set():
            return
        self.result.wave2_hosts.update(item.name for item in resolved)
        probe_ports = (
            list(self.config.ports.keys()) if self.profile.port_scan else [80, 443]
        )
        for start in range(0, len(resolved), self._host_batch):
            if self._stop.is_set():
                break
            batch = resolved[start : start + self._host_batch]
            try:
                await self._sweep_batch(batch, probe_ports)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - per-batch guard
                self.bus.bump("errors")
                bus.error(f"Second-wave batch failed ({exc.__class__.__name__}: {exc})")
        bus.emit(
            f"Second wave complete — {len(self.result.wave2_hosts)} host(s) scanned, "
            f"{len(self.result.findings)} interface(s) in total",
            "info",
            "stat",
        )

    def _seed_previous_findings(self) -> int:
        """Merge the newest report for this domain instead of clearing it.

        Running a passive profile and then a brute profile on the same domain
        used to start from an empty result set, so everything the first pass
        found vanished from the UI.  The previous report is now read back,
        marked ``from_previous_scan`` and merged into this run — new findings are
        added to them, duplicates are replaced by the fresh row.
        """
        if not self.config.carry_over:
            return 0
        try:
            from .workflow import load_previous_report
        except Exception:  # pragma: no cover - import guard
            return 0
        try:
            payload = load_previous_report(self.config.domain, self.config.output_dir)
        except Exception:  # pragma: no cover - defensive
            payload = None
        if not payload:
            return 0

        seeded = 0
        for row in payload.get("findings") or []:
            if not isinstance(row, Mapping):
                continue
            try:
                finding = Finding.from_dict(row)
            except Exception:  # pragma: no cover - malformed row
                continue
            if not finding.subdomain or not finding.port:
                continue
            self.result.findings.append(finding)
            self._jsonl_emit(finding)
            seeded += 1
        if not seeded:
            return 0

        self.result.carried_over = seeded
        self.bus.set_field("carried_over", seeded)
        finished = payload.get("finished_at")
        when = (
            time.strftime("%Y-%m-%d %H:%M", time.localtime(float(finished)))
            if isinstance(finished, (int, float))
            else "previously"
        )
        self.bus.emit(
            f"Merged {seeded} finding(s) from the previous scan of "
            f"{self.config.domain} ({when}) — results are never cleared, only "
            f"added to",
            "success",
            "phase",
            count=seeded,
            carried_over=seeded,
        )
        return seeded

    def _banner(self) -> None:
        from .theme import banner_lines

        for line in banner_lines(width=100):
            if line.strip():
                self.bus.emit(line, "info", "phase")

    def _open_jsonl(self) -> None:
        """Open the live NDJSON sink when ``--jsonl`` is enabled."""
        self.result.stem = (
            f"subsonar_{self.config.domain}_{time.strftime('%Y%m%d-%H%M%S')}"
        )
        self._jsonl = None
        if not self.config.jsonl:
            return
        try:
            from ..reporters import JsonlSink

            self._jsonl = JsonlSink(
                self.config.output_dir / f"{self.result.stem}.jsonl",
                domain=self.config.domain,
            )
            self._jsonl.open(
                meta={
                    "tool": "subsonar",
                    "target": self.config.domain,
                    "profile": self.profile.id,
                }
            )
        except Exception as exc:  # pragma: no cover - export is best effort
            self.bus.warn(f"JSONL export unavailable ({exc.__class__.__name__}: {exc})")
            self._jsonl = None

    def _jsonl_emit(self, finding: Finding) -> None:
        if self._jsonl is None:
            return
        try:
            self._jsonl.finding(finding.to_dict())
        except Exception:  # pragma: no cover - never break a scan for export
            pass

    def _finish(self) -> ScanResult:
        self.result.finished_at = time.time()
        self.bus.set_field("finished_at", self.result.finished_at)
        self.bus.set_field("phase", "done")
        self._dedupe_findings()
        self._score_findings()
        self.bus.set_field("findings", len(self.result.findings))
        self.result.findings.sort(
            key=lambda f: (-f.confidence, f.subdomain, f.port)
        )
        if self._jsonl is not None:
            try:
                self._jsonl.close()
            except Exception:  # pragma: no cover - best effort
                pass
            self._jsonl = None
        return self.result

    async def _fingerprint_finding(self, finding: Finding, probe: WebProbeResult) -> None:
        """Attach favicon hash, technologies and data-file probes to a finding.

        Runs only for confirmed interfaces, and never lets a failure affect the
        finding itself — fingerprinting is enrichment, not verification.
        """
        try:
            from .fingerprint import fingerprint as run_fingerprint
        except Exception:  # pragma: no cover - module unavailable
            return
        try:
            result = await run_fingerprint(
                self._probe,
                finding.scheme,
                finding.subdomain,
                finding.ip,
                finding.port,
                bus=self.bus,
                timeout=min(6.0, self.config.http_timeout * 1.5),
                meta=probe,
                probe_paths=True,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.bus.emit(
                f"Fingerprinting skipped for {finding.host_port} — "
                f"{exc.__class__.__name__}: {exc}",
                "debug",
                "http",
                host=finding.subdomain,
                port=finding.port,
            )
            return
        finding.favicon_hash = result.favicon_hash
        finding.technologies = [match.name for match in result.technologies]
        finding.data_files = dict(result.data_files)
        finding.headers = dict(result.headers)
        if finding.technologies or result.favicon_hash or result.data_files:
            self.bus.emit(
                f"Fingerprint {finding.host_port} — "
                + (f"favicon {result.favicon_hash} · " if result.favicon_hash else "")
                + (", ".join(finding.technologies[:6]) or "no tech signature")
                + (
                    f" · files: {', '.join(f'{p}={s}' for p, s in finding.data_files.items())}"
                    if finding.data_files
                    else ""
                ),
                "info",
                "http",
                host=finding.subdomain,
                port=finding.port,
            )
        await self._run_template_checks(finding)

    async def _run_template_checks(self, finding: Finding) -> None:
        """Run template-style exposure checks and attach matches to a finding.

        Status-only by design (see :mod:`subsonar.core.templates`): a match on
        ``/.env`` records the status code and never reads a byte of the body.
        """
        if not self.config.template_checks:
            return
        try:
            from .templates import run_template_checks
        except Exception:  # pragma: no cover - module unavailable
            return
        try:
            matches = await run_template_checks(
                self._probe,
                finding.scheme,
                finding.subdomain,
                finding.ip,
                finding.port,
            )
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover - enrichment is best effort
            return
        if not matches:
            return
        finding.exposures = [match.to_dict() for match in matches]
        for match in matches:
            self.bus.emit(
                f"Check {match.severity.upper()} — {finding.host_port}: "
                f"{match.name} ({match.evidence})",
                "warn" if match.severity in ("high", "critical") else "info",
                "check",
                host=finding.subdomain,
                port=finding.port,
            )

    def _score_findings(self) -> None:
        """Rank findings by an explainable confidence score."""
        if not self.config.score_findings or not self.result.findings:
            return
        try:
            from .confidence import rank_findings
        except Exception:  # pragma: no cover - module unavailable
            return
        report = self.result.wildcard
        try:
            ranked = rank_findings(
                self.result.findings,
                wildcard_ips=tuple(sorted(report.ips)) if report else (),
                wildcard_fingerprints=(
                    tuple(sorted(report.http_fingerprints)) if report else ()
                ),
                # How many findings share a content length / fingerprint: a high
                # count means the same page is answering on many ports.
                shared_content_lengths=_duplicate_count(
                    f.content_length for f in self.result.findings
                ),
                shared_fingerprints=_duplicate_count(
                    f.fingerprint for f in self.result.findings
                ),
                open_ports=sum(len(p) for p in self.result.open_ports.values()),
            )
        except Exception as exc:  # pragma: no cover - defensive
            self.bus.warn(
                f"Confidence scoring failed ({exc.__class__.__name__}: {exc})"
            )
            return
        breakdown_labels: dict[int, str] = {}
        for finding, breakdown in ranked:
            finding.confidence = breakdown.score
            finding.confidence_label = breakdown.label
            finding.confidence_reasons = list(breakdown.reasons)
            finding.confidence_penalties = list(breakdown.penalties)
            breakdown_labels[id(finding)] = breakdown.label
        summary = {"high": 0, "medium": 0, "low": 0}
        for label in breakdown_labels.values():
            summary[label] = summary.get(label, 0) + 1
        self.bus.emit(
            f"Confidence scoring — {summary['high']} high, {summary['medium']} "
            f"medium, {summary['low']} low",
            "info",
            "stat",
            scores=summary,
        )

    def _dedupe_key(self, finding: Finding) -> tuple:
        """Identity of one interface: host, address, fingerprint, scheme, status.

        Two findings sharing this key are the *same* web interface reached on
        different ports, which is how a vhost on 80/8080/2082/2086/2095 collapses
        into a single row.
        """
        return (
            finding.subdomain,
            finding.ip,
            finding.fingerprint,
            finding.scheme,
            finding.status,
        )

    def _drop_superseded_carried_over(self) -> None:
        """Drop merged rows that this run re-confirmed (same host/port/kind).

        The identity deliberately ignores the address: Cloudflare/Akamai-style
        round-robin DNS answers with a different edge IP on every query, so keying
        on the IP would keep the previous scan's copy of an interface next to the
        fresh one and show the same URL twice.
        """
        carried = [f for f in self.result.findings if f.from_previous_scan]
        if not carried:
            return
        confirmed: dict[tuple, Finding] = {}
        for finding in self.result.findings:
            if finding.from_previous_scan:
                continue
            confirmed[
                (finding.subdomain, finding.port, finding.scheme, finding.status)
            ] = finding
        if not confirmed:
            return
        kept: list[Finding] = []
        for finding in self.result.findings:
            if not finding.from_previous_scan:
                kept.append(finding)
                continue
            fresh = confirmed.get(
                (finding.subdomain, finding.port, finding.scheme, finding.status)
            )
            if fresh is None:
                kept.append(finding)
                continue
            self.result.filtered[f"{finding.subdomain}:{finding.port}"] = (
                "superseded by this run"
            )
            self.bus.filtered(
                f"Dropped carried-over ://{finding.subdomain}:{finding.port} — "
                f"re-confirmed this run at {fresh.ip}"
                + (
                    f" (the address rotated from {finding.ip})"
                    if fresh.ip != finding.ip
                    else ""
                ),
                host=finding.subdomain,
                port=finding.port,
                ip=finding.ip,
            )
        self.result.findings = kept

    def _dedupe_findings(self) -> None:
        """Collapse the *same* interface answered on several ports.

        A single vhost is frequently reachable on 80, 8080, 2082, 2086, 2095 …
        — those are one web interface, not five.  Findings are grouped by
        ``(host, ip, fingerprint, scheme, status)`` and only the most canonical
        port survives; the rest are recorded as filtered duplicates so the live log
        stays transparent about the drop.

        Carried-over rows are dropped first when this run re-confirmed the same
        interface/port — including on a *rotating* address (round-robin DNS hands
        out a different edge IP per query), which would otherwise leave the same
        URL in the table twice.
        """
        from .config import TLS_FIRST_PORTS

        self._drop_superseded_carried_over()
        canonical = {
            443: 0, 8443: 1, 9443: 2, 10000: 3, 2087: 4, 2083: 5, 2096: 6,
            80: 10, 8080: 11, 8000: 12, 8888: 13, 3000: 14, 5000: 15, 9000: 16,
            2082: 20, 2086: 21, 2095: 22,
        }
        groups: dict[tuple, list[Finding]] = {}
        for finding in self.result.findings:
            groups.setdefault(self._dedupe_key(finding), []).append(finding)

        kept: list[Finding] = []
        for group in groups.values():
            if len(group) == 1:
                kept.append(group[0])
                continue
            group.sort(
                key=lambda f: (
                    # A finding re-confirmed by *this* run beats the carried-over
                    # copy of the same row.
                    0 if (f.port in TLS_FIRST_PORTS) == (f.scheme == "https") else 1,
                    canonical.get(f.port, 100),
                    1 if f.from_previous_scan else 0,
                    f.port,
                )
            )
            winner = group[0]
            winner.aliases = sorted(f.port for f in group[1:])
            kept.append(winner)
            for loser in group[1:]:
                self.bus.filtered(
                    f"Filtered out ://{loser.subdomain}:{loser.port} — same "
                    f"interface as {winner.subdomain}:{winner.port} "
                    f"(identical response fingerprint {loser.fingerprint})",
                    host=loser.subdomain,
                    port=loser.port,
                    ip=loser.ip,
                )
                self.result.filtered[
                    f"{loser.subdomain}:{loser.port}"
                ] = f"duplicate of port {winner.port}"
        if len(kept) != len(self.result.findings):
            self.bus.emit(
                f"Collapsed {len(self.result.findings) - len(kept)} duplicate "
                f"port finding(s) — {len(kept)} distinct web interface(s) remain",
                "info",
                "probe",
            )
        self.result.findings = kept
        self._promote_redirects()

    def _promote_redirects(self) -> None:
        """Surface a redirect-only port when its host has no real interface.

        ``support.example.com:2082`` bouncing to ``https://support.example.com/`` is not
        a web interface, but if 443 were firewalled it would still be the only
        evidence of a live web service.  Those bounce entries are therefore kept
        as a labelled fallback (``kind=redirect``) instead of being thrown away.
        """
        if not self.result.redirects:
            return
        have = {finding.subdomain for finding in self.result.findings}
        by_host: dict[str, list[Finding]] = {}
        for finding in self.result.redirects:
            if finding.subdomain in have:
                continue
            by_host.setdefault(finding.subdomain, []).append(finding)
        for host, candidates in by_host.items():
            candidates.sort(key=lambda f: (f.port != 80 and f.port != 443, f.port))
            winner = candidates[0]
            self.result.findings.append(winner)
            self._jsonl_emit(winner)
            # ``_sweep_batch`` records a bare-host key when only bounces answered;
            # ``_dedupe_findings`` uses ``host:port``.  Clear both so a promoted
            # redirect is not reported as filtered as well.
            for key in (host, f"{host}:{winner.port}"):
                self.result.filtered.pop(key, None)
            self.bus.emit(
                f"Only a redirect answered for {host} — reporting "
                f"{winner.url} → {winner.redirect_chain[-1] if winner.redirect_chain else '?'} "
                f"as a redirect entry (kind=redirect)",
                "info",
                "probe",
                host=host,
                port=winner.port,
            )

    # -- phase 1: candidates ---------------------------------------------- #
    async def _collect_candidates(self) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []

        def add(host: str) -> bool:
            host = host.strip().lower().rstrip(".")
            if not host or host in seen:
                return False
            if not is_valid_hostname(host, self.config.domain):
                return False
            seen.add(host)
            ordered.append(host)
            return True

        # The apex is always a candidate — it is the explicitly requested target.
        if add(self.config.domain):
            self.result.osint_hosts.add(self.config.domain)

        if self.profile.passive:
            await self._phase_osint(add)
        if self.profile.passive and self.config.enable_plugin_sources:
            await self._phase_plugin_sources(add)
        if self.profile.brute:
            await self._phase_brute(add)

        if self.config.enable_discovery:
            await self._phase_discovery(add)

        if not ordered:
            self.bus.warn(
                "No candidates discovered — falling back to the apex domain"
            )
            add(self.config.domain)

        if self.config.max_candidates and len(ordered) > self.config.max_candidates:
            dropped = len(ordered) - self.config.max_candidates
            ordered = ordered[: self.config.max_candidates]
            self.bus.warn(
                f"Candidate cap reached — {dropped:,} host(s) dropped "
                f"(max_candidates={self.config.max_candidates:,})"
            )

        self.bus.set_field("candidates", len(ordered))
        self.bus.set_field("osint_unique", len(self.result.osint_hosts))
        self.bus.set_field("brute_unique", len(self.result.brute_hosts))
        self.bus.phase(
            f"Candidate pool built — {len(ordered)} unique host(s) "
            f"({len(self.result.osint_hosts)} OSINT / {len(self.result.brute_hosts)} brute "
            f"/ {len(self.result.discovered_hosts)} active discovery)"
        )
        return ordered

    async def _phase_discovery(self, add: Callable[[str], bool]) -> None:
        """Active discovery: SAN harvesting, CNAME chasing, permutations."""
        bus = self.bus
        bus.phase(
            "Phase 2b — active discovery (TLS SAN harvesting, CNAME chase, "
            "recursive permutations)"
        )
        known = sorted(
            set(self.result.osint_hosts)
            | set(self.result.brute_hosts)
            | {self.config.domain}
        )
        hosts, stats = await expand_discovery(
            self.config.domain,
            known,
            resolver=self._resolver,
            bus=bus,
            depth=self.config.permutation_depth,
            permutation_limit=self.config.permutation_limit,
            enable_san=self.config.enable_san,
            enable_permutations=self.config.enable_permutations,
            enable_cnames=self.config.enable_cnames,
        )
        added = 0
        for host in hosts:
            if add(host):
                self.result.discovered_hosts.add(host)
                added += 1
        self.result.discovery = stats
        bus.emit(
            f"Active discovery queued {added} new candidate host(s) "
            f"(SAN {stats.san_hosts}, permutations {stats.permutations}, "
            f"CNAME hops {stats.cname_hops}"
            + (
                ", providers: " + ", ".join(sorted(stats.providers))
                if stats.providers
                else ""
            )
            + ")",
            "info",
            "osint",
            added=added,
        )

    async def _phase_osint(self, add: Callable[[str], bool]) -> None:
        bus = self.bus
        bus.phase("Phase 1/4 — passive OSINT collection (0 packets to target)")
        async with OSINTCollector(self.config.domain, bus=bus) as collector:
            tasks = [
                asyncio.create_task(self._run_source(collector, name, add))
                for name in self.profile.osint_sources
            ]
            while tasks:
                done, pending = await asyncio.wait(
                    tasks, timeout=2.0, return_when=asyncio.FIRST_COMPLETED
                )
                for task in done:
                    tasks.remove(task)
                    exc = task.exception()
                    if exc is not None:
                        bus.warn(f"OSINT task failed: {exc.__class__.__name__}: {exc}")
                if not done and tasks:
                    bus.emit(
                        f"OSINT collection in progress — "
                        f"{len(self.result.osint_hosts)} host(s) so far, "
                        f"{len(tasks)} source(s) pending",
                        "debug",
                        "osint",
                    )
            self.result.sources = dict(collector.reports)
        for name, report in self.result.sources.items():
            bus.emit(
                f"Source {name}: {report.hosts} host(s), "
                f"{report.errors} error(s), {report.duration:.1f}s",
                "info",
                "osint",
            )

    async def _run_source(
        self, collector: OSINTCollector, name: str, add: Callable[[str], bool]
    ) -> None:
        generator = {
            "crt.sh": collector.crtsh,
            "hackertarget": collector.hackertarget,
            "anubis": collector.anubis,
        }.get(name)
        if generator is None:
            return
        count = 0
        async for result in generator():
            if self._stop.is_set():
                return
            if add(result.host):
                count += 1
                self.result.osint_hosts.add(result.host)
                self.bus.bump_source(result.source, 1)
                if count % 25 == 0:
                    self.bus.osint(
                        f"{result.source}: queued {count} new host(s) — latest "
                        f"{result.host}",
                        host=result.host,
                        source=result.source,
                    )
            await asyncio.sleep(0)
        self.bus.osint(
            f"Source {name} exhausted — {count} new host(s) queued",
            source=name,
            count=count,
        )

    async def _phase_plugin_sources(self, add: Callable[[str], bool]) -> None:
        """Run the plugin registry — extra free, no-signup discovery sources.

        Additive on purpose: the built-in three keep running through
        :class:`OSINTCollector`, and every plugin is independently optional and
        independently fallible.
        """
        bus = self.bus
        try:
            from .sources import all_sources, collect, free_sources
        except Exception as exc:  # pragma: no cover - plugin package missing
            bus.warn(
                f"Discovery plugins unavailable ({exc.__class__.__name__}: {exc})"
            )
            return

        if self.config.plugin_sources:
            wanted = [
                name
                for name in self.config.plugin_sources
                if name in {source.name for source in all_sources()}
            ]
        else:
            wanted = [source.name for source in free_sources()]
        if not wanted:
            return

        bus.phase(
            f"Phase 1b — {len(wanted)} plugin source(s): {', '.join(wanted)}"
        )
        added = 0
        try:
            async for result in collect(
                wanted, self.config.domain, bus=bus, source_timeout=45.0
            ):
                if self._stop.is_set():
                    return
                host = getattr(result, "host", None)
                if not host:
                    continue
                if add(host):
                    added += 1
                    self.result.osint_hosts.add(host)
                    self.result.plugin_hosts.add(host)
                    self.bus.bump_source(getattr(result, "source", "plugin"), 1)
                    if added % 25 == 0:
                        bus.osint(
                            f"plugins queued {added} new host(s) — latest {host}",
                            host=host,
                            source=getattr(result, "source", "plugin"),
                        )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            bus.warn(
                f"Plugin collection failed ({exc.__class__.__name__}: {exc}) — "
                f"continuing with the built-in sources"
            )
        bus.emit(
            f"Plugin sources added {added} new candidate host(s)",
            "info",
            "osint",
            added=added,
        )

    async def _phase_brute(self, add: Callable[[str], bool]) -> None:
        bus = self.bus
        size = self.profile.wordlist_size or 1_000
        bus.phase(f"Phase 2/4 — brute-force candidate generation ({size:,} labels)")
        if self.profile.wildcard_check:
            # Wildcard pre-flight runs *first* so the warning lands before any
            # brute-force packet is emitted.
            await self._phase_wildcard()
        spec = self._wordlists.spec
        if spec is not None and spec.builtin:
            bus.emit(
                f"Using the built-in wordlist {spec.name} — {spec.label} "
                f"({spec.approx_size:,} labels, {spec.licence}, no download)",
                "info",
                "wordlist",
            )
        else:
            where = spec.provenance or spec.source if spec is not None else "SecLists"
            bus.emit(
                f"Streaming wordlist {spec.name if spec else 'seclists'} from raw "
                f"GitHub ({where}) — cached locally after the first run",
                "info",
                "wordlist",
            )
        wordlist = await self._wordlists.load(
            size,
            domain=self.config.domain,
            offline=self.config.offline,
        )
        self.result.wordlist = wordlist
        added = 0
        for label in wordlist.words:
            host = f"{label}.{self.config.domain}"
            if add(host):
                added += 1
                self.result.brute_hosts.add(host)
        mutated = 0
        if self.config.wordlist_permutations:
            from .discovery import permute_labels

            mutations = permute_labels(
                wordlist.words,
                depth=1,
                limit=self.config.wordlist_permutation_limit,
            )
            for label in mutations:
                host = f"{label}.{self.config.domain}"
                if add(host):
                    mutated += 1
                    self.result.brute_hosts.add(host)
            bus.emit(
                f"Wordlist permutation pass added {mutated} new candidate host(s) "
                f"(env/region/number affixes)",
                "info",
                "wordlist",
            )
        bus.emit(
            f"Wordlist generated {added} new candidate host(s) "
            f"({wordlist.size - added} duplicates/already known)",
            "info",
            "wordlist",
        )

    async def _phase_wildcard(self) -> None:
        """Detect wildcard DNS/HTTP responders before brute-force traffic."""
        bus = self.bus
        bus.phase("Wildcard DNS pre-flight check")
        bus.wildcard(
            f"Checking wildcard status for target {self.config.domain}...",
            host=self.config.domain,
        )

        async def http_probe(candidate: str) -> str | None:
            """Fingerprint a random label so wildcard web servers are caught."""
            for port in (80, 443):
                try:
                    probe = await self._probe.probe(candidate, candidate, port)
                except Exception:
                    continue
                if probe.ok and probe.fingerprint:
                    return probe.fingerprint
            return None

        report = await self._resolver.detect_wildcard(
            self.config.domain, samples=3, probe=http_probe
        )
        self.result.wildcard = report
        if report.wildcard:
            bus.set_field("wildcard_hits", 1)
            detail = ", ".join(sorted(report.ips)) or "wildcard HTTP responder"
            bus.wildcard(
                f"WARNING — {self.config.domain} is wildcard; every brute-forced "
                f"host resolving only to {detail} will be filtered as a false "
                f"positive",
                host=self.config.domain,
            )
            self.result.notes.append(f"wildcard DNS detected ({detail})")
            if report.http_fingerprints:
                self.result.notes.append(
                    f"wildcard HTTP signature(s): {', '.join(sorted(report.http_fingerprints))}"
                )
        else:
            bus.emit(
                f"Wildcard check complete — {self.config.domain} is not wildcard, "
                f"brute-force results can be trusted",
                "success",
                "wildcard",
                host=self.config.domain,
            )

    # -- phase 3: DNS resolution ------------------------------------------ #
    async def _phase_resolve(self, candidates: Sequence[str]) -> list[DNSResult]:
        bus = self.bus
        bus.phase(
            f"Phase 3/4 — anonymous DNS resolution of {len(candidates):,} host(s) "
            f"via {len(self.config.resolver_pool)} privacy resolvers"
            + (
                f" · {self._resolver.limiter.summary()}"
                if self._resolver.limiter.enabled
                else ""
            )
        )
        resolved = await self._resolve_batch(candidates, label="phase 3")
        bus.phase(
            f"DNS resolution complete — {len(resolved)} host(s) answered "
            f"({self.bus.snapshot()['dns_failed']} failures)"
            + (
                f" · rate limiter waited {self._resolver.rate_wait_seconds:.1f}s "
                f"over {self._resolver.rate_waits} query attempt(s)"
                if self._resolver.rate_waits
                else ""
            )
            + (
                f" · {self._resolver.deadline_aborts} name(s) abandoned at the "
                f"{self.config.dns_name_deadline:g}s per-name budget"
                if self._resolver.deadline_aborts
                else ""
            )
        )
        return resolved

    async def _resolve_batch(
        self, candidates: Sequence[str], *, label: str = "batch"
    ) -> list[DNSResult]:
        """Resolve *candidates* with the worker pool and return the live hosts."""
        bus = self.bus
        queue: asyncio.Queue[str | None] = asyncio.Queue()
        for host in candidates:
            queue.put_nowait(host)
        workers = max(1, min(self.config.dns_concurrency, len(candidates) or 1))
        tasks = [
            asyncio.create_task(self._resolve_worker(queue, index))
            for index in range(workers)
        ]
        started = time.perf_counter()
        last_report = started
        while any(not task.done() for task in tasks):
            await asyncio.sleep(0.5)
            now = time.perf_counter()
            if now - last_report >= 2.0:
                last_report = now
                stats = self.bus.snapshot()
                # Progress across the whole run: resolution is half the work of a
                # scan, the port sweep the other half.
                self.bus.stats.set_progress(
                    (stats["dns_resolved"] + stats["dns_failed"]) * 2,
                    max(1, len(candidates) * 2),
                )
                bus.emit(
                    f"DNS progress ({label}) — {stats['dns_resolved']} resolved / "
                    f"{stats['dns_failed']} failures of {len(candidates)} "
                    f"({stats['rate']}/s, {stats['elapsed']:.0f}s elapsed)",
                    "debug",
                    "stat",
                )
            if self._stop.is_set():
                break
        await asyncio.gather(*tasks, return_exceptions=True)
        bus.set_field("candidates", len(candidates))
        wanted = set(candidates)
        resolved = [
            result
            for host, result in self.result.resolutions.items()
            if result.ok and host in wanted
        ]
        resolved.sort(key=lambda item: item.name)
        snapshot = self.bus.snapshot()
        self.bus.stats.set_progress(
            snapshot["dns_resolved"] + snapshot["dns_failed"], max(1, len(candidates))
        )
        bus.emit(
            f"DNS ({label}) — {len(resolved)} of {len(candidates)} host(s) answered "
            f"in {time.perf_counter() - started:.1f}s",
            "info",
            "dns",
        )
        return resolved

    async def _resolve_worker(self, queue: asyncio.Queue[str | None], index: int) -> None:
        while True:
            if self._stop.is_set():
                return
            try:
                host = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                if self._delay[1] > 0:
                    await self._sleep_delay()
                result = await self._resolver.resolve(host, log=self.profile.id != 8)
                self.bus.bump("dns_queries")
                if result.ok and self.config.ipv6:
                    await self._augment_ipv6(host, result)
                if result.ok and self.config.confirm_resolvers >= 2:
                    await self._confirm_resolution(host, result)
                if not result.ok:
                    self.bus.bump("dns_failed")
                    reason = result.error or "no records"
                    if reason == "NXDOMAIN":
                        self.bus.filtered(
                            f"Filtered out ://{host} — NXDOMAIN (no DNS record)",
                            host=host,
                        )
                    elif result.empty_noerror or reason == "NOERROR/empty":
                        self.bus.filtered(
                            f"Filtered out ://{host} — NOERROR with an empty answer "
                            f"(name exists, no address)",
                            host=host,
                        )
                    else:
                        self.bus.filtered(
                            f"Filtered out ://{host} — {reason}",
                            host=host,
                        )
                    self.result.filtered[host] = reason
                    continue
                if self._is_wildcard_false_positive(host, result):
                    self.bus.bump("wildcard_filtered")
                    self.bus.filtered(
                        f"Filtered out ://{host} — wildcard DNS matches "
                        f"{', '.join(result.addresses)} (false positive)",
                        host=host,
                        ip=result.ip,
                    )
                    self.result.filtered[host] = "wildcard"
                    continue
                self.bus.bump("dns_resolved")
                self.result.resolutions[host] = result
                geo = self._geo_label(result.ip)
                self.bus.dns(
                    f"Resolved ://{host} → {', '.join(result.addresses)} "
                    + (f"({geo}) " if geo else "")
                    + f"via [{result.resolver}] in {result.rtt_ms:.0f} ms",
                    host=host,
                    ip=result.ip,
                )
                total = len(self.result.resolutions)
                if total % self._progress_interval == 0:
                    bus.emit(
                        f"{total} host(s) resolved — {self.bus.stats.dns_failed} "
                        f"negative answer(s) so far",
                        "debug",
                        "stat",
                    )
            finally:
                queue.task_done()

    async def _augment_ipv6(self, host: str, result: DNSResult) -> None:
        """Add AAAA addresses to a resolution so IPv6-only hosts are scannable.

        IPv6 web interfaces are vastly under-scanned, so this finds services
        that A-record-only tooling misses entirely.
        """
        try:
            aaaa = await self._resolver.resolve(host, log=False, ipv6=True)
        except Exception:
            return
        added = [addr for addr in aaaa.addresses if addr not in result.addresses]
        if not added:
            return
        result.addresses.extend(added)
        self.bus.bump("ipv6_hosts")
        self.bus.emit(
            f"AAAA records for ://{host} — {', '.join(added)} "
            f"(IPv6 addresses will be port-scanned too)",
            "debug",
            "dns",
            host=host,
        )

    async def _confirm_resolution(self, host: str, result: DNSResult) -> None:
        """Require several independent resolvers to agree on an address.

        Catches poisoned answers, hijacked wildcards and single-node lies — the
        failure modes that make a scanner report infrastructure it never
        actually reached.
        """
        needed = max(2, self.config.confirm_resolvers)
        primary = set(result.addresses)
        agreements = 1
        disagreeing: list[str] = []
        # Snapshot the list first: a probe may retire a node from the live set.
        live = [
            server
            for server in list(self._resolver.live_servers)
            if server != result.resolver
        ]
        if not live:
            return
        # Ask N distinct nodes directly — not the rotating pool — so the
        # confirmations are genuinely independent of each other.
        sample = live[: max(needed - 1, 1)]
        for server in sample:
            try:
                # Pin the main resolver to this node: one socket pool, no new
                # connection churn — and no cache reads/writes, so the answer is
                # genuinely that node's own answer.
                answer = await self._resolver.resolve(
                    host, log=False, server=server, use_cache=False
                )
            except Exception:
                continue
            if set(answer.addresses) & primary:
                agreements += 1
            elif answer.addresses:
                disagreeing.append(f"{server}→{','.join(answer.addresses)}")
            if agreements >= needed:
                break
        result.confirmed_by = agreements
        result.disagreements = disagreeing
        if agreements >= needed:
            self.bus.bump("dns_confirmed")
            self.bus.emit(
                f"DNS confirmed for ://{host} — {agreements} resolver(s) agree on "
                f"{', '.join(sorted(primary))}",
                "debug",
                "dns",
                host=host,
                ip=result.ip,
            )
        else:
            self.bus.bump("dns_unconfirmed")
            self.bus.warn(
                f"Only {agreements} resolver(s) confirmed ://{host} "
                f"({', '.join(sorted(primary))})"
                + (f"; disagreement: {'; '.join(disagreeing)}" if disagreeing else "")
            )

    def _is_wildcard_false_positive(self, host: str, result: DNSResult) -> bool:
        report = self.result.wildcard
        if report is None or not report.wildcard or not self.config.wildcard_filter:
            return False
        if host == self.config.domain:
            # The explicitly requested apex is always kept.
            return False
        if host in self.result.osint_hosts:
            # OSINT-confirmed hosts are trusted even behind wildcard DNS.
            return False
        return report.is_false_positive(result.addresses)

    def _is_wildcard_soft_404(self, probe: WebProbeResult) -> bool:
        """True when a web response merely re-serves the wildcard signature."""
        report = self.result.wildcard
        if (
            report is None
            or not report.wildcard
            or not self.config.wildcard_filter
            or not report.http_fingerprints
            or not probe.fingerprint
        ):
            return False
        if probe.host == self.config.domain or probe.host in self.result.osint_hosts:
            return False
        return probe.fingerprint in report.http_fingerprints

    # -- phase 4: ports + HTTP -------------------------------------------- #
    async def _phase_scan(self, resolved: Sequence[DNSResult]) -> None:
        """Port-major sweep with streaming HTTP verification.

        Hosts are processed in batches.  Inside a batch the scanner sweeps port
        by port across *all* hosts (so one slow/filtered host cannot idle worker
        slots), and each batch's confirmed open ports are handed to the HTTP
        prober immediately — port scanning and HTTP verification therefore
        overlap instead of running as two serial phases.
        """
        bus = self.bus
        if not resolved:
            bus.warn("No host resolved — nothing to scan")
            return

        matrix = list(self.config.ports.keys())
        probe_ports = matrix if self.profile.port_scan else [80, 443]
        batch_size = max(1, self._host_batch)
        batches = [
            list(resolved[i : i + batch_size])
            for i in range(0, len(resolved), batch_size)
        ]
        # Phase-aware progress: the bar covers DNS *and* the sweep, so it no longer
        # sits at 100 % as soon as resolution finishes.
        dns_done = self.bus.snapshot()["dns_resolved"] + self.bus.snapshot()["dns_failed"]
        total_probes = max(1, len(resolved) * len(probe_ports))
        self.bus.stats.set_progress(dns_done, dns_done + total_probes)
        bus.phase(
            f"Phase 4/4 — port-major sweep ({len(probe_ports)} ports × "
            f"{len(resolved)} host(s) in {len(batches)} batch(es), "
            f"fast timeout {self.config.tcp_fast_timeout:.2f}s → "
            f"{self.config.tcp_timeout:.2f}s) + streaming HTTP verification"
            + (
                f" · {self._scanner.limiter.summary(prefix='connect limit: ', unit='connects/s')}"
                if self._scanner.limiter.enabled
                else ""
            )
        )

        started = time.perf_counter()
        semaphore = asyncio.Semaphore(max(1, self._host_batch_workers))
        completed = 0

        async def run_batch(batch: list[DNSResult]) -> None:
            nonlocal completed
            async with semaphore:
                if self._stop.is_set():
                    return
                try:
                    await self._sweep_batch(batch, probe_ports)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # pragma: no cover - per-batch guard
                    self.bus.bump("errors")
                    self.bus.error(
                        f"Batch scan failure ({len(batch)} host(s)) — "
                        f"{exc.__class__.__name__}: {exc}"
                    )
                finally:
                    completed += 1

        tasks = [asyncio.create_task(run_batch(batch)) for batch in batches]
        last_report = started
        while any(not task.done() for task in tasks):
            await asyncio.sleep(0.5)
            now = time.perf_counter()
            stats = self.bus.snapshot()
            self.bus.stats.set_progress(
                dns_done + min(total_probes, stats["ports_probed"]),
                dns_done + total_probes,
            )
            if now - last_report >= 2.0:
                last_report = now
                pstats = self._scanner.stats
                bus.emit(
                    f"Probe progress — {stats['ports_open']} open / "
                    f"{stats['ports_probed']} probed "
                    f"({pstats.rate:,.0f}/s, {pstats.retries} adaptive retries) / "
                    f"{stats['http_probes']} HTTP probe(s) / "
                    f"{stats['findings']} web interface(s) / "
                    f"{completed}/{len(batches)} batch(es) done",
                    "debug",
                    "stat",
                )
            if self._stop.is_set():
                break
        await asyncio.gather(*tasks, return_exceptions=True)

        pstats = self._scanner.stats
        bus.emit(
            f"Port sweep stats — {pstats.probes:,} probes in {pstats.duration:.1f}s "
            f"({pstats.rate:,.0f}/s): {pstats.opens} open, {pstats.refused} refused, "
            f"{pstats.timeouts} timed out, {pstats.retries} adaptive retry(ies)"
            + (
                f", connect limiter waited {pstats.rate_wait_seconds:.1f}s over "
                f"{pstats.rate_waits:,} probe(s)"
                if pstats.rate_waits
                else ""
            ),
            "info",
            "stat",
        )
        # The sweep is finished: the bar is complete even if a few probes were
        # skipped because a filter dropped their host.
        self.bus.stats.set_progress(1, 1)
        bus.phase(
            f"Scan complete — {self.bus.stats.ports_open} open port(s), "
            f"{len(self.result.findings)} web interface(s) confirmed in "
            f"{time.perf_counter() - started:.1f}s"
        )

    async def _sweep_batch(self, batch: Sequence[DNSResult], ports: Sequence[int]) -> None:
        """Sweep one host batch and verify every open port immediately.

        Hosts that resolve into a third-party provider (Office 365 / Exchange
        Online, SharePoint, S3, Heroku, a CDN …) are **not scanned at all**:
        they are somebody else's shared infrastructure, so neither a port sweep
        nor an HTTP probe against them says anything about the target.  They are
        recorded with their provider (``result.provider_hosts``) and filtered
        with that reason instead.
        """
        bus = self.bus
        provider_by_host: dict[str, Provider | None] = {
            item.name: detect_provider(item.cnames, item.name)
            for item in batch
            if item.ip
        }
        skipped: dict[str, Provider] = {}
        if self.config.skip_provider_hosts:
            skipped = {
                host: provider
                for host, provider in provider_by_host.items()
                if provider is not None and provider.skip
            }
        if skipped:
            for host in sorted(skipped):
                provider = skipped[host]
                self.result.provider_hosts[host] = provider.name
                self.result.filtered[host] = (
                    f"third-party host ({provider.name}) — not scanned"
                )
                bus.bump("provider_skipped")
                bus.filtered(
                    f"Skipped ://{host} — hosted on shared {provider.category} "
                    f"infrastructure ({provider.name}); not port-scanned",
                    host=host,
                )
            bus.emit(
                f"Skipped {len(skipped)} Office 365-style tenant host(s) — "
                + ", ".join(sorted({p.name for p in skipped.values()}))
                + " (scan them with --scan-provider-hosts)",
                "info",
                "port",
            )
        targets = [
            (item.name, item.ip)
            for item in batch
            if item.ip and item.name not in skipped
        ]
        if not targets:
            return
        bus.bump_clamped("active_tasks", 1)
        try:
            swept = await self._scanner.sweep_hosts(targets, ports)
            host_probes: list[tuple[str, str, list[int]]] = []
            label_by_host: dict[str, dict[int, str]] = {}
            ip_by_host: dict[str, str] = {}
            provider_name_by_host: dict[str, str | None] = {}
            for host, ip in targets:
                if self._stop.is_set():
                    return
                provider = provider_by_host.get(host)
                open_ports = swept.get(host, [])
                if not open_ports:
                    self.bus.bump("filtered_no_web")
                    self.bus.filtered(
                        f"Filtered out ://{host} - no port of the "
                        f"{len(ports)}-port matrix responded (No Web Interface)",
                        host=host,
                        ip=ip,
                    )
                    self.result.filtered[host] = "no open port"
                    continue
                self.result.open_ports[host] = open_ports
                bus.emit(
                    f"{host} ({ip}) — {len(open_ports)} open port(s): "
                    + ", ".join(
                        f"{p.port}" + (f" {p.service}" if p.service else "")
                        for p in open_ports
                    ),
                    "info",
                    "port",
                    host=host,
                    ip=ip,
                )
                if self._delay[1] > 0:
                    await self._sleep_delay()
                label_by_host[host] = {p.port: p.label for p in open_ports}
                ip_by_host[host] = ip
                provider_name_by_host[host] = provider.name if provider else None
                host_probes.append((host, ip, [p.port for p in open_ports]))

            # Fan out HTTP verification across every host of the batch at once,
            # instead of awaiting each host's probes in turn.  The prober's own
            # semaphore still bounds the in-flight requests.
            async def probe_host(host: str, ip: str, ports: list[int]):
                return host, await self._probe.probe_multi(host, ip, ports)

            gathered = await asyncio.gather(
                *(probe_host(host, ip, ports) for host, ip, ports in host_probes),
                return_exceptions=True,
            )
            for entry in gathered:
                if self._stop.is_set():
                    return
                if isinstance(entry, BaseException):
                    continue
                host, probes = entry
                ip = ip_by_host[host]
                label_map = label_by_host.get(host, {})
                provider_name = provider_name_by_host.get(host)
                interfaces = [p for p in probes if p.ok]
                if not interfaces:
                    # Only bounces answered: record them, promote later if the
                    # host turns out to have no real interface anywhere.
                    self.bus.bump("filtered_no_web")
                    self.result.filtered[host] = "redirect only"
                for probe in probes:
                    await self._handle_probe(
                        probe, ip, label_map, provider_name=provider_name
                    )
        finally:
            bus.bump_clamped("active_tasks", -1, minimum=0)

    async def _handle_probe(
        self,
        probe: WebProbeResult,
        ip: str,
        label_map: dict[int, str],
        provider_name: str | None = None,
    ) -> None:
        """Turn one verified probe into a finding, a bounce or a filter event."""
        if self._is_wildcard_soft_404(probe):
            self.bus.bump("wildcard_filtered")
            self.bus.filtered(
                f"Filtered out ://{probe.host} - Port {probe.port} serves the "
                f"wildcard signature (soft-404, false positive)",
                host=probe.host,
                port=probe.port,
                ip=ip,
            )
            self.result.filtered[probe.host] = "wildcard soft-404"
            return
        finding = self._make_finding(probe, ip, label_map, provider_name=provider_name)
        if probe.kind == "redirect":
            self.result.redirects.append(finding)
            return
        self.result.findings.append(finding)
        self._jsonl_emit(finding)
        self.bus.bump("findings")
        if self.config.fingerprint_findings:
            await self._fingerprint_finding(finding, probe)
        self.bus.probe(
            f"WEB INTERFACE — {finding.url} · {finding.status} · "
            f"{finding.title or 'no title'}"
            + (f" · [{finding.kind}]" if finding.kind != "interface" else ""),
            host=probe.host,
            port=finding.port,
            ip=ip,
            url=finding.url,
            status=finding.status,
            title=finding.title,
            kind=finding.kind,
        )
        if self.on_finding is not None:
            maybe = self.on_finding(finding)
            if asyncio.iscoroutine(maybe):
                await maybe

    async def _scan_host(self, resolved: DNSResult) -> None:
        """Compatibility shim — sweeps a single host."""
        await self._sweep_batch([resolved], list(self.config.ports.keys()))

    def _make_finding(
        self,
        probe: WebProbeResult,
        ip: str,
        label_map: dict[int, str],
        provider_name: str | None = None,
    ) -> Finding:
        sources: list[str] = []
        if probe.host in self.result.osint_hosts:
            sources.append("osint")
        if probe.host in self.result.brute_hosts:
            sources.append("brute")
        if not sources:
            sources.append("apex" if probe.host == self.config.domain else "unknown")
        return Finding(
            subdomain=probe.host,
            ip=probe.ip or ip or "",
            port=probe.port,
            scheme=probe.scheme,
            url=probe.url,
            status=probe.status,
            title=probe.title,
            server=probe.server,
            tls=probe.tls,
            tls_version=probe.tls_version,
            content_type=probe.content_type,
            content_length=probe.content_length,
            declared_length=probe.declared_length,
            redirect_chain=list(probe.redirect_chain),
            port_label=label_map.get(probe.port, describe(probe.port)),
            sources=sources,
            fingerprint=probe.fingerprint,
            kind=probe.kind,
            initial_status=probe.initial_status,
            final_url=probe.final_url,
            latency_ms=probe.latency_ms,
            provider=provider_name,
        )

    # -- introspection ----------------------------------------------------- #
    def describe_plan(self) -> list[str]:
        """The *effective* plan — what this run will really do, not what the
        profile alone would do (an explicit wordlist/matrix/rate wins)."""
        from .ports import describe_matrix

        cfg = self.config
        profile = self.profile
        try:
            from .wordlists import resolve_wordlist

            spec = resolve_wordlist(cfg.wordlist)
            labels = f"{profile.wordlist_size:,} of {spec.name}" if profile.brute else "n/a"
        except Exception:  # pragma: no cover - unknown registry name
            labels = f"{profile.wordlist_size:,}" if profile.brute else "n/a"
        matrix = describe_matrix(cfg.ports)
        return [
            f"target            : {cfg.domain}",
            f"profile           : {profile.id}. {profile.name}",
            f"packets           : {profile.packet_profile}",
            f"rate limits       : dns {cfg.dns_rate_limit:g}/s"
            + (f" ({cfg.dns_rate_per_server:g}/node)" if cfg.dns_rate_per_server else "")
            + (f" · ports {cfg.port_rate_limit:g}/s" if cfg.port_rate_limit else "")
            + (f" ({cfg.port_rate_per_host:g}/host)" if cfg.port_rate_per_host else ""),
            f"osint sources     : {', '.join(profile.osint_sources) if profile.passive else 'disabled'}",
            f"wordlist          : {labels}",
            f"port matrix       : {matrix} ({len(cfg.ports)} ports)",
            f"dns resolvers     : {len(cfg.resolver_pool)} anonymous (no Google/Cloudflare)",
            f"dns concurrency   : {cfg.dns_concurrency}",
            f"port concurrency  : {cfg.port_concurrency}",
            f"http concurrency  : {cfg.http_concurrency}",
        f"dns timeout       : {cfg.dns_timeout}s (per name: "
        f"{cfg.dns_name_deadline:g}s budget, {cfg.dns_concurrency} in flight)",
            f"tcp timeout       : {cfg.tcp_timeout}s",
            f"http timeout      : {cfg.http_timeout}s",
            f"wildcard check    : {'enabled' if profile.wildcard_check else 'disabled'}",
            f"stealth delay     : {cfg.stealth_delay[0]:.2f}-{cfg.stealth_delay[1]:.2f}s",
            f"carry over        : {'merge previous report' if cfg.carry_over else 'off'}",
            f"enrichment        : geo {'on' if cfg.geoip else 'off'} · dns-intel "
            f"{'on' if cfg.dns_intel else 'off'} · ptr {'on' if cfg.reverse_dns else 'off'}"
            f" · mining {'on' if cfg.web_mining else 'off'}",
        ]
