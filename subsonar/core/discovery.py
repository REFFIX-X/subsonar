"""Active discovery helpers: permutations, SAN harvesting and CNAME chasing.

These turn a small seeded set of known hostnames into a much larger candidate
pool for free — no API, no key, just local computation plus one TLS handshake.

* :func:`permute_hostnames` mutates known names the way real operations teams do
  (``admin`` → ``admin-dev``, ``dev-admin``, ``admin2``, ``admin.staging``).
* :func:`harvest_san` reads the apex certificate's Subject Alternative Names —
  organisations routinely list internal hostnames there without realising.
* :func:`chase_cnames` walks CNAME chains and reports provider hints, which
  exposes sibling naming conventions (``acme.github.io`` ⇒ ``*.github.io``).
"""

from __future__ import annotations

import asyncio
import re
import ssl
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from .events import BUS, EventBus
from .osint import is_valid_hostname
from .providers import cname_providers, provider_name

# --------------------------------------------------------------------------- #
# Permutation vocabulary
# --------------------------------------------------------------------------- #

#: Suffixes appended to a known label.
SUFFIXES: tuple[str, ...] = (
    "dev", "development", "test", "testing", "qa", "uat", "stage", "staging",
    "stg", "prod", "production", "preprod", "pre", "beta", "alpha", "canary",
    "demo", "sandbox", "lab", "local", "old", "legacy", "new", "next",
    "internal", "intranet", "private", "public", "ext", "external", "partner",
    "vendor", "admin", "manage", "mgmt", "panel", "portal", "app", "apps",
    "api", "api2", "apiv2", "v2", "v3", "web", "web1", "web2", "www", "www2",
    "mail", "smtp", "mx", "ns", "ns1", "ns2", "dns", "cdn", "static", "assets",
    "img", "media", "files", "docs", "wiki", "git", "svn", "ci", "cd", "build",
    "jenkins", "gitlab", "grafana", "kibana", "auth", "sso", "login", "id",
    "db", "sql", "mysql", "postgres", "mongo", "redis", "cache", "queue",
    "backup", "bak", "archive", "monitor", "status", "health", "metrics",
)

#: Prefixes prepended to a known label.
PREFIXES: tuple[str, ...] = (
    "dev", "test", "qa", "stage", "staging", "prod", "preprod", "beta",
    "demo", "old", "new", "internal", "ext", "partner", "admin", "api",
    "app", "web", "my", "my-", "the", "go", "get", "try", "use", "eu", "us",
    "uk", "dk", "de", "us-east", "us-west", "eu-west", "us-east-1",
)

#: Region / environment shorthands used as separators or suffixes.
REGIONS: tuple[str, ...] = (
    "eu", "us", "uk", "dk", "de", "fr", "nl", "se", "no", "fi", "es", "it",
    "us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1",
)

NUMERIC_SUFFIXES: tuple[str, ...] = tuple(str(n) for n in range(1, 11))

#: Providers inferred from a CNAME target — used as a hint, never as a filter.
#:
#: Derived from :mod:`subsonar.core.providers`, which keeps the table ordered
#: most-specific-first and validates that ordering at import time (a broad
#: suffix listed before a narrow one used to shadow it, so ``elb.amazonaws.com``
#: could never match).
CNAME_PROVIDERS: tuple[tuple[str, str], ...] = cname_providers()

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?$")
_DOTTED_RE = re.compile(r"^[a-z0-9._-]+$")


@dataclass(slots=True)
class DiscoveryStats:
    permutations: int = 0
    san_hosts: int = 0
    cname_hops: int = 0
    providers: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "permutations": self.permutations,
            "san_hosts": self.san_hosts,
            "cname_hops": self.cname_hops,
            "providers": dict(self.providers),
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- #
# Permutations
# --------------------------------------------------------------------------- #


def permute_labels(
    labels: Iterable[str],
    *,
    depth: int = 1,
    include_numbers: bool = True,
    include_regions: bool = True,
    limit: int = 20_000,
) -> list[str]:
    """Mutate a set of single labels into a larger candidate label set.

    ``depth=2`` feeds the first round's output back in, which is how names like
    ``dev-api-admin`` appear.  Output is de-duplicated and order-stable.
    """
    seeds = [label.strip().lower() for label in labels if label.strip()]
    seen: set[str] = set(seeds)
    frontier = list(seeds)
    produced: list[str] = []
    modifiers = list(SUFFIXES)
    if include_regions:
        modifiers += [f"{r}" for r in REGIONS]

    for _ in range(max(1, depth)):
        new_frontier: list[str] = []
        for label in frontier:
            if len(produced) >= limit:
                break
            candidates: list[str] = []
            for suffix in modifiers:
                candidates.append(f"{label}-{suffix}")
                candidates.append(f"{label}{suffix}")
                candidates.append(f"{suffix}-{label}")
            for prefix in PREFIXES:
                candidates.append(f"{prefix}-{label}")
                candidates.append(f"{prefix}{label}")
            if include_numbers:
                for number in NUMERIC_SUFFIXES:
                    candidates.append(f"{label}{number}")
                    candidates.append(f"{label}-{number}")
            for candidate in candidates:
                if candidate in seen or len(candidate) > 63:
                    continue
                if not _LABEL_RE.match(candidate):
                    continue
                seen.add(candidate)
                produced.append(candidate)
                new_frontier.append(candidate)
                if len(produced) >= limit:
                    break
            if len(produced) >= limit:
                break
        frontier = new_frontier
        if not frontier:
            break
    return produced[:limit]


def permute_hostnames(
    hosts: Iterable[str],
    domain: str,
    *,
    depth: int = 1,
    include_numbers: bool = True,
    include_regions: bool = True,
    limit: int = 20_000,
) -> list[str]:
    """Expand known FQDNs into new in-scope FQDN candidates.

    Known hostnames frequently use several labels (``api.dev.example.com``), so
    both the full prefix and its first label are used as seeds.
    """
    domain = domain.strip().lower().rstrip(".")
    labels: list[str] = []
    for host in hosts:
        host = host.strip().lower().rstrip(".")
        if not host:
            continue
        if host.endswith("." + domain):
            prefix = host[: -(len(domain) + 1)]
        elif host == domain:
            continue
        else:
            continue
        if not prefix or not _DOTTED_RE.match(prefix):
            continue
        labels.append(prefix)
        first = prefix.split(".")[0]
        if first != prefix and _LABEL_RE.match(first):
            labels.append(first)

    unique_labels = list(dict.fromkeys(labels))
    mutations = permute_labels(
        unique_labels,
        depth=depth,
        include_numbers=include_numbers,
        include_regions=include_regions,
        limit=limit,
    )
    out: list[str] = []
    seen: set[str] = set()
    for mutation in mutations:
        host = f"{mutation}.{domain}"
        if host in seen or not is_valid_hostname(host, domain):
            continue
        seen.add(host)
        out.append(host)
    return out


# --------------------------------------------------------------------------- #
# TLS SAN harvesting
# --------------------------------------------------------------------------- #


def extract_sans_from_der(der: bytes) -> list[str]:
    """Pull dNSName SANs out of a DER certificate."""
    from .scanner import parse_der_certificate

    _cn, sans = parse_der_certificate(der)
    return sans


async def harvest_san(
    domain: str,
    *,
    ports: Sequence[int] = (443, 8443, 9443, 10443),
    timeout: float = 4.0,
    bus: EventBus | None = None,
    resolver: Any = None,
) -> list[str]:
    """Read the TLS certificate at *domain* and return in-scope SAN hostnames.

    This is passive-plus-one-handshake discovery: the certificate is served to
    anyone who connects.  The connection is made to an address resolved through
    the **anonymous** resolver (*resolver*), because letting the OS resolver
    look the hostname up would leak the target to the system/ISP DNS — the one
    thing subsonar promises never to do.  Without a resolver the harvest is
    skipped instead of falling back to ``getaddrinfo``.  Never raises.
    """
    bus = bus or BUS
    bus.emit(
        f"Harvesting TLS certificate SANs for ://{domain} (ports "
        f"{', '.join(str(p) for p in ports)})",
        "info",
        "osint",
        host=domain,
    )
    found: list[str] = []
    seen: set[str] = set()

    async def anonymous_lookup(host: str) -> str | None:
        """Resolve *host* through the anonymous pool (never the OS resolver)."""
        if resolver is None:
            return None
        try:
            answer = await resolver.resolve(host, log=False)
        except asyncio.CancelledError:
            raise
        except Exception:
            return None
        return getattr(answer, "ip", None) if getattr(answer, "ok", False) else None

    async def probe(host: str, ip: str, port: int) -> None:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        writer = None
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=ip, port=port, ssl=context, server_hostname=host
                ),
                timeout=timeout,
            )
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                return
            der = None
            try:
                der = ssl_object.getpeercert(binary_form=True)
            except Exception:
                der = None
            if not der:
                return
            new_here = 0
            for san in extract_sans_from_der(der):
                san_host = san.strip().lower().lstrip("*.").rstrip(".")
                if not san_host or san_host in seen:
                    continue
                if not is_valid_hostname(san_host, domain):
                    continue
                seen.add(san_host)
                found.append(san_host)
                new_here += 1
            bus.emit(
                f"Certificate on ://{host}:{port} lists {new_here} new in-scope "
                f"SAN hostname(s) ({len(found)} so far)",
                "debug",
                "osint",
                host=host,
                port=port,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

    targets: list[str] = [domain]
    if domain.count(".") >= 1 and not domain.startswith("www."):
        targets.append(f"www.{domain}")
    skipped = 0
    for host in targets:
        # One anonymous lookup per host, reused for every port.
        address = await anonymous_lookup(host)
        if address is None:
            skipped += 1
            continue
        for port in ports:
            await probe(host, address, port)
    if skipped:
        bus.emit(
            f"No anonymous address for {skipped} target(s) — SAN harvesting "
            f"skipped those (the OS resolver is never used)",
            "warn",
            "osint",
            host=domain,
        )
    if found:
        bus.emit(
            f"SAN harvesting found {len(found)} in-scope hostname(s): "
            + ", ".join(found[:8])
            + (" …" if len(found) > 8 else ""),
            "success",
            "osint",
            host=domain,
            count=len(found),
        )
    else:
        bus.emit(
            f"SAN harvesting found no additional hostnames for {domain}",
            "debug",
            "osint",
            host=domain,
        )
    return found


# --------------------------------------------------------------------------- #
# CNAME chasing
# --------------------------------------------------------------------------- #


def provider_for(target: str) -> str | None:
    """Map a CNAME target to a hosting provider, if it is a known one."""
    return provider_name(target)


@dataclass(slots=True)
class CNAMEChain:
    host: str
    chain: list[str] = field(default_factory=list)
    provider: str | None = None

    @property
    def terminal(self) -> str | None:
        return self.chain[-1] if self.chain else None


async def chase_cnames(
    hosts: Sequence[str],
    *,
    resolver: Any,
    max_hops: int = 5,
    bus: EventBus | None = None,
) -> list[CNAMEChain]:
    """Follow CNAME chains and report the provider behind each one."""
    bus = bus or BUS
    results: list[CNAMEChain] = []
    providers: dict[str, int] = {}
    for host in hosts:
        chain: list[str] = []
        current = host
        for _ in range(max_hops):
            try:
                result = await resolver.query_raw(current, 5, log=False)  # TYPE_CNAME
            except Exception:
                break
            if not result.cnames:
                break
            target = result.cnames[-1].rstrip(".")
            if target in chain or not target:
                break
            chain.append(target)
            next_result = await resolver.resolve(target, log=False)
            current = target
            if next_result.ok:
                break
        provider = provider_for(chain[-1]) if chain else None
        if provider:
            providers[provider] = providers.get(provider, 0) + 1
        results.append(CNAMEChain(host=host, chain=chain, provider=provider))
    if providers:
        bus.emit(
            "CNAME providers observed — "
            + ", ".join(f"{name}×{count}" for name, count in sorted(providers.items())),
            "info",
            "osint",
            providers=providers,
        )
    return results


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


async def expand_discovery(
    domain: str,
    known_hosts: Sequence[str],
    *,
    resolver: Any = None,
    bus: EventBus | None = None,
    depth: int = 1,
    san_ports: Sequence[int] = (443, 8443),
    permutation_limit: int = 10_000,
    enable_san: bool = True,
    enable_permutations: bool = True,
    enable_cnames: bool = True,
) -> tuple[list[str], DiscoveryStats]:
    """Run every active discovery technique and return ``(hosts, stats)``.

    The returned hosts are already scope-validated and de-duplicated against
    *known_hosts*; ordering puts SAN discoveries first (they are the highest
    confidence) followed by CNAME siblings and then permutations.
    """
    bus = bus or BUS
    stats = DiscoveryStats()
    known = {h.strip().lower().rstrip(".") for h in known_hosts}
    ordered: list[str] = []
    seen = set(known)

    def add(host: str) -> bool:
        host = host.strip().lower().rstrip(".")
        if not host or host in seen:
            return False
        if not is_valid_hostname(host, domain):
            return False
        seen.add(host)
        ordered.append(host)
        return True

    if enable_san:
        san_hosts = await harvest_san(
            domain, ports=san_ports, bus=bus, resolver=resolver
        )
        for host in san_hosts:
            if add(host):
                stats.san_hosts += 1

    if enable_cnames and resolver is not None:
        seeds = [domain, f"www.{domain}"] + list(known)[:25]
        try:
            chains = await chase_cnames(seeds, resolver=resolver, bus=bus)
            for chain in chains:
                stats.cname_hops += len(chain.chain)
                if chain.provider:
                    stats.providers[chain.provider] = (
                        stats.providers.get(chain.provider, 0) + 1
                    )
                for target in chain.chain:
                    # A sibling of the provider target is a plausible hostname.
                    if add(target):
                        stats.notes.append(f"cname target {target}")
        except Exception as exc:  # pragma: no cover - defensive
            bus.warn(f"CNAME chasing failed: {exc.__class__.__name__}: {exc}")

    if enable_permutations and (known or ordered):
        seeds = list(known) + ordered
        permutations = permute_hostnames(
            seeds, domain, depth=depth, limit=permutation_limit
        )
        for host in permutations:
            if add(host):
                stats.permutations += 1

    if stats.permutations or stats.san_hosts:
        bus.emit(
            f"Active discovery expanded the candidate pool — "
            f"{stats.san_hosts} SAN + {stats.permutations} permutation host(s)",
            "info",
            "osint",
            san=stats.san_hosts,
            permutations=stats.permutations,
        )
    return ordered, stats
