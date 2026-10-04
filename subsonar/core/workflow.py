"""Workflow features: config files, resumable scans, diffs and multi-domain runs.

* :class:`ScanSettings` — a TOML config file (``subsonar.toml``) merged with CLI
  overrides, so a long invocation can be reduced to a file.
* :func:`state_path_for` / :class:`ScanState` — a durable checkpoint after every
  phase, so an interrupted 20 000-label sweep can resume instead of restarting.
* :func:`diff_results` — what is new, changed or gone since the previous scan of
  the same target.  This is the feature that makes continuous recon usable.
* :func:`run_multi` — sequential multi-domain batch runs sharing one cache.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from .config import CACHE_DIR, PORT_MATRIX, OUTPUT_DIR, ScanConfig
from .ports import describe, parse_port_spec
from .profiles import PROFILE_BY_KEY, get_profile

try:  # pragma: no cover - Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

CONFIG_FILENAME = "subsonar.toml"
STATE_SCHEMA = 1


# --------------------------------------------------------------------------- #
# Configuration files
# --------------------------------------------------------------------------- #


@dataclass
class ScanSettings:
    """Declarative scan settings, loadable from TOML and overridable by CLI."""

    domains: list[str] = field(default_factory=list)
    profile: str = "3"
    ports: list[int] | None = None
    offline: bool = False
    output_dir: Path = OUTPUT_DIR
    cache_dir: Path = CACHE_DIR
    formats: list[str] = field(
        default_factory=lambda: ["json", "csv", "md", "html", "txt"]
    )
    dns_timeout: float | None = None
    #: Per-name DNS time budget across failover attempts (None = default).
    dns_deadline: float | None = None
    tcp_timeout: float | None = None
    tcp_fast_timeout: float | None = None
    http_timeout: float | None = None
    dns_concurrency: int | None = None
    port_concurrency: int | None = None
    http_concurrency: int | None = None
    host_batch: int | None = None
    verify_tls: bool = False
    wildcard_filter: bool = True
    adaptive_timeout: bool = True
    multiplex_dns: bool = True
    disk_cache: bool = True
    ipv6: bool = False
    #: Attempt a DNS zone transfer (opt-in; talks to the target's nameservers).
    axfr: bool = False
    confirm_resolvers: int = 0
    enable_san: bool = True
    enable_permutations: bool = True
    enable_cnames: bool = True
    #: Probe provider-hosted (Office 365, S3, Heroku, …) hosts anyway instead of
    #: skipping them (they live on shared third-party infrastructure).
    skip_provider_hosts: bool = True
    #: Brute-force wordlist registry name (``seclists-top1m``, ``ai-super``, …).
    wordlist: str | None = None
    #: Merge the newest report for the domain into the new run (default: on).
    carry_over: bool = True
    #: DNS queries/second cap (``None`` = let the profile decide, 0 = unlimited).
    dns_rate: float | None = None
    #: Per-nameserver queries/second cap.
    dns_rate_per_server: float | None = None
    #: Burst allowance for :attr:`dns_rate`.
    dns_rate_burst: float | None = None
    #: TCP connect rate cap (connects/second, ``None`` = profile default, 0 = off).
    port_rate: float | None = None
    #: Per-host connects/second cap.
    port_rate_per_host: float | None = None
    #: Burst allowance for :attr:`port_rate`.
    port_rate_burst: float | None = None
    #: Offline country/ASN enrichment from the free BGP/RIR dumps.
    geoip: bool = True
    #: Allow the one-off geo index download.
    geoip_download: bool = True
    #: Reverse-DNS (PTR) lookups for resolved addresses.
    reverse_dns: bool = True
    #: Apex DNS intelligence (MX/SPF/DMARC/CAA/DNSSEC/verification tokens).
    dns_intel: bool = True
    #: Mine robots.txt / sitemap.xml / security.txt / response headers for hosts.
    web_mining: bool = True
    #: Run template-style exposure checks (status-only, severity-labelled).
    template_checks: bool = True
    #: Stream findings to a live NDJSON (.jsonl) file as they are confirmed.
    jsonl: bool = False
    #: Named matrix (``core``, ``extended``, ``web``, ``audit``) or a spec string
    #: (``80,443,8000-8100``).  Overrides :attr:`ports` when set.
    port_matrix: str | None = None
    permutation_depth: int = 1
    wordlist_extra: list[str] = field(default_factory=list)
    #: Mutate brute-force labels with env/region/number affixes.
    wordlist_permutations: bool = False
    wordlist_permutation_limit: int = 50_000
    max_candidates: int | None = None

    # -- loading ----------------------------------------------------------- #
    @classmethod
    def load(cls, path: Path | str | None = None) -> "ScanSettings":
        """Load settings from TOML, falling back to an empty default set."""
        candidate = Path(path) if path else Path.cwd() / CONFIG_FILENAME
        if not candidate.is_file():
            return cls()
        if tomllib is None:  # pragma: no cover
            return cls()
        try:
            with open(candidate, "rb") as handle:
                data = tomllib.load(handle)
        except Exception:
            return cls()
        return cls.from_mapping(data)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "ScanSettings":
        scan = data.get("scan", data)
        settings = cls()
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        for key, value in {**data, **scan}.items():
            if key not in known or value is None:
                continue
            current = getattr(settings, key)
            if isinstance(current, Path):
                setattr(settings, key, Path(value))
            elif key == "domains" and isinstance(value, str):
                setattr(settings, key, [value])
            else:
                setattr(settings, key, value)
        return settings

    def to_mapping(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name in self.__dataclass_fields__:  # type: ignore[attr-defined]
            value = getattr(self, name)
            if isinstance(value, Path):
                out[name] = str(value)
            else:
                out[name] = value
        return out

    # -- config building --------------------------------------------------- #
    def build_config(self, domain: str, *, profile: Any = None) -> ScanConfig:
        """Create a :class:`ScanConfig` for one domain from these settings."""
        chosen = profile if profile is not None else self.resolve_profile()
        config = ScanConfig(
            domain=domain,
            profile_id=chosen.id,
            offline=self.offline,
            verify_tls=self.verify_tls,
            wildcard_filter=self.wildcard_filter,
            adaptive_timeout=self.adaptive_timeout,
            cache_dir=Path(self.cache_dir),
            output_dir=Path(self.output_dir),
        )
        if self.port_matrix:
            config.ports = parse_port_spec(self.port_matrix)
            config.ports_override = True
        elif self.ports:
            config.ports = {
                int(port): describe(int(port)) for port in self.ports
            }
            config.ports_override = True
        for attribute in (
            "dns_timeout", "tcp_timeout", "tcp_fast_timeout", "http_timeout",
            "dns_concurrency", "port_concurrency", "http_concurrency", "host_batch",
            "ipv6", "confirm_resolvers", "max_candidates",
        ):
            value = getattr(self, attribute)
            if value is not None:
                setattr(config, attribute, value)
        if any(
            getattr(self, name) is not None
            for name in ("dns_concurrency", "port_concurrency", "http_concurrency")
        ):
            # The values were written after construction, so __post_init__ could
            # not flag them; protect them from the profile.
            config.concurrency_override = True
        if self.dns_deadline is not None:
            config.dns_name_deadline = max(0.0, float(self.dns_deadline))
        # The discovery/accuracy switches are plain bools with defaults, so they
        # are copied explicitly rather than only when non-None.
        config.enable_san = self.enable_san
        config.enable_permutations = self.enable_permutations
        config.enable_cnames = self.enable_cnames
        config.enable_discovery = bool(
            self.enable_san or self.enable_permutations or self.enable_cnames
        )
        config.axfr = self.axfr
        config.multiplex_dns = self.multiplex_dns
        config.disk_cache = self.disk_cache
        config.adaptive_timeout = self.adaptive_timeout
        config.permutation_depth = self.permutation_depth
        config.skip_provider_hosts = self.skip_provider_hosts
        config.carry_over = self.carry_over
        config.geoip = self.geoip
        config.geoip_download = self.geoip_download
        config.reverse_dns = self.reverse_dns
        config.dns_intel = self.dns_intel
        config.web_mining = self.web_mining
        config.template_checks = self.template_checks
        config.jsonl = self.jsonl
        if self.dns_rate is not None:
            config.dns_rate_limit = max(0.0, float(self.dns_rate))
            config.dns_rate_override = True
        if self.dns_rate_per_server is not None:
            config.dns_rate_per_server = max(0.0, float(self.dns_rate_per_server))
            config.dns_rate_override = True
        if self.dns_rate_burst is not None:
            config.dns_rate_burst = max(0.0, float(self.dns_rate_burst))
        if self.port_rate is not None:
            config.port_rate_limit = max(0.0, float(self.port_rate))
            config.port_rate_override = True
        if self.port_rate_per_host is not None:
            config.port_rate_per_host = max(0.0, float(self.port_rate_per_host))
            config.port_rate_override = True
        if self.port_rate_burst is not None:
            config.port_rate_burst = max(0.0, float(self.port_rate_burst))
        if self.wordlist:
            config.wordlist = self.wordlist
        config.wordlist_permutations = self.wordlist_permutations
        config.wordlist_permutation_limit = self.wordlist_permutation_limit
        return config

    def resolve_profile(self) -> Any:
        key = str(self.profile).strip().lower()
        if key.isdigit():
            return get_profile(int(key))
        return PROFILE_BY_KEY.get(key) or get_profile(3)


def write_example_config(path: Path | str = CONFIG_FILENAME) -> Path:
    """Write a commented example config file."""
    target = Path(path)
    target.write_text(
        """# subsonar configuration — every value is optional.
# CLI flags override anything set here.

[scan]
domains = ["example.com"]
profile = "3"                 # 1-8 or a key: passive, light, medium, deep,
                              # full-postal, quick, infra, stealth
formats = ["json", "csv", "md", "html", "txt"]
offline = false

# --- performance ---------------------------------------------------------
host_batch = 32               # hosts swept together in one port-major batch
port_concurrency = 300        # simultaneous TCP connects
dns_concurrency = 400
http_concurrency = 60
tcp_fast_timeout = 0.45       # first-pass port timeout
tcp_timeout = 1.8             # retry timeout for responsive hosts
dns_timeout = 2.5             # per-attempt DNS timeout
# Total seconds one hostname may spend across all its failover attempts.  A brute
# list is mostly dead names, so without this the DNS phase is paced by timeouts
# (6 attempts x 2.5s = 15s per dead name) instead of by the rate limit.  0 = let
# every name use its whole attempt budget.
dns_deadline = 6.0
adaptive_timeout = true
multiplex_dns = true          # one UDP socket per resolver, many queries
disk_cache = true             # durable DNS answer cache across runs

# --- discovery -----------------------------------------------------------
enable_san = true             # harvest TLS certificate SANs (anonymous DNS)
enable_permutations = true    # mutate known hostnames into new candidates
enable_cnames = true          # chase CNAME chains and report providers
permutation_depth = 1         # 2 feeds the first round back in (much bigger)
# Third-party hosted hosts (Office 365 / Exchange Online, S3, Heroku, CDNs, …)
# are skipped entirely — they are somebody else's shared infrastructure, so a
# port sweep or HTTP probe against them says nothing about the target.  Set to
# false to scan them like any other host.
skip_provider_hosts = true

# Merge the newest report for the same domain into the next run.  With this on
# (the default) switching from a passive profile to a brute profile keeps every
# finding the first pass produced — results are added to, never cleared.
carry_over = true

# --- wordlist ------------------------------------------------------------
# Pick a brute-force list: seclists-top1m (default), seclists-5k, seclists-20k,
# bitquark, namelist, deepmagic, deepmagic-50k, fierce, shubs, jhaddix, ai-super.
# `python main.py wordlists` prints them all.  The profile still sizes the slice.
wordlist = "seclists-top1m"

# Mutate every brute-force label with env/region/number affixes (admin -> admin-dev,
# dev-admin, admin2, admin.staging, ...) for extra coverage on misconfigured naming.
wordlist_permutations = false
wordlist_permutation_limit = 50000

# --- politeness / rate limiting ------------------------------------------
# Concurrency bounds how many queries are in flight; the rate limit bounds
# how many leave the machine per second (token bucket, so short bursts are still
# allowed).  0 = unlimited.  Profiles supply sane defaults (e.g. medium brute:
# 250 DNS q/s with 50 per node, 600 connects/s with 60 per host); setting a value
# here overrides the profile.  The stealth profile is 25 q/s and 60 connects/s.
dns_rate = 0                  # queries/second across the whole resolver pool
dns_rate_per_server = 0       # queries/second against any single resolver
dns_rate_burst = 0            # burst size (0 = one second worth of tokens)
port_rate = 0                 # TCP connects/second across the whole sweep
port_rate_per_host = 0        # TCP connects/second against any single host
port_rate_burst = 0           # burst size (0 = one second worth of tokens)

# --- offline OSINT enrichment (no API key, nothing leaves this machine) ---
geoip = true                  # country flag + ASN + AS organisation per IP
geoip_download = true         # allow the one-off BGP/RIR dump download (~10 MB)
reverse_dns = true            # PTR records for resolved addresses
dns_intel = true              # MX/NS/SOA/SPF/DKIM/DMARC/CAA/DNSSEC + providers
web_mining = true             # robots.txt / sitemap.xml / security.txt / headers
template_checks = true        # status-only exposure checks (severity-labelled)
jsonl = false                 # stream every finding to a live .jsonl file

# --- accuracy ------------------------------------------------------------
wildcard_filter = true
confirm_resolvers = 0         # 2+ asks that many resolvers to agree on an IP
ipv6 = false                  # also resolve and scan AAAA records
verify_tls = false
""",
        encoding="utf-8",
    )
    return target


# --------------------------------------------------------------------------- #
# Resumable scan state
# --------------------------------------------------------------------------- #


def state_path_for(domain: str, cache_dir: Path | None = None) -> Path:
    safe = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in domain)
    return Path(cache_dir or CACHE_DIR) / f"state-{safe}.json"


class ScanState:
    """Checkpointed progress for one target.

    Written after every phase so an interrupted run resumes rather than
    restarting.  Stage flags are deliberately coarse — the goal is to avoid
    redoing the expensive DNS/port work, not to make the scan transactional.
    """

    def __init__(self, domain: str, path: Path | None = None) -> None:
        self.domain = domain
        self.path = Path(path) if path else state_path_for(domain)
        self.schema = STATE_SCHEMA
        self.started_at: float = time.time()
        self.updated_at: float = self.started_at
        self.profile: str = ""
        self.candidates: list[str] = []
        self.resolved: dict[str, dict[str, Any]] = {}
        self.open_ports: dict[str, list[int]] = {}
        self.completed: list[str] = []
        self.domain_stage: str = "started"
        self.extra: dict[str, Any] = {}

    # -- persistence ------------------------------------------------------- #
    @property
    def exists(self) -> bool:
        return self.path.is_file()

    def save(self) -> Path:
        self.updated_at = time.time()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": self.schema,
            "domain": self.domain,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "profile": self.profile,
            "stage": self.domain_stage,
            "completed": self.completed,
            "candidates": self.candidates,
            "resolved": self.resolved,
            "open_ports": self.open_ports,
            "extra": self.extra,
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(self.path)
        return self.path

    @classmethod
    def load(cls, domain: str, path: Path | None = None) -> "ScanState | None":
        target = Path(path) if path else state_path_for(domain)
        if not target.is_file():
            return None
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
        except Exception:
            return None
        if payload.get("schema") != STATE_SCHEMA:
            return None
        state = cls(domain, target)
        state.started_at = payload.get("started_at", time.time())
        state.updated_at = payload.get("updated_at", state.started_at)
        state.profile = payload.get("profile", "")
        state.domain_stage = payload.get("stage", "started")
        state.completed = list(payload.get("completed") or [])
        state.candidates = list(payload.get("candidates") or [])
        state.resolved = dict(payload.get("resolved") or {})
        state.open_ports = {
            host: list(ports) for host, ports in (payload.get("open_ports") or {}).items()
        }
        state.extra = dict(payload.get("extra") or {})
        return state

    def clear(self) -> None:
        """Delete the checkpoint and its (differently named) temp file."""
        for candidate in (self.path, self.path.with_suffix(".tmp")):
            try:
                candidate.unlink(missing_ok=True)
            except Exception:
                pass

    # -- stage bookkeeping -------------------------------------------------- #
    def mark(self, stage: str) -> None:
        if stage not in self.completed:
            self.completed.append(stage)
        self.domain_stage = stage
        self.save()

    @property
    def is_resumable(self) -> bool:
        return bool(self.completed) and self.domain_stage not in ("done", "finished")

    def pending_candidates(self) -> list[str]:
        """Candidates not yet resolved, preserving order."""
        done = set(self.resolved)
        return [host for host in self.candidates if host not in done]

    def age(self) -> float:
        return max(0.0, time.time() - self.updated_at)

    def summary(self) -> str:
        return (
            f"{self.domain}: stage={self.domain_stage} "
            f"candidates={len(self.candidates):,} resolved={len(self.resolved):,} "
            f"ports={sum(len(v) for v in self.open_ports.values()):,} "
            f"age={self.age() / 60:.1f}min"
        )


# --------------------------------------------------------------------------- #
# Diffing
# --------------------------------------------------------------------------- #


@dataclass
class ScanDiff:
    """What changed between two scans of the same target."""

    new_findings: list[dict[str, Any]] = field(default_factory=list)
    changed_findings: list[dict[str, Any]] = field(default_factory=list)
    lost_findings: list[dict[str, Any]] = field(default_factory=list)
    unchanged: int = 0
    previous_at: float | None = None
    current_at: float | None = None

    @property
    def has_changes(self) -> bool:
        return bool(self.new_findings or self.changed_findings or self.lost_findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "new": self.new_findings,
            "changed": self.changed_findings,
            "lost": self.lost_findings,
            "unchanged": self.unchanged,
            "previous_at": self.previous_at,
            "current_at": self.current_at,
        }

    def summary(self) -> str:
        return (
            f"{len(self.new_findings)} new, {len(self.changed_findings)} changed, "
            f"{len(self.lost_findings)} gone, {self.unchanged} unchanged"
        )


def _finding_key(finding: dict[str, Any]) -> tuple[str, int]:
    return (str(finding.get("subdomain", "")).lower(), int(finding.get("port") or 0))


def _finding_signature(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        finding.get("status"),
        (finding.get("title") or "").strip(),
        finding.get("server") or "",
        finding.get("scheme") or "",
    )


def diff_results(previous: dict[str, Any] | None, current: dict[str, Any]) -> ScanDiff:
    """Compare two ``ScanResult.to_dict()`` payloads."""
    diff = ScanDiff(
        previous_at=(previous or {}).get("finished_at"),
        current_at=current.get("finished_at"),
    )
    old = {_finding_key(f): f for f in (previous or {}).get("findings", [])}
    new = {_finding_key(f): f for f in current.get("findings", [])}
    for key, finding in new.items():
        if key not in old:
            diff.new_findings.append(finding)
        elif _finding_signature(old[key]) != _finding_signature(finding):
            diff.changed_findings.append(
                {
                    "before": old[key],
                    "after": finding,
                    "changed": [
                        name
                        for name in ("status", "title", "server", "scheme")
                        if old[key].get(name) != finding.get(name)
                    ],
                }
            )
        else:
            diff.unchanged += 1
    for key, finding in old.items():
        if key not in new:
            diff.lost_findings.append(finding)
    return diff


def latest_report(domain: str, output_dir: Path | None = None) -> Path | None:
    """Newest JSON report for *domain*, if any."""
    directory = Path(output_dir or OUTPUT_DIR)
    if not directory.is_dir():
        return None
    candidates = sorted(
        directory.glob(f"subsonar_{domain}_*.json"),
        key=lambda path: path.stat().st_mtime,
    )
    return candidates[-1] if candidates else None


def load_previous_report(domain: str, output_dir: Path | None = None) -> dict[str, Any] | None:
    path = latest_report(domain, output_dir)
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_baseline(
    domain: str, payload: dict[str, Any], cache_dir: Path | None = None
) -> Path:
    """Store the current finding set as the baseline for future diffs."""
    directory = Path(cache_dir or CACHE_DIR)
    directory.mkdir(parents=True, exist_ok=True)
    safe = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in domain)
    path = directory / f"baseline-{safe}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def load_baseline(domain: str, cache_dir: Path | None = None) -> dict[str, Any] | None:
    directory = Path(cache_dir or CACHE_DIR)
    safe = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in domain)
    path = directory / f"baseline-{safe}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def render_diff_markdown(domain: str, diff: ScanDiff) -> str:
    lines = [f"# subsonar diff — {domain}", "", diff.summary(), ""]
    if diff.new_findings:
        lines.append("## New")
        lines.append("")
        lines.append("| Subdomain | Port | Status | Title | URL |")
        lines.append("| --- | --- | --- | --- | --- |")
        for finding in diff.new_findings:
            lines.append(
                f"| `{finding.get('subdomain')}` | {finding.get('port')} | "
                f"{finding.get('status')} | {finding.get('title') or ''} | "
                f"[{finding.get('url')}]({finding.get('url')}) |"
            )
        lines.append("")
    if diff.changed_findings:
        lines.append("## Changed")
        lines.append("")
        for entry in diff.changed_findings:
            before, after = entry["before"], entry["after"]
            lines.append(
                f"- `{after.get('subdomain')}:{after.get('port')}` "
                f"({', '.join(entry['changed'])}): "
                f"{before.get('status')}/{before.get('title') or '-'} → "
                f"{after.get('status')}/{after.get('title') or '-'}"
            )
        lines.append("")
    if diff.lost_findings:
        lines.append("## Gone")
        lines.append("")
        for finding in diff.lost_findings:
            lines.append(
                f"- `{finding.get('subdomain')}:{finding.get('port')}` "
                f"({finding.get('status')}, {finding.get('title') or '-'})"
            )
        lines.append("")
    if not diff.has_changes:
        lines.append("No changes since the previous scan.")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Multi-domain runs
# --------------------------------------------------------------------------- #


async def run_multi(
    domains: Sequence[str],
    settings: ScanSettings,
    *,
    runner: Callable[[ScanConfig, Any], Any],
    on_result: Callable[[str, Any], Any] | None = None,
    bus: Any = None,
) -> list[tuple[str, Any]]:
    """Run several domains sequentially, sharing the resolver pool and cache.

    Sequential on purpose: running several targets at once multiplies the
    packet rate against unrelated infrastructure, which is exactly the kind of
    collateral traffic a scanner should avoid.
    """
    profile = settings.resolve_profile()
    results: list[tuple[str, Any]] = []
    for index, domain in enumerate(domains, start=1):
        if bus is not None:
            bus.phase(
                f"Multi-domain run {index}/{len(domains)} — starting {domain}"
            )
        config = settings.build_config(domain, profile=profile)
        try:
            result = await runner(config, profile)
        except Exception as exc:  # noqa: BLE001 - one bad target must not stop the batch
            if bus is not None:
                bus.error(
                    f"Target {domain} failed: {exc.__class__.__name__}: {exc}"
                )
            results.append((domain, None))
            continue
        results.append((domain, result))
        if on_result is not None:
            maybe = on_result(domain, result)
            if hasattr(maybe, "__await__"):
                await maybe
    return results
