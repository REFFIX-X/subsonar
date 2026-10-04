"""subsonar — command line entry point.

Examples
--------
Interactive Textual UI::

    python main.py

Direct scan with the headless console::

    python main.py scan example.com --profile 3

Web dashboard (Streamlit)::

    python main.py web --domain example.com

Environment self-test (no external traffic)::

    python main.py selftest
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Sequence

# Allow ``python main.py`` from a source checkout without installation.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from subsonar import __version__  # noqa: E402
from subsonar.core.config import (  # noqa: E402
    CACHE_DIR,
    DNS_RESOLVER_POOL,
    FORBIDDEN_DNS_SERVERS,
    ScanConfig,
)
from subsonar.core.events import BUS  # noqa: E402
from subsonar.core.profiles import PROFILE_BY_ID, render_profile_table  # noqa: E402
from subsonar.core.theme import Palette, banner_lines  # noqa: E402
from subsonar.core.workflow import (  # noqa: E402
    CONFIG_FILENAME,
    ScanSettings,
    ScanState,
    diff_results,
    load_baseline,
    load_previous_report,
    render_diff_markdown,
    save_baseline,
    write_example_config,
)
from subsonar.reporters import write_reports  # noqa: E402

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NO_FINDINGS = 2
EXIT_INTERRUPTED = 130


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subsonar",
        description=(
            "subsonar — ultra-fast asynchronous subdomain & web-interface scanner "
            "with anonymous DNS resolution and a Monokai Pro interface."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "profiles:\n" + render_profile_table() + "\n\n"
            "examples:\n"
            "  python main.py                          # interactive TUI\n"
            "  python main.py scan example.com -p 3    # headless medium brute\n"
            "  python main.py scan example.com -p 1 --formats json,csv,html\n"
            "  python main.py web                      # streamlit dashboard\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"subsonar {__version__}")

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="run a scan in the headless console")
    _add_common(scan)
    scan.add_argument(
        "--domains",
        default=None,
        help="comma-separated list of additional domains to scan sequentially",
    )
    scan.add_argument(
        "--debug-log", action="store_true", help="include debug/trace events in the log"
    )
    scan.add_argument(
        "--formats",
        default="json,csv,md,html,txt",
        help="comma separated report formats (default: all)",
    )
    scan.add_argument(
        "--no-reports", action="store_true", help="do not write report files"
    )

    tui = sub.add_parser("tui", help="launch the interactive Textual interface")
    tui.add_argument("domain", nargs="?", help="target domain (optional)")
    _add_common(tui, include_domain=False)
    tui.add_argument("--quiet", action="store_true", help="hide debug/filter events at start")

    web = sub.add_parser("web", help="launch the Streamlit web dashboard")
    web.add_argument("domain", nargs="?", help="target domain (optional)")
    _add_common(web, include_domain=False)
    web.add_argument("--port", type=int, default=8501, help="dashboard port")
    web.add_argument(
        "--headless", action="store_true", help="do not open a browser window"
    )

    profiles = sub.add_parser("profiles", help="list the 8 scan profiles")
    profiles.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    wordlists = sub.add_parser("wordlists", help="list the brute-force wordlists")
    wordlists.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    geoip = sub.add_parser(
        "geoip", help="offline country/ASN index (free BGP + RIR data, no API key)"
    )
    geoip.add_argument("--build", action="store_true", help="download and (re)build")
    geoip.add_argument("--refresh", action="store_true", help="rebuild even if fresh")
    geoip.add_argument("--stats", action="store_true", help="show index statistics")
    geoip.add_argument("--lookup", metavar="IP", default=None, help="describe one address")
    geoip.add_argument("--cache-dir", default=None, help="cache directory override")
    geoip.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    selftest = sub.add_parser(
        "selftest", help="verify the engine end-to-end without external traffic"
    )
    selftest.add_argument("--json", action="store_true", help="emit JSON results")

    sub.add_parser("init", help="write an example subsonar.toml config file")

    diff = sub.add_parser(
        "diff", help="compare the newest report for a domain with its baseline"
    )
    diff.add_argument("domain", help="target domain")
    diff.add_argument(
        "--set-baseline",
        action="store_true",
        help="record the newest report as the new baseline and exit",
    )
    diff.add_argument("--output", default=None, help="report directory to read from")
    diff.add_argument("--write", default=None, help="write the diff as markdown here")
    diff.add_argument("--json", action="store_true", help="emit the diff as JSON")

    resume = sub.add_parser("resume", help="show or clear saved scan state")
    resume.add_argument("domain", nargs="?", help="target domain")
    resume.add_argument("--all", action="store_true", help="list every saved state")
    resume.add_argument("--clear", action="store_true", help="delete saved state")

    return parser


def _add_common(parser: argparse.ArgumentParser, include_domain: bool = True) -> None:
    if include_domain:
        parser.add_argument("domain", help="target domain, e.g. example.com")
    parser.add_argument(
        "-p",
        "--profile",
        default=None,
        help="scan profile 1-8 or key (default: 3 = Medium Brute)",
    )
    parser.add_argument(
        "--config",
        default=None,
        help=f"TOML config file (default: ./{CONFIG_FILENAME} when present)",
    )
    parser.add_argument(
        "--dns-timeout", type=float, default=None, help="DNS timeout in seconds"
    )
    parser.add_argument(
        "--dns-deadline", type=float, default=None, metavar="SECONDS",
        help=(
            "total seconds one hostname may spend across failover attempts "
            "(default 6.0, 0 = unlimited).  Keeps a mostly-NXDOMAIN brute list "
            "from being paced by DNS timeouts instead of the rate limit"
        ),
    )
    parser.add_argument(
        "--tcp-timeout", type=float, default=None, help="TCP connect timeout in seconds"
    )
    parser.add_argument(
        "--tcp-fast-timeout",
        type=float,
        default=None,
        help="first-pass port timeout (default 0.45s; timeouts are retried slowly)",
    )
    parser.add_argument(
        "--http-timeout", type=float, default=None, help="HTTP timeout in seconds"
    )
    parser.add_argument("--dns-concurrency", type=int, default=None)
    parser.add_argument("--port-concurrency", type=int, default=None)
    parser.add_argument("--http-concurrency", type=int, default=None)
    parser.add_argument(
        "--host-batch", type=int, default=None,
        help="hosts swept together in one port-major batch (default 32)",
    )
    parser.add_argument(
        "--ports", default=None, metavar="SPEC",
        help=(
            "override the port matrix: a name (core, extended, web, audit), a "
            "list (80,443,8443) or ranges (8000-8100).  Default: the profile's "
            "matrix (Top-50 core)"
        ),
    )
    parser.add_argument(
        "--port-matrix", default=None, metavar="NAME",
        choices=("core", "extended", "web", "audit"),
        help=(
            "named port matrix — 'extended' probes ~170 web/admin/dev ports "
            "instead of the core 50"
        ),
    )
    parser.add_argument(
        "--max-candidates", type=int, default=None,
        help="cap the candidate pool (safety valve for permutation-heavy runs)",
    )
    parser.add_argument(
        "--wordlist", default=None, metavar="NAME",
        help=(
            "brute-force wordlist from the registry (default: seclists-top1m).  "
            "See `python main.py wordlists` — e.g. ai-super, bitquark, namelist, "
            "shubs, jhaddix, seclists-20k"
        ),
    )
    parser.add_argument(
        "--permute-wordlist", action="store_true",
        help=(
            "mutate every brute-force label with env/region/number affixes "
            "(admin → admin-dev, dev-admin, admin2, admin.staging, …)"
        ),
    )
    parser.add_argument(
        "--wordlist-permutation-limit", type=int, default=None, metavar="N",
        help="cap the extra labels the wordlist mutation pass may produce (50k)",
    )
    parser.add_argument(
        "--dns-rate", type=float, default=None, metavar="QPS",
        help=(
            "DNS query rate limit in queries/second across the whole resolver "
            "pool (0 = unlimited).  The stealth profile defaults to 25 q/s"
        ),
    )
    parser.add_argument(
        "--dns-rate-per-server", type=float, default=None, metavar="QPS",
        help="per-resolver query rate limit (0 = unlimited; stealth defaults to 8)",
    )
    parser.add_argument(
        "--dns-rate-burst", type=float, default=None, metavar="N",
        help="burst allowance for --dns-rate (default: one second worth)",
    )
    parser.add_argument(
        "--port-rate", type=float, default=None, metavar="CPS",
        help=(
            "TCP connect rate limit in connects/second for the port sweep "
            "(0 = unlimited).  Profiles default to 400-800/s (stealth: 60/s)"
        ),
    )
    parser.add_argument(
        "--port-rate-per-host", type=float, default=None, metavar="CPS",
        help="per-host connects/second cap (stealth defaults to 10)",
    )
    parser.add_argument(
        "--port-rate-burst", type=float, default=None, metavar="N",
        help="burst allowance for --port-rate (default: one second worth)",
    )
    parser.add_argument(
        "--no-geo", action="store_true",
        help=(
            "skip the offline country/ASN enrichment (no BGP dump download, no "
            "flags/ASN next to resolved IPs)"
        ),
    )
    parser.add_argument(
        "--no-geo-download", action="store_true",
        help="use an existing geo index only, never download the free dumps",
    )
    parser.add_argument(
        "--no-reverse-dns", action="store_true",
        help="skip the PTR lookups for resolved addresses",
    )
    parser.add_argument(
        "--no-dns-intel", action="store_true",
        help="skip the apex MX/SPF/DKIM/DMARC/CAA/DNSSEC intelligence",
    )
    parser.add_argument(
        "--no-mining", action="store_true",
        help="skip mining robots.txt/sitemap.xml/security.txt/headers for hosts",
    )
    parser.add_argument(
        "--no-template-checks", action="store_true",
        help="skip the template-style exposure checks (/.env, /.git/config, …)",
    )
    parser.add_argument(
        "--jsonl", action="store_true",
        help="stream every confirmed finding to a live .jsonl file",
    )
    parser.add_argument(
        "--no-carry-over", action="store_true",
        help=(
            "start from an empty result set instead of merging the previous "
            "report of the same domain (default: merge, never clear)"
        ),
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="never touch the network for wordlists/OSINT (cache only)",
    )
    parser.add_argument("--output", default=None, help="report output directory")
    parser.add_argument(
        "--no-adaptive-timeout", action="store_true",
        help="use one flat TCP timeout instead of the fast-then-slow strategy",
    )
    parser.add_argument(
        "--no-multiplex-dns", action="store_true",
        help="open a fresh UDP socket per DNS query (slower, for troubleshooting)",
    )
    parser.add_argument(
        "--no-disk-cache", action="store_true",
        help="do not use the durable cross-run DNS answer cache",
    )
    parser.add_argument(
        "--ipv6", action="store_true",
        help="also resolve AAAA records and port-scan IPv6 addresses",
    )
    parser.add_argument(
        "--confirm-resolvers", type=int, default=None, metavar="N",
        help="require N independent resolvers to agree on an address (2-3)",
    )
    parser.add_argument(
        "--no-discovery", action="store_true",
        help="disable SAN harvesting, CNAME chasing and permutations",
    )
    parser.add_argument("--no-san", action="store_true", help="skip TLS SAN harvesting")
    parser.add_argument(
        "--no-permutations", action="store_true", help="skip hostname permutations"
    )
    parser.add_argument("--no-cnames", action="store_true", help="skip CNAME chasing")
    parser.add_argument(
        "--permutation-depth", type=int, default=None,
        help="1 = single mutations, 2 = feed results back (much larger pool)",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="resume an interrupted scan of this domain from its saved state",
    )
    parser.add_argument(
        "--no-state", action="store_true",
        help="do not write resumable scan state for this domain",
    )
    parser.add_argument(
        "--scan-provider-hosts", action="store_true",
        help=(
            "also scan hosts that live on third-party infrastructure "
            "(Office 365 / Exchange Online, SharePoint, S3, Heroku, CDNs, ...).  "
            "By default those hosts are skipped and recorded with their provider"
        ),
    )


def _settings_from_args(args: argparse.Namespace) -> ScanSettings:
    """Merge a TOML config file with explicit CLI flags (CLI wins)."""
    config_path = getattr(args, "config", None)
    settings = ScanSettings.load(config_path)
    if getattr(args, "profile", None):
        settings.profile = str(args.profile)
    for attribute in (
        "dns_timeout", "dns_deadline", "tcp_timeout", "tcp_fast_timeout",
        "http_timeout", "dns_concurrency", "port_concurrency", "http_concurrency",
        "host_batch", "max_candidates", "confirm_resolvers", "permutation_depth",
    ):
        value = getattr(args, attribute, None)
        if value is not None:
            setattr(settings, attribute, value)
    if getattr(args, "output", None):
        settings.output_dir = Path(args.output)
    if getattr(args, "offline", False):
        settings.offline = True
    if getattr(args, "ipv6", False):
        settings.ipv6 = True
    if getattr(args, "no_adaptive_timeout", False):
        settings.adaptive_timeout = False
    if getattr(args, "no_multiplex_dns", False):
        settings.multiplex_dns = False
    if getattr(args, "no_disk_cache", False):
        settings.disk_cache = False
    if getattr(args, "no_discovery", False):
        settings.enable_san = False
        settings.enable_permutations = False
        settings.enable_cnames = False
    if getattr(args, "no_san", False):
        settings.enable_san = False
    if getattr(args, "no_permutations", False):
        settings.enable_permutations = False
    if getattr(args, "no_cnames", False):
        settings.enable_cnames = False
    if getattr(args, "scan_provider_hosts", False):
        settings.skip_provider_hosts = False
    if getattr(args, "no_geo", False):
        settings.geoip = False
    if getattr(args, "no_geo_download", False):
        settings.geoip_download = False
    if getattr(args, "no_reverse_dns", False):
        settings.reverse_dns = False
    if getattr(args, "no_dns_intel", False):
        settings.dns_intel = False
    if getattr(args, "no_mining", False):
        settings.web_mining = False
    if getattr(args, "no_template_checks", False):
        settings.template_checks = False
    if getattr(args, "jsonl", False):
        settings.jsonl = True
    if getattr(args, "no_carry_over", False):
        settings.carry_over = False
    for attribute in (
        "dns_rate",
        "dns_rate_per_server",
        "dns_rate_burst",
        "port_rate",
        "port_rate_per_host",
        "port_rate_burst",
    ):
        value = getattr(args, attribute, None)
        if value is not None:
            setattr(settings, attribute, float(value))
    wordlist = getattr(args, "wordlist", None)
    if wordlist:
        # Fail fast with the list of valid names instead of mid-scan.
        from subsonar.core.wordlists import resolve_wordlist

        settings.wordlist = resolve_wordlist(wordlist).name
    if getattr(args, "permute_wordlist", False):
        settings.wordlist_permutations = True
    if getattr(args, "wordlist_permutation_limit", None) is not None:
        settings.wordlist_permutation_limit = int(args.wordlist_permutation_limit)
    if getattr(args, "ports", None):
        # Validate the spec now so a typo fails before the scan starts.
        from subsonar.core.ports import parse_port_spec

        parse_port_spec(str(args.ports))
        settings.port_matrix = str(args.ports)
    if getattr(args, "port_matrix", None):
        settings.port_matrix = str(args.port_matrix)
    return settings


def _apply_settings(config: ScanConfig, settings: ScanSettings) -> ScanConfig:
    """Copy discovery/accuracy switches from settings onto a ScanConfig."""
    config.enable_discovery = bool(
        settings.enable_san or settings.enable_permutations or settings.enable_cnames
    )
    config.enable_san = settings.enable_san
    config.enable_permutations = settings.enable_permutations
    config.enable_cnames = settings.enable_cnames
    config.permutation_depth = settings.permutation_depth
    config.ipv6 = settings.ipv6
    config.confirm_resolvers = settings.confirm_resolvers
    config.disk_cache = settings.disk_cache
    config.multiplex_dns = settings.multiplex_dns
    config.adaptive_timeout = settings.adaptive_timeout
    config.max_candidates = settings.max_candidates
    config.verify_tls = settings.verify_tls
    config.wildcard_filter = settings.wildcard_filter
    config.skip_provider_hosts = settings.skip_provider_hosts
    config.carry_over = settings.carry_over
    config.geoip = settings.geoip
    config.geoip_download = settings.geoip_download
    config.reverse_dns = settings.reverse_dns
    config.dns_intel = settings.dns_intel
    config.web_mining = settings.web_mining
    if settings.dns_deadline is not None:
        config.dns_name_deadline = max(0.0, float(settings.dns_deadline))
    if settings.dns_rate is not None:
        config.dns_rate_limit = max(0.0, float(settings.dns_rate))
        config.dns_rate_override = True
    if settings.dns_rate_per_server is not None:
        config.dns_rate_per_server = max(0.0, float(settings.dns_rate_per_server))
        config.dns_rate_override = True
    if settings.dns_rate_burst is not None:
        config.dns_rate_burst = max(0.0, float(settings.dns_rate_burst))
    if settings.port_rate is not None:
        config.port_rate_limit = max(0.0, float(settings.port_rate))
        config.port_rate_override = True
    if settings.port_rate_per_host is not None:
        config.port_rate_per_host = max(0.0, float(settings.port_rate_per_host))
        config.port_rate_override = True
    if settings.port_rate_burst is not None:
        config.port_rate_burst = max(0.0, float(settings.port_rate_burst))
    return config


def _config_from_args(args: argparse.Namespace, domain: str) -> ScanConfig:
    """Build a ScanConfig from a TOML file plus CLI overrides."""
    settings = _settings_from_args(args)
    profile = settings.resolve_profile()
    config = settings.build_config(domain, profile=profile)
    return _apply_settings(config, settings)


def _prepare_state(domain: str, args: argparse.Namespace) -> ScanState | None:
    """Load or create resumable scan state for *domain*."""
    if getattr(args, "no_state", False):
        return None
    if getattr(args, "resume", False):
        existing = ScanState.load(domain)
        if existing is None:
            print(f"  no saved state for {domain} — starting a fresh scan")
            return ScanState(domain)
        print(
            f"  resuming {domain}: {existing.summary()} "
            f"({len(existing.pending_candidates()):,} candidate(s) still to resolve)"
        )
        return existing
    return ScanState(domain)


def _target_domains(args: argparse.Namespace) -> list[str]:
    """The target list: the positional domain plus any ``--domains`` extras."""
    domains: list[str] = []
    primary = getattr(args, "domain", None)
    if primary:
        domains.append(primary)
    extra = getattr(args, "domains", None)
    if extra:
        for token in str(extra).split(","):
            token = token.strip()
            if token:
                domains.append(token)
    seen: set[str] = set()
    unique: list[str] = []
    for domain in domains:
        key = domain.strip().lower()
        if key and key not in seen:
            seen.add(key)
            unique.append(domain)
    return unique


def _scan_many(args: argparse.Namespace, domains: list[str]) -> int:
    """Sequential multi-domain run sharing one resolver pool and cache."""
    from subsonar.ui.console import ConsoleRenderer
    from subsonar.core.workflow import run_multi

    settings = _settings_from_args(args)
    profile = settings.resolve_profile()
    formats = [fmt.strip() for fmt in args.formats.split(",") if fmt.strip()]
    findings_total = 0

    async def runner(config: ScanConfig, chosen: object) -> object:
        renderer = ConsoleRenderer(bus=BUS, show_debug=args.debug_log)
        return await renderer.run(config, chosen)  # type: ignore[arg-type]

    async def on_result(domain: str, result: object) -> None:
        nonlocal findings_total
        if result is None:
            return
        findings_total += len(result.findings)  # type: ignore[attr-defined]
        if not args.no_reports:
            written = write_reports(
                result,  # type: ignore[arg-type]
                Path(args.output) if args.output else settings.output_dir,
                formats=formats,
            )
            for fmt, path in written.items():
                print(f"    {domain} {fmt:<5} → {path}")

    print(
        f"\n  multi-domain run — {len(domains)} target(s), profile "
        f"{profile.id}. {profile.name}, sequential on purpose\n"
    )
    asyncio.run(run_multi(domains, settings, runner=runner, on_result=on_result, bus=BUS))
    print(f"\n  batch complete — {findings_total} web interface(s) across {len(domains)} target(s)")
    return EXIT_OK if findings_total else EXIT_NO_FINDINGS


def cmd_scan(args: argparse.Namespace) -> int:
    domains = _target_domains(args)
    if len(domains) > 1:
        return _scan_many(args, domains)

    from subsonar.ui.console import run_console

    profile = _settings_from_args(args).resolve_profile()
    config = _config_from_args(args, domains[0])
    state = _prepare_state(config.domain, args)
    if state is not None:
        state.profile = f"{profile.id}.{profile.name}"
        state.mark("started")

    result = asyncio.run(
        run_console(config, profile, show_debug=args.debug_log, bus=BUS)
    )

    if state is not None:
        state.completed = sorted(set(state.completed) | {"scan"})
        state.candidates = sorted(
            set(state.candidates) | set(result.osint_hosts) | set(result.brute_hosts)
        )
        state.resolved = {
            host: {"addresses": res.addresses, "error": res.error}
            for host, res in result.resolutions.items()
        }
        state.open_ports = {
            host: [p.port for p in ports]
            for host, ports in result.open_ports.items()
        }
        state.mark("done")

    if not args.no_reports:
        formats = [fmt.strip() for fmt in args.formats.split(",") if fmt.strip()]
        written = write_reports(result, config.output_dir, formats=formats)
        for fmt, path in written.items():
            print(f"  {fmt:<5} → {path}")
        _maybe_diff(config.domain, result, args, config.output_dir)
    return EXIT_OK if result.findings else EXIT_NO_FINDINGS


def _cache_dir_for(output_dir: Path) -> Path:
    """Where baselines live: SUBSONAR_CACHE if set, else ``<output>/../.subsonar_cache``."""
    from subsonar.core.config import CACHE_DIR, PROJECT_ROOT

    if CACHE_DIR != PROJECT_ROOT / ".subsonar_cache":
        return Path(CACHE_DIR)
    return Path(output_dir).parent / ".subsonar_cache"


def _maybe_diff(
    domain: str,
    result: object,
    args: argparse.Namespace,
    output_dir: Path,
) -> None:
    """Print and persist a baseline diff when one is available."""
    try:
        current = result.to_dict()  # type: ignore[attr-defined]
    except Exception:
        return
    cache_dir = _cache_dir_for(output_dir)
    # Only the stored baseline is compared against.  Falling back to "the newest
    # report" would compare the scan with the report it just wrote.
    previous = load_baseline(domain, cache_dir)
    if previous is None:
        save_baseline(domain, current, cache_dir)
        print(f"  baseline recorded for {domain} (first scan)")
        return
    diff = diff_results(previous, current)
    print()
    print(f"  change since previous scan — {diff.summary()}")
    for finding in diff.new_findings[:20]:
        print(
            f"    + {finding.get('subdomain')}:{finding.get('port')} "
            f"{finding.get('status')} {finding.get('title') or ''}"
        )
    if len(diff.new_findings) > 20:
        print(f"    … and {len(diff.new_findings) - 20} more new host(s)")
    for entry in diff.changed_findings[:10]:
        after = entry.get("after", {})
        print(
            f"    ~ {after.get('subdomain')}:{after.get('port')} "
            f"({', '.join(entry.get('changed', []))})"
        )
    for finding in diff.lost_findings[:10]:
        print(f"    - {finding.get('subdomain')}:{finding.get('port')} (gone)")
    markdown_path = output_dir / f"diff_{domain}.md"
    try:
        markdown_path.write_text(render_diff_markdown(domain, diff), encoding="utf-8")
        print(f"  diff  → {markdown_path}")
    except Exception:
        pass
    save_baseline(domain, current, cache_dir)


def cmd_tui(args: argparse.Namespace) -> int:
    try:
        from subsonar.ui.tui import run_tui
    except ImportError as exc:
        print(
            f"error: the Textual TUI requires the 'textual' package ({exc}).\n"
            f"       install it with:  {sys.executable} -m pip install textual\n"
            f"       or run the headless console:  python main.py scan <domain>",
            file=sys.stderr,
        )
        return EXIT_ERROR
    # ``args.profile`` defaults to None (the CLI flag is optional), and the TUI
    # has no TOML fallback — resolve it exactly like ``scan`` does.
    profile = _settings_from_args(args).resolve_profile()
    run_tui(
        domain=getattr(args, "domain", None),
        profile_id=profile.id,
        offline=bool(args.offline),
        quiet=bool(getattr(args, "quiet", False)),
    )
    return EXIT_OK


def cmd_web(args: argparse.Namespace) -> int:
    import subprocess

    dashboard = Path(__file__).resolve().parent / "subsonar" / "ui" / "dashboard.py"
    config = Path(__file__).resolve().parent / ".streamlit" / "config.toml"
    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(dashboard),
        "--server.port",
        str(args.port),
        "--theme.base",
        "dark",
        "--theme.backgroundColor",
        Palette.BACKGROUND,
        "--theme.secondaryBackgroundColor",
        Palette.SURFACE,
        "--theme.textColor",
        Palette.TEXT,
        "--theme.primaryColor",
        Palette.PINK,
    ]
    if config.exists():
        command += ["--server.headless", "true" if args.headless else "false"]
    # The dashboard pre-fills its target box from this variable, so
    # ``python main.py web example.com`` means what a user expects it to mean.
    env = dict(os.environ)
    domain = getattr(args, "domain", None)
    if domain:
        env["SUBSONAR_WEB_DOMAIN"] = str(domain)
        print(f"pre-filling the target domain: {domain}")
    print(f"launching Streamlit dashboard on http://127.0.0.1:{args.port}")
    try:
        return subprocess.call(command, env=env)
    except FileNotFoundError:  # pragma: no cover
        print(
            "error: streamlit is not installed — pip install streamlit",
            file=sys.stderr,
        )
        return EXIT_ERROR


def cmd_wordlists(args: argparse.Namespace) -> int:
    """Print the brute-force wordlist registry."""
    import dataclasses

    from subsonar.core.wordlists import WORDLISTS, format_wordlists

    if getattr(args, "json", False):
        print(json.dumps([dataclasses.asdict(spec) for spec in WORDLISTS], indent=2))
        return EXIT_OK
    print()
    print("  brute-force wordlists — pick one with --wordlist NAME")
    print("  (the scan profile still sizes the slice taken from the list)")
    print()
    print(format_wordlists())
    print()
    print("  aliases: ai, super, 5k, 20k, 110k, default, dnsrecon, jhaddix-all, shubham")
    print()
    return EXIT_OK


def cmd_init(args: argparse.Namespace) -> int:
    path = write_example_config()
    print(f"  wrote {path}")
    print("  edit it, then run:  python main.py scan                 # uses ./subsonar.toml")
    return EXIT_OK


def cmd_diff(args: argparse.Namespace) -> int:
    output_dir = Path(args.output) if args.output else Path("output")
    current = load_previous_report(args.domain, output_dir)
    if current is None:
        print(f"error: no report found for {args.domain} in {output_dir}", file=sys.stderr)
        return EXIT_ERROR
    if args.set_baseline:
        path = save_baseline(args.domain, current, Path(".subsonar_cache"))
        print(f"  baseline for {args.domain} recorded from the newest report → {path}")
        return EXIT_OK
    previous = load_baseline(args.domain, Path(".subsonar_cache"))
    if previous is None:
        print(
            f"  no baseline for {args.domain} yet — recording the newest report as "
            f"the baseline"
        )
        save_baseline(args.domain, current, Path(".subsonar_cache"))
        return EXIT_OK
    diff = diff_results(previous, current)
    if args.json:
        print(json.dumps(diff.to_dict(), indent=2, default=str))
        return EXIT_OK
    markdown = render_diff_markdown(args.domain, diff)
    if args.write:
        Path(args.write).write_text(markdown, encoding="utf-8")
        print(f"  diff written to {args.write}")
    else:
        print(markdown)
    return EXIT_OK


def cmd_resume(args: argparse.Namespace) -> int:
    from subsonar.core.config import CACHE_DIR

    if args.all or not args.domain:
        states = sorted(Path(CACHE_DIR).glob("state-*.json"))
        if not states:
            print("  no saved scan state")
            return EXIT_OK
        for path in states:
            domain = path.stem.removeprefix("state-")
            state = ScanState.load(domain)
            if state is not None:
                print(f"  {state.summary()}")
        return EXIT_OK
    state = ScanState.load(args.domain)
    if state is None:
        print(f"  no saved state for {args.domain}")
        return EXIT_OK
    if args.clear:
        state.clear()
        print(f"  cleared saved state for {args.domain}")
        return EXIT_OK
    print(f"  {state.summary()}")
    print(f"  path            : {state.path}")
    print(f"  profile         : {state.profile or 'unknown'}")
    print(f"  last stage      : {state.domain_stage}")
    print(f"  stages completed: {', '.join(state.completed) or 'none'}")
    pending = state.pending_candidates()
    if pending:
        print(f"  pending         : {len(pending):,} candidate(s), e.g. {pending[:3]}")
    print(f"  resume with     : python main.py scan {args.domain} --resume")
    return EXIT_OK


def cmd_geoip(args: argparse.Namespace) -> int:
    """Offline country/ASN index — build, refresh, inspect or look up an address."""
    from subsonar.core import geoip

    cache_dir = Path(args.cache_dir) if args.cache_dir else CACHE_DIR
    want_build = bool(args.build or args.refresh)
    if want_build:
        print("  downloading the free BGP/RIR dumps (one-off, ~10 MB)…")
        try:
            summary = geoip.build_index(cache_dir)
        except Exception as exc:
            print(f"  error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(
                f"  index built — {summary['entries']:,} range(s) "
                f"({summary['ipv4']:,} IPv4 / {summary['ipv6']:,} IPv6) from "
                f"{', '.join(summary['sources'])}"
            )
            print(f"  stored at {geoip.index_path(cache_dir)}")
        geoip.reset_cache()

    if args.lookup:
        record = geoip.enrich(args.lookup, cache_dir)
        if args.json:
            print(json.dumps(record.to_dict() if record else None, indent=2))
            return EXIT_OK if record else EXIT_ERROR
        if record is None:
            print(f"  {args.lookup}: no data (no index, private address or unknown)")
            return EXIT_ERROR
        print(
            f"  {args.lookup}: {record.label}  ·  {record.country or '?'}  ·  "
            f"{record.range_label}"
        )
        return EXIT_OK

    if want_build and not args.stats:
        return EXIT_OK

    # Default: stats.
    index = geoip.load_index(cache_dir)
    if index is None:
        if args.json:
            print(json.dumps({"available": False, "path": str(geoip.index_path(cache_dir))}))
        else:
            print("\n".join(banner_lines(width=100)))
            print()
            print("  no offline geo index yet")
            print(f"    build it with: {sys.executable} main.py geoip --build")
            print(
                "    (free ip2asn.com BGP dump + RIR delegation fallback, "
                "no API key, local lookups)"
            )
            print()
        return EXIT_OK
    stats = index.stats()
    if args.json:
        print(json.dumps(stats, indent=2))
    else:
        print("\n".join(banner_lines(width=100)))
        print()
        print("  offline geo index (country + ASN, no API key)")
        print("  " + "-" * 74)
        print(f"  path      : {stats['path']}")
        print(f"  entries   : {stats['entries']:,}")
        print(f"  ipv4/ipv6 : {stats['ipv4']:,} / {stats['ipv6']:,}")
        age = stats.get("age_days")
        print(f"  age       : {age:.1f} day(s)" if age is not None else "  age       : ?")
        print(f"  sources   : {', '.join(stats['sources']) or '?'}")
        print()
    return EXIT_OK


def cmd_profiles(args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps([p.to_dict() for p in PROFILE_BY_ID.values()], indent=2))
        return EXIT_OK
    print("\n".join(banner_lines(width=100)))
    print()
    print("  available scan profiles")
    print("  " + "-" * 74)
    print(render_profile_table())
    print()
    return EXIT_OK


def cmd_selftest(args: argparse.Namespace) -> int:
    from subsonar.core.selftest import run_selftest

    report = asyncio.run(run_selftest())
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("\n".join(banner_lines(width=100)))
        print("\n  engine self-test (loopback only — no external traffic)\n")
        for check in report["checks"]:
            mark = "✔" if check["ok"] else "✖"
            print(f"  {mark} {check['name']:<34} {check['detail']}")
        print()
        print(
            f"  {report['passed']}/{report['total']} checks passed "
            f"in {report['duration']:.2f}s"
        )
        print()
    return EXIT_OK if report["passed"] == report["total"] else EXIT_ERROR


# --------------------------------------------------------------------------- #
# Default interactive behaviour
# --------------------------------------------------------------------------- #


def interactive_default(argv: Sequence[str]) -> int:
    """No subcommand: launch the TUI, or print guidance when unavailable."""
    try:
        import textual  # noqa: F401
    except ImportError:
        print("\n".join(banner_lines(width=100)))
        print()
        print("  The interactive TUI needs the 'textual' package.")
        print(f"    {sys.executable} -m pip install -r requirements.txt")
        print()
        print("  Meanwhile you can run a scan directly:")
        print("    python main.py scan <domain> --profile 3")
        print()
        return EXIT_OK
    if not sys.stdout.isatty():
        # Piped / non-interactive shell — a full-screen TUI would be unusable.
        print("\n".join(banner_lines(width=100)))
        print()
        print("  No interactive terminal detected, so the full-screen TUI was not")
        print("  started. Available commands:")
        print()
        print("    python main.py scan <domain> --profile 3   headless scan + reports")
        print("    python main.py tui                         interactive TUI (TTY)")
        print("    python main.py web                         Streamlit dashboard")
        print("    python main.py selftest                    engine self-test")
        print()
        return EXIT_OK
    from subsonar.ui.tui import run_tui

    run_tui()
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "scan": cmd_scan,
        "tui": cmd_tui,
        "web": cmd_web,
        "profiles": cmd_profiles,
        "wordlists": cmd_wordlists,
        "geoip": cmd_geoip,
        "selftest": cmd_selftest,
        "init": cmd_init,
        "diff": cmd_diff,
        "resume": cmd_resume,
    }
    if args.command is None:
        try:
            return interactive_default([])
        except KeyboardInterrupt:
            return EXIT_INTERRUPTED
    handler = handlers.get(args.command)
    if handler is None:  # pragma: no cover
        parser.print_help()
        return EXIT_ERROR
    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\ninterrupted — partial results were written if a scan completed")
        return EXIT_INTERRUPTED
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


def _privacy_banner() -> str:
    return (
        f"resolvers: {len(DNS_RESOLVER_POOL)} anonymous · "
        f"blocked: {', '.join(sorted(FORBIDDEN_DNS_SERVERS))}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
