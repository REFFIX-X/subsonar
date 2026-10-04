"""The eight selectable subsonar scan profiles."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from .config import PORT_MATRIX
from .ports import AUDIT_PORTS, WEB_CORE_PORTS, audit_matrix, full_matrix


@dataclass(frozen=True, slots=True)
class Profile:
    """Declarative description of a scan profile."""

    id: int
    key: str
    name: str
    description: str
    passive: bool = False
    brute: bool = False
    wordlist_size: int = 0
    port_scan: bool = True
    port_mode: str = "matrix"          # matrix | audit | web
    stealth: bool = False
    wildcard_check: bool = True
    osint_sources: tuple[str, ...] = ("crt.sh", "hackertarget", "anubis")
    notes: str = ""

    # -- derived ----------------------------------------------------------- #
    def ports(self) -> dict[int, str]:
        if self.port_mode == "audit":
            return audit_matrix()
        if self.port_mode == "web":
            return {port: PORT_MATRIX[port] for port in WEB_CORE_PORTS if port in PORT_MATRIX}
        return full_matrix()

    def port_numbers(self) -> tuple[int, ...]:
        return tuple(self.ports().keys())

    @property
    def packet_profile(self) -> str:
        """Human summary of how loud this profile is."""
        if self.passive and not self.brute:
            return "0 packets to the target (pure OSINT)"
        if self.stealth:
            return "low-and-slow, randomised delays"
        return "aggressive async fan-out"

    def rate_summary(self) -> str:
        """One-line description of the pacing this profile applies by default."""
        dns = PROFILE_DNS_RATE.get(self.id, 0.0)
        dns_node = PROFILE_DNS_RATE_PER_SERVER.get(self.id, 0.0)
        port = PROFILE_PORT_RATE.get(self.id, 0.0)
        host = PROFILE_PORT_RATE_PER_HOST.get(self.id, 0.0)
        if not dns and not port:
            return "unlimited"
        parts: list[str] = []
        if dns:
            parts.append(
                f"dns {dns:g}/s" + (f" ({dns_node:g}/node)" if dns_node else "")
            )
        if port and self.port_scan:
            parts.append(f"ports {port:g}/s" + (f" ({host:g}/host)" if host else ""))
        return " · ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "passive": self.passive,
            "brute": self.brute,
            "wordlist_size": self.wordlist_size,
            "port_scan": self.port_scan,
            "port_mode": self.port_mode,
            "ports": len(self.port_numbers()),
            "stealth": self.stealth,
            "wildcard_check": self.wildcard_check,
            "osint_sources": list(self.osint_sources),
            "packets": self.packet_profile,
            "notes": self.notes,
        }


PROFILES: tuple[Profile, ...] = (
    Profile(
        id=1,
        key="passive",
        name="Passive Only",
        description="OSINT scraping only — CRT.sh + HackerTarget + Anubis. "
        "Zero packets are sent to the target; only the discovered web "
        "interfaces on 80/443 are verified.",
        passive=True,
        brute=False,
        port_scan=False,
        port_mode="web",
        wildcard_check=False,
        notes="Fully non-intrusive. Ideal for scoping an engagement.",
    ),
    Profile(
        id=2,
        key="light",
        name="Light Brute",
        description="Top 1,000 subdomains from SecLists + the full Top-50 port "
        "matrix.",
        passive=False,
        brute=True,
        wordlist_size=1_000,
        port_scan=True,
        port_mode="matrix",
        notes="Fast, low-noise first pass.",
    ),
    Profile(
        id=3,
        key="medium",
        name="Medium Brute",
        description="Top 5,000 subdomains from SecLists + the full Top-50 port "
        "matrix.",
        passive=False,
        brute=True,
        wordlist_size=5_000,
        port_scan=True,
        port_mode="matrix",
        notes="Balanced default for production reconnaissance.",
    ),
    Profile(
        id=4,
        key="deep",
        name="Deep Brute",
        description="Top 20,000 subdomains from SecLists + the full Top-50 port "
        "matrix.",
        passive=False,
        brute=True,
        wordlist_size=20_000,
        port_scan=True,
        port_mode="matrix",
        notes="Long-running exhaustive sweep.",
    ),
    Profile(
        id=5,
        key="full-postal",
        name="Full Postal",
        description="Passive OSINT + Medium brute-force combined — maximum "
        "coverage in a single run.",
        passive=True,
        brute=True,
        wordlist_size=5_000,
        port_scan=True,
        port_mode="matrix",
        notes="Recommended when time allows.",
    ),
    Profile(
        id=6,
        key="quick",
        name="HTTP Quick Check",
        description="Fast DNS resolution of the top 500 subdomains with an "
        "immediate port check — optimised for speed over depth.",
        passive=True,
        brute=True,
        wordlist_size=500,
        port_scan=True,
        port_mode="web",
        wildcard_check=True,
        notes="Sub-minute triage sweep.",
    ),
    Profile(
        id=7,
        key="infra",
        name="Infrastructure Audit",
        description="Dedicated profile focused only on alternative web admin "
        "ports (8443, 9443, 10000, 2083, 2087, ...) across passive and light "
        "brute candidates.",
        passive=True,
        brute=True,
        wordlist_size=2_000,
        port_scan=True,
        port_mode="audit",
        notes=f"{len(AUDIT_PORTS)} alternative admin ports only.",
    ),
    Profile(
        id=8,
        key="stealth",
        name="Stealth Mode",
        description="Low-and-slow brute-forcing with randomised delays between "
        "async requests to evade rate-based detection.",
        passive=False,
        brute=True,
        wordlist_size=5_000,
        port_scan=True,
        port_mode="matrix",
        stealth=True,
        notes="Rate-limited fan-out; expect a long runtime.",
    ),
)

PROFILE_BY_ID: dict[int, Profile] = {profile.id: profile for profile in PROFILES}
PROFILE_BY_KEY: dict[str, Profile] = {profile.key: profile for profile in PROFILES}

#: Concurrency envelope per profile (dns, port, http).
PROFILE_CONCURRENCY: dict[int, tuple[int, int, int]] = {
    1: (200, 200, 40),
    2: (400, 300, 60),
    3: (400, 300, 60),
    4: (500, 400, 80),
    5: (450, 350, 70),
    6: (600, 400, 80),
    7: (350, 300, 60),
    8: (60, 40, 12),
}

#: Randomised inter-request delay (seconds) per profile.
PROFILE_DELAY: dict[int, tuple[float, float]] = {
    1: (0.0, 0.0),
    2: (0.0, 0.02),
    3: (0.0, 0.03),
    4: (0.0, 0.05),
    5: (0.0, 0.03),
    6: (0.0, 0.0),
    7: (0.0, 0.02),
    8: (0.35, 1.25),
}

#: DNS queries/second per profile (``0`` = unlimited).
#:
#: A concurrency limit bounds how many queries are *in flight*; it says nothing
#: about how many leave the machine per second — which is the number a resolver
#: operator actually sees, and the number that gets a scanner rate-limited or
#: banned.  Every profile therefore paces its queries by default; the values sit
#: comfortably below common per-client thresholds (and below the throughput the
#: concurrency setting would otherwise produce).
PROFILE_DNS_RATE: dict[int, float] = {
    1: 60.0,      # passive: only OSINT/wildcard/DNS-intel lookups
    2: 150.0,
    3: 250.0,
    4: 300.0,
    5: 250.0,
    6: 300.0,     # quick check: few names, so a slightly higher ceiling
    7: 250.0,
    8: 25.0,
}

#: Per-nameserver queries/second per profile (``0`` = unlimited).  Keeps one
#: pooled resolver from ever carrying a whole burst on its own.
PROFILE_DNS_RATE_PER_SERVER: dict[int, float] = {
    1: 20.0,
    2: 30.0,
    3: 50.0,
    4: 60.0,
    5: 50.0,
    6: 60.0,
    7: 50.0,
    8: 8.0,
}

#: TCP connects/second for the port sweep, per profile (``0`` = unlimited).
#: A firewall or IPS sees the connects-per-second, not the concurrency setting.
PROFILE_PORT_RATE: dict[int, float] = {
    1: 0.0,       # no port scan at all
    2: 400.0,
    3: 600.0,
    4: 800.0,
    5: 500.0,
    6: 800.0,
    7: 500.0,
    8: 60.0,
}

#: Per-host connects/second per profile — the same target is never hammered even
#: when the global budget is shared across a 32-host batch.
PROFILE_PORT_RATE_PER_HOST: dict[int, float] = {
    1: 0.0,
    2: 40.0,
    3: 60.0,
    4: 80.0,
    5: 50.0,
    6: 80.0,
    7: 50.0,
    8: 10.0,
}


def get_profile(identifier: int | str) -> Profile:
    """Resolve a profile by numeric id or mnemonic key."""
    if isinstance(identifier, int) or (isinstance(identifier, str) and identifier.isdigit()):
        profile = PROFILE_BY_ID.get(int(identifier))
    else:
        profile = PROFILE_BY_KEY.get(str(identifier).strip().lower())
    if profile is None:
        raise KeyError(
            f"unknown profile {identifier!r} — choose 1-8 or one of "
            + ", ".join(p.key for p in PROFILES)
        )
    return profile


def profile_choices() -> Sequence[str]:
    return tuple(f"{p.id}. {p.name}" for p in PROFILES)


def render_profile_table() -> str:
    """Plain-text menu used by the CLI and the Streamlit sidebar."""
    lines = []
    for profile in PROFILES:
        ports = len(profile.port_numbers())
        lines.append(
            f"  [{profile.id}] {profile.name:<22} "
            f"wordlist={profile.wordlist_size or 0:<6} ports={ports:<3} "
            f"{'passive ' if profile.passive else '        '}"
            f"{'brute ' if profile.brute else '      '}"
            f"{'stealth' if profile.stealth else ''}"
        )
        lines.append(f"      {profile.description}")
        # The profile also decides *how fast* the scan is allowed to go: the
        # wordlist says which names are tried, this says at what rate.
        lines.append(f"      rate limit: {profile.rate_summary()}")
    return "\n".join(lines)


def apply_profile(profile: Profile, config: Any) -> Any:
    """Push profile settings onto a :class:`ScanConfig` instance.

    A port matrix the caller chose explicitly (``--ports``, ``--port-matrix``,
    TOML ``port_matrix``/``ports`` or a direct ``ScanConfig(ports=…)``) is left
    alone — the profile only supplies the default matrix.
    """
    dns_c, port_c, http_c = PROFILE_CONCURRENCY[profile.id]
    config.profile_id = profile.id
    if not getattr(config, "ports_override", False):
        config.ports = profile.ports()
    # An explicit --dns/port/http-concurrency (or TOML/direct value) wins over
    # the profile's pacing; otherwise the profile supplies a sane default.
    if not getattr(config, "concurrency_override", False):
        config.dns_concurrency = dns_c
        config.port_concurrency = port_c
        config.http_concurrency = http_c
    config.stealth_delay = PROFILE_DELAY[profile.id]
    if not getattr(config, "wildcard_override", False):
        config.wildcard_filter = profile.wildcard_check
    # An explicit --dns-rate/--port-rate (or TOML value) always wins over the
    # profile default; otherwise the profile supplies a sane, ban-safe pace.
    if not getattr(config, "dns_rate_override", False):
        config.dns_rate_limit = PROFILE_DNS_RATE.get(profile.id, 0.0)
        config.dns_rate_per_server = PROFILE_DNS_RATE_PER_SERVER.get(profile.id, 0.0)
    if not getattr(config, "port_rate_override", False):
        config.port_rate_limit = PROFILE_PORT_RATE.get(profile.id, 0.0)
        config.port_rate_per_host = PROFILE_PORT_RATE_PER_HOST.get(profile.id, 0.0)
    return config
