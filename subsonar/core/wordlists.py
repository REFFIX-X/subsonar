"""Curated brute-force wordlist registry.

Every list here is free, public and needs no key or signup.  Remote lists are
streamed from **raw GitHub** (never an archive) and cached under
``.subsonar_cache/``; built-in lists ship with the package and need no network at
all, which is what makes ``--offline`` work from a cold start.

The big lists are memory-safe to use: :func:`~subsonar.core.wordlist.parse_wordlist`
streams the file, and every run only takes the slice the profile asks for
(``--wordlist jhaddix -p 2`` = the first 1 000 labels of a 26 MB list).

Add a list by appending a :class:`WordlistSpec`; nothing else has to change.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import DEFAULT_WORDLIST, PACKAGE_ROOT

__all__ = [
    "ALIASES",
    "BUILTIN_DIR",
    "DEFAULT_WORDLIST",
    "WORDLISTS",
    "WordlistSpec",
    "available_wordlists",
    "format_wordlists",
    "get_wordlist",
    "mirror_urls",
    "resolve_wordlist",
]

#: Directory holding packaged (built-in) wordlists.
BUILTIN_DIR = PACKAGE_ROOT / "data"

_SECLISTS = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/"
    "master/Discovery/DNS/"
)

#: The AI Super list shipped with the package — regenerate with
#: ``python tools/build_ai_wordlist.py``.
AI_SUPER_FILE = "ai-super-subdomains.txt"


@dataclass(frozen=True, slots=True)
class WordlistSpec:
    """One selectable brute-force wordlist."""

    name: str
    label: str
    #: ``https://…`` for a streamed list, ``builtin:<filename>`` for a packaged one.
    source: str
    #: Documented entry count (best effort — the file itself is authoritative).
    approx_size: int
    tags: tuple[str, ...]
    licence: str
    #: Where the labels came from (shown by ``main.py wordlists``).
    provenance: str = ""

    @property
    def builtin(self) -> bool:
        return self.source.startswith("builtin:")

    @property
    def filename(self) -> str:
        """Basename used for the cache file / packaged file."""
        if self.builtin:
            return self.source.split(":", 1)[1]
        return self.source.rstrip("/").split("/")[-1]

    @property
    def path(self) -> Path | None:
        """Path of a packaged list (``None`` for streamed lists)."""
        return BUILTIN_DIR / self.filename if self.builtin else None


WORDLISTS: tuple[WordlistSpec, ...] = (
    WordlistSpec(
        name="seclists-top1m",
        label="SecLists Subdomains Top 1M (110k slice)",
        source=_SECLISTS + "subdomains-top1million-110000.txt",
        approx_size=110_000,
        tags=("default", "balanced"),
        licence="MIT",
        provenance="danielmiessler/SecLists — the long-standing default",
    ),
    WordlistSpec(
        name="seclists-5k",
        label="SecLists Top-1M, five-thousand slice (fastest)",
        source=_SECLISTS + "subdomains-top1million-5000.txt",
        approx_size=5_000,
        tags=("fast", "recon"),
        licence="MIT",
        provenance="danielmiessler/SecLists",
    ),
    WordlistSpec(
        name="seclists-20k",
        label="SecLists Top-1M, twenty-thousand slice",
        source=_SECLISTS + "subdomains-top1million-20000.txt",
        approx_size=20_000,
        tags=("fast", "balanced"),
        licence="MIT",
        provenance="danielmiessler/SecLists",
    ),
    WordlistSpec(
        name="bitquark",
        label="bitquark DNS popularity list (100k, frequency weighted)",
        source=_SECLISTS + "bitquark-subdomains-top100000.txt",
        approx_size=100_000,
        tags=("frequency", "research"),
        licence="MIT",
        provenance="bitquark — popularity-ranked, a different token mix to Top-1M",
    ),
    WordlistSpec(
        name="namelist",
        label="dnsrecon namelist (real-world hostname vocabulary)",
        source=_SECLISTS + "namelist.txt",
        approx_size=190_000,
        tags=("high-yield", "hostnames"),
        licence="MIT",
        provenance="the dnsrecon namelist, mirrored in SecLists",
    ),
    WordlistSpec(
        name="deepmagic",
        label="DeepMagic network-prefix list (500, high signal)",
        source=_SECLISTS + "deepmagic.com-prefixes-top500.txt",
        approx_size=500,
        tags=("network", "infra"),
        licence="MIT",
        provenance="deepmagic.com prefix study — ISP/Carrier vocabulary",
    ),
    WordlistSpec(
        name="deepmagic-50k",
        label="DeepMagic network-prefix list (50k)",
        source=_SECLISTS + "deepmagic.com-prefixes-top50000.txt",
        approx_size=50_000,
        tags=("network", "infra"),
        licence="MIT",
        provenance="deepmagic.com prefix study, extended",
    ),
    WordlistSpec(
        name="fierce",
        label="fierce hostlist (classic, ~2k)",
        source=_SECLISTS + "fierce-hostlist.txt",
        approx_size=2_000,
        tags=("classic", "fast"),
        licence="MIT",
        provenance="the original fierce DNS bruteforce list",
    ),
    WordlistSpec(
        name="shubs",
        label="Shubham Shah recon list (real-world, 6 MB)",
        source=_SECLISTS + "shubs-subdomains.txt",
        approx_size=600_000,
        tags=("deep", "recon"),
        licence="MIT",
        provenance="Shubham Shah's merged real-world recon output",
    ),
    WordlistSpec(
        name="jhaddix",
        label="Jason Haddix 'all' merge (26 MB — deepest)",
        source=_SECLISTS + "dns-Jhaddix.txt",
        approx_size=2_000_000,
        tags=("deep", "mega"),
        licence="MIT",
        provenance="jhaddix's all.txt merge, mirrored in SecLists",
    ),
    WordlistSpec(
        name="ai-super",
        label="subsonar AI Super list (curated + generated, built-in)",
        source=f"builtin:{AI_SUPER_FILE}",
        approx_size=23_052,
        tags=("curated", "no-network", "modern"),
        licence="CC0-1.0",
        provenance=(
            "generated by subsonar from curated recon vocabulary, naming "
            "conventions and modern-stack defaults — see tools/build_ai_wordlist.py"
        ),
    ),
)

#: Accepted spellings → canonical registry name.
ALIASES: dict[str, str] = {
    "default": DEFAULT_WORDLIST,
    "seclists": DEFAULT_WORDLIST,
    "top1m": DEFAULT_WORDLIST,
    "top1million": DEFAULT_WORDLIST,
    "110k": DEFAULT_WORDLIST,
    "5k": "seclists-5k",
    "20k": "seclists-20k",
    "bitquark-top100k": "bitquark",
    "dnsrecon": "namelist",
    "deepmagic-top500": "deepmagic",
    "deepmagic-top50000": "deepmagic-50k",
    "jhaddix-all": "jhaddix",
    "shubham": "shubs",
    "subbrute": "seclists-top1m",
    "ai": "ai-super",
    "super": "ai-super",
    "ai-special": "ai-super",
}

BY_NAME: dict[str, WordlistSpec] = {spec.name: spec for spec in WORDLISTS}


def resolve_wordlist(name: str | None) -> WordlistSpec:
    """Resolve a registry name (or alias); ``None``/empty means the default."""
    key = str(name or "").strip().lower()
    if not key:
        return BY_NAME[DEFAULT_WORDLIST]
    key = ALIASES.get(key, key)
    try:
        return BY_NAME[key]
    except KeyError:
        raise KeyError(
            f"unknown wordlist {name!r} — choose one of "
            + ", ".join(spec.name for spec in WORDLISTS)
        ) from None


def get_wordlist(name: str | None) -> WordlistSpec:
    """:func:`resolve_wordlist` with the friendly error as a ``ValueError``."""
    try:
        return resolve_wordlist(name)
    except KeyError as exc:
        raise ValueError(exc.args[0]) from None


def available_wordlists() -> tuple[WordlistSpec, ...]:
    return WORDLISTS


def mirror_urls(spec: WordlistSpec) -> tuple[str, ...]:
    """Alternative CDN mirrors serving the *same* file (jsDelivr, githack).

    ``raw.githubusercontent.com`` is the canonical host but it is rate-limited and
    occasionally blocked; these two serve the identical bytes from GitHub's
    content, which matters most for the very large lists.
    """
    if spec.builtin or "raw.githubusercontent.com/" not in spec.source:
        return ()
    path = spec.source.split("raw.githubusercontent.com/", 1)[1]
    parts = path.split("/")
    if len(parts) < 5:  # owner/repo/branch/…/file
        return ()
    owner, repo, branch = parts[0], parts[1], parts[2]
    remainder = "/".join(parts[3:])
    return (
        f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{remainder}",
        f"https://raw.githack.com/{owner}/{repo}/{branch}/{remainder}",
    )


def format_wordlists() -> str:
    """Plain-text table used by ``main.py wordlists`` and the README."""
    lines: list[str] = []
    for spec in WORDLISTS:
        where = "built-in" if spec.builtin else "streamed+cached"
        lines.append(
            f"  {spec.name:<15} {spec.approx_size:>9,} labels  {where:<15} "
            f"{spec.licence:<9} {spec.label}"
        )
        if spec.provenance:
            lines.append(f"      {spec.provenance}")
    return "\n".join(lines)
