"""Mine in-scope hostnames out of the responses a web scan already fetched.

Free, no API, no extra traffic against the target: the scanner already retrieves
``robots.txt``, ``sitemap.xml``, ``security.txt``, response headers and page
content, so anything those files name is a candidate for free.

Sources mined, in order of signal quality:

* ``/.well-known/security.txt`` — ``Contact``/``Policy``/``Canonical`` URLs,
* ``robots.txt`` — ``Sitemap:`` directives,
* ``sitemap.xml`` — ``<loc>`` entries (recursively for sitemap indexes, bounded),
* response headers — ``Content-Security-Policy`` (``report-uri``,
  ``report-to``…), ``Link``, ``Location``, ``Access-Control-Allow-Origin``,
  ``X-Backend-Server`` and friends,
* inline HTML/JS — absolute URLs that point at the scanned domain.

Everything is filtered through :func:`subsonar.core.osint.is_valid_hostname`
against the target domain, so only in-scope names survive.
"""

from __future__ import annotations

import re
from typing import Iterable, Iterator, Sequence

from .osint import is_valid_hostname

__all__ = [
    "HEADER_HOST_KEYS",
    "extract_hosts",
    "extract_sitemap_locations",
    "mine_headers",
    "mine_text",
]

#: Headers that routinely name internal hosts.
HEADER_HOST_KEYS: tuple[str, ...] = (
    "content-security-policy",
    "content-security-policy-report-only",
    "report-to",
    "link",
    "location",
    "access-control-allow-origin",
    "x-backend-server",
    "x-served-by",
    "x-host",
    "x-forwarded-host",
    "x-origin-server",
    "server-timing",
    "x-amz-website-redirect-location",
    "x-upstream",
    "via",
    "forwarded",
)

#: ``https://host`` / ``//host`` / bare ``host.name.tld`` occurrences.
_URL_RE = re.compile(
    r"(?:(?:https?:)?//)([A-Za-z0-9_][A-Za-z0-9_.\-]*\.[A-Za-z]{2,})",
    re.IGNORECASE,
)
_BARE_HOST_RE = re.compile(
    r"\b([A-Za-z0-9_][A-Za-z0-9_\-]*(?:\.[A-Za-z0-9_\-]+)+\.(?:[A-Za-z]{2,}))\b"
)
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_SITEMAP_DIRECTIVE_RE = re.compile(
    r"^\s*sitemap\s*:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE
)


def extract_sitemap_locations(text: str) -> list[str]:
    """``<loc>`` values inside a sitemap (or sitemap index)."""
    return [match.group(1) for match in _SITEMAP_LOC_RE.finditer(text or "")]


def extract_robots_sitemaps(text: str) -> list[str]:
    """``Sitemap:`` directive URLs from a robots.txt file."""
    return [match.group(1) for match in _SITEMAP_DIRECTIVE_RE.finditer(text or "")]


def _hosts_in(text: str) -> Iterator[str]:
    for match in _URL_RE.finditer(text or ""):
        yield match.group(1)
    for match in _BARE_HOST_RE.finditer(text or ""):
        yield match.group(1)


def extract_hosts(
    text: str, domain: str, *, allow_subdomains: bool = True
) -> list[str]:
    """In-scope hostnames mentioned in *text* (deduplicated, order preserved)."""
    domain = str(domain or "").strip().lower().rstrip(".")
    out: list[str] = []
    for host in _hosts_in(text):
        candidate = host.lower().strip(".").rstrip(".")
        if not candidate or candidate in out:
            continue
        if not is_valid_hostname(candidate, domain):
            continue
        if not allow_subdomains and candidate != domain:
            continue
        out.append(candidate)
    return out


def mine_text(text: str, domain: str) -> list[str]:
    """Hostnames referenced by a body of text (HTML, JS, XML, plain text)."""
    return extract_hosts(text, domain)


def mine_headers(headers: Iterable[tuple[str, str]] | dict[str, str], domain: str) -> list[str]:
    """Hostnames leaked by response headers (CSP, Link, Location, …)."""
    items = headers.items() if isinstance(headers, dict) else headers
    found: list[str] = []
    for name, value in items:
        if str(name).strip().lower() not in HEADER_HOST_KEYS:
            continue
        for host in extract_hosts(str(value), domain):
            if host not in found:
                found.append(host)
    return found


def mine_sitemap_entries(
    text: str, domain: str, *, limit: int = 200
) -> list[str]:
    """Hostnames from a sitemap document (bounded)."""
    locations = extract_sitemap_locations(text)
    if not locations:
        return mine_text(text, domain)[:limit]
    out: list[str] = []
    for url in locations:
        for host in extract_hosts(url, domain):
            if host not in out:
                out.append(host)
            if len(out) >= limit:
                return out
    return out


def summarise(hosts: Sequence[str], domain: str, *, source: str) -> str:
    """One-line log message for a mining result."""
    if not hosts:
        return f"{source}: no new in-scope hostname"
    preview = ", ".join(sorted(hosts)[:5])
    more = "" if len(hosts) <= 5 else f" (+{len(hosts) - 5} more)"
    return f"{source}: {len(hosts)} in-scope hostname(s) — {preview}{more}"
