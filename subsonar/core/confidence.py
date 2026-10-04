"""Per-finding confidence scoring.

Every finding gets a 0–100 score, a ``high``/``medium``/``low`` label and — the
part that matters — a list of the *reasons* that raised the score and the
*penalties* that lowered it.  A score that cannot be explained is a bug: each
contribution below appends exactly one line to
:attr:`~subsonar.core.confidence.ConfidenceBreakdown.reasons` or
:attr:`~subsonar.core.confidence.ConfidenceBreakdown.penalties`.

The scorer is duck-typed: it accepts the engine's
:class:`~subsonar.core.engine.Finding`, a plain ``dict``, a
:class:`~subsonar.core.web_probe.WebProbeResult` or any object exposing the same
attribute names.  Nothing is imported from the engine, so this module stays
independently importable.

Two scoring choices are worth calling out because they intentionally differ from
a naive reading of "4xx is bad, 2xx is good":

* ``401``/``403``/``407``/``429``/``451`` prove a live application (something is
  enforcing auth or a rate limit), so they earn an *application* reason — and
  still take the client-error penalty, because the content itself was not
  served.  Net effect: a gated service ranks below an open one, above a 404.
* Signals that need cross-finding context (content length uniform across many
  interfaces, a fingerprint shared by many ports) cannot be computed from one
  finding alone.  :func:`rank_findings` computes those cluster counts and hands
  them to :func:`score_finding` through the optional kwargs
  (``shared_content_lengths``, ``shared_fingerprints``); the keywords are
  documented and default to "no information", never to a penalty.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "HIGH_THRESHOLD",
    "MEDIUM_THRESHOLD",
    "WEIGHTS",
    "ConfidenceBreakdown",
    "label_for",
    "score_finding",
    "rank_findings",
]

#: Score at or above which a finding is reported as ``high`` confidence.
HIGH_THRESHOLD = 75
#: Score at or above which a finding is reported as ``medium`` confidence.
MEDIUM_THRESHOLD = 45

#: Documented weights (points) for every signal.  Kept as data so the report and
#: the tests can assert on the same numbers the scorer uses.
WEIGHTS: dict[str, int] = {
    "status_2xx": 30,
    "status_3xx_same_port": 12,
    "status_auth_gated": 16,
    "status_client_error": -15,
    "status_server_error": -22,
    "status_missing": -8,
    "title_present": 12,
    "title_missing": -8,
    "title_redirect_label": -6,
    "content_length_plausible": 8,
    "content_length_tiny": -4,
    "content_length_empty": -6,
    "content_length_uniform": -10,
    "server_header": 6,
    "tls": 10,
    "multi_port_host": 5,
    "favicon": 8,
    "technology_each": 4,
    "technology_max": 12,
    "security_header_each": 3,
    "security_header_max": 9,
    "data_file_each": 3,
    "data_file_max": 9,
    "fingerprint_distinct": 8,
    "fingerprint_shared": -20,
    "fingerprint_wildcard": -30,
    "wildcard_ip": -35,
    "resolvers_single": -12,
    "resolvers_agreeing": 5,
    "alias_ports": -14,
    "kind_redirect": -25,
}

_2XX = frozenset(range(200, 300))
_3XX = frozenset(range(300, 400))
#: Statuses that prove an application is there but is refusing to serve content.
_AUTH_STATUSES = frozenset({401, 403, 407, 429, 451})

_PLAUSIBLE_CONTENT_MIN = 256
_PLAUSIBLE_CONTENT_MAX = 8 * 1024 * 1024

_REDIRECT_TITLE_PREFIX = "redirects to"

#: Context keys that may be supplied as ``{host: value}`` maps to
#: :func:`rank_findings`; every other key is passed through unchanged.
PER_FINDING_KEYS = frozenset({"technologies", "data_files", "headers", "favicon_hash"})

#: Keyword arguments :func:`score_finding` accepts (used to filter ``**context``).
_SCORE_KWARGS = frozenset(
    {
        "wildcard_ips",
        "wildcard_fingerprints",
        "resolvers_agreeing",
        "favicon_hash",
        "technologies",
        "data_files",
        "headers",
        "shared_content_lengths",
        "shared_fingerprints",
        "open_ports",
    }
)


@dataclass(slots=True)
class ConfidenceBreakdown:
    """Explainable confidence for one finding."""

    score: int
    label: str
    reasons: list[str] = field(default_factory=list)
    penalties: list[str] = field(default_factory=list)

    @property
    def explainable(self) -> bool:
        return bool(self.reasons or self.penalties)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "label": self.label,
            "reasons": list(self.reasons),
            "penalties": list(self.penalties),
        }

    def render(self) -> str:
        """One-line human summary: ``high 82 — +reason -penalty``."""
        tail = ""
        if self.reasons:
            tail += " + " + "; ".join(self.reasons)
        if self.penalties:
            tail += " - " + "; ".join(self.penalties)
        return f"{self.label} {self.score}{tail}"

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.render()


def label_for(score: int) -> str:
    """Map a 0–100 score onto ``high``/``medium``/``low``."""
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


# --------------------------------------------------------------------------- #
# Duck-typed access helpers
# --------------------------------------------------------------------------- #


def _get(finding: Any, name: str, default: Any = None) -> Any:
    if finding is None:
        return default
    if isinstance(finding, Mapping):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _finding_keys(finding: Any) -> tuple[str, ...]:
    keys: list[str] = []
    for name in ("subdomain", "host", "url", "ip", "link", "name"):
        value = _get(finding, name)
        if isinstance(value, str) and value:
            keys.append(value)
    return tuple(keys)


def _resolve_context(value: Any, finding: Any, key: str) -> Any:
    """Resolve one ``**context`` entry for one finding.

    * a plain value is used as-is;
    * a ``{host: value}`` mapping is looked up by the finding's identifiers
      (``subdomain``/``host``/``url``/``ip``) — but only for
      :data:`PER_FINDING_KEYS`;
    * a ``{path: status}`` mapping is a data-file map for *every* finding;
    * a per-host mapping with no entry for this finding resolves to ``None``
      (no evidence), never to a penalty.
    """
    if not isinstance(value, Mapping):
        return value
    for candidate in _finding_keys(finding):
        if candidate in value:
            return value[candidate]
    if key in PER_FINDING_KEYS:
        if value and all(str(item).startswith("/") for item in value):
            return value
        return None
    return value


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #


def score_finding(
    finding: Any,
    *,
    wildcard_ips: Sequence[str] = (),
    wildcard_fingerprints: Sequence[str] = (),
    resolvers_agreeing: int = 0,
    favicon_hash: str | None = None,
    technologies: Sequence[Any] | None = None,
    data_files: Mapping[str, int] | None = None,
    headers: Mapping[str, str] | None = None,
    shared_content_lengths: int = 0,
    shared_fingerprints: int = 0,
    open_ports: int = 0,
) -> ConfidenceBreakdown:
    """Score one finding 0–100 with a full explanation.

    ``technologies``, ``data_files``, ``headers`` and ``favicon_hash`` default to
    ``None``, which means "use whatever the finding object carries" (the
    fingerprinting subsystem can be merged onto a finding); passing an explicit
    value — including an empty one — overrides it.

    ``shared_content_lengths`` / ``shared_fingerprints`` are the number of *other*
    findings with the same content length / response fingerprint; both default to
    ``0`` ("unknown, do not penalise") and are filled in by
    :func:`rank_findings`.
    """
    reasons: list[str] = []
    penalties: list[str] = []
    raw = 0

    def reward(points: int, text: str) -> None:
        nonlocal raw
        raw += points
        reasons.append(text)

    def punish(points: int, text: str) -> None:
        nonlocal raw
        raw += points  # points are negative
        penalties.append(text)

    status = _get(finding, "status")
    status = _as_int(status) if status is not None else None
    kind = _get(finding, "kind", "interface") or "interface"
    title = _get(finding, "title")
    title_text = str(title).strip() if title else ""
    content_length = _as_int(_get(finding, "content_length", 0))
    server = _get(finding, "server")
    tls = bool(_get(finding, "tls", False))
    tls_version = _get(finding, "tls_version")
    host = _get(finding, "subdomain") or _get(finding, "host") or "?"
    port = _get(finding, "port")
    fingerprint = _get(finding, "fingerprint")
    aliases = list(_get(finding, "aliases") or [])

    # -- HTTP status ------------------------------------------------------ #
    if status is None:
        punish(WEIGHTS["status_missing"], "no HTTP status was recorded")
    elif kind == "redirect":
        punish(
            WEIGHTS["kind_redirect"],
            f"the scanned port only bounces the request elsewhere (HTTP {status})",
        )
    elif status in _2XX:
        reward(
            WEIGHTS["status_2xx"],
            f"HTTP {status} — the application served a real response",
        )
    elif status in _3XX:
        reward(
            WEIGHTS["status_3xx_same_port"],
            f"HTTP {status} — a redirect that stays on the scanned port",
        )
    elif status in _AUTH_STATUSES:
        reward(
            WEIGHTS["status_auth_gated"],
            f"HTTP {status} — an application is present but gated",
        )
        punish(
            WEIGHTS["status_client_error"],
            f"HTTP {status} is a client error — content was not served",
        )
    elif status >= 500:
        punish(WEIGHTS["status_server_error"], f"HTTP {status} — server error")
    elif status >= 400:
        punish(WEIGHTS["status_client_error"], f"HTTP {status} — client error")
    else:
        punish(WEIGHTS["status_missing"], f"unexpected HTTP status {status}")

    # -- title ------------------------------------------------------------ #
    if not title_text:
        punish(WEIGHTS["title_missing"], "no page title — an empty shell or error page")
    elif title_text.lower().startswith(_REDIRECT_TITLE_PREFIX):
        punish(
            WEIGHTS["title_redirect_label"],
            "title is the synthetic redirect label, not real page content",
        )
    else:
        reward(WEIGHTS["title_present"], f"page title present ({title_text[:60]!r})")

    # -- body size -------------------------------------------------------- #
    if content_length == 0:
        punish(WEIGHTS["content_length_empty"], "empty response body")
    elif content_length < _PLAUSIBLE_CONTENT_MIN:
        punish(
            WEIGHTS["content_length_tiny"],
            f"body is only {content_length} bytes — likely a placeholder",
        )
    elif content_length <= _PLAUSIBLE_CONTENT_MAX:
        reward(
            WEIGHTS["content_length_plausible"],
            f"content length {content_length} bytes is in a plausible range",
        )
    if shared_content_lengths >= 2:
        punish(
            WEIGHTS["content_length_uniform"],
            f"content length {content_length} is shared with "
            f"{shared_content_lengths} other findings — uniform responses",
        )

    # -- transport / server ----------------------------------------------- #
    if server:
        reward(WEIGHTS["server_header"], f"Server header present ({str(server)[:60]})")
    if tls:
        detail = f" ({tls_version})" if tls_version else ""
        reward(WEIGHTS["tls"], f"TLS negotiated{detail}")

    # -- host surface ----------------------------------------------------- #
    ports_seen = _as_int(open_ports, 0) or (len(aliases) + 1)
    if ports_seen >= 2:
        reward(
            WEIGHTS["multi_port_host"],
            f"host answers on {ports_seen} ports — a real multi-service host",
        )
    if aliases:
        rendered = ", ".join(str(item) for item in aliases[:6])
        punish(
            WEIGHTS["alias_ports"],
            f"port {port} is one of {len(aliases) + 1} serving identical content "
            f"(also on {rendered})",
        )

    # -- favicon ---------------------------------------------------------- #
    icon = favicon_hash if favicon_hash is not None else _get(finding, "favicon_hash")
    if icon:
        reward(WEIGHTS["favicon"], f"favicon hash {icon} identifies the application")

    # -- technologies ----------------------------------------------------- #
    tech_list = list(
        technologies if technologies is not None else (_get(finding, "technologies") or ())
    )
    if tech_list:
        names: list[str] = []
        for tech in tech_list[:4]:
            name = _get(tech, "name") if not isinstance(tech, str) else tech
            if name:
                names.append(str(name))
        points = min(len(tech_list) * WEIGHTS["technology_each"], WEIGHTS["technology_max"])
        reward(
            points,
            f"{len(tech_list)} technologies detected"
            + (f" ({', '.join(names)})" if names else ""),
        )

    # -- security headers ------------------------------------------------- #
    header_map = headers if headers is not None else _get(finding, "headers")
    if isinstance(header_map, Mapping) and header_map:
        points = min(
            len(header_map) * WEIGHTS["security_header_each"],
            WEIGHTS["security_header_max"],
        )
        reward(
            points,
            f"{len(header_map)} security/technology headers present "
            f"({', '.join(sorted(str(key) for key in header_map)[:4])})",
        )

    # -- well-known data files -------------------------------------------- #
    file_map = data_files if data_files is not None else _get(finding, "data_files")
    if isinstance(file_map, Mapping) and file_map:
        hits = [path for path, code in file_map.items() if _as_int(code, 0) < 400]
        if hits:
            points = min(len(hits) * WEIGHTS["data_file_each"], WEIGHTS["data_file_max"])
            reward(
                points,
                f"{len(hits)} well-known data files answered "
                f"({', '.join(sorted(str(path) for path in hits)[:3])})",
            )

    # -- response fingerprint --------------------------------------------- #
    wildcard_fp = {str(item) for item in (wildcard_fingerprints or ())}
    if fingerprint and str(fingerprint) in wildcard_fp:
        punish(
            WEIGHTS["fingerprint_wildcard"],
            f"response fingerprint {str(fingerprint)[:16]} matches the wildcard signature",
        )
    elif shared_fingerprints >= 1:
        # One other host on the same scheme serving the byte-identical response
        # is already boilerplate rather than a distinct interface.
        punish(
            WEIGHTS["fingerprint_shared"],
            f"response fingerprint is shared with {shared_fingerprints} other "
            "host(s) on this scheme — identical boilerplate",
        )
    elif fingerprint and shared_fingerprints == 0:
        reward(
            WEIGHTS["fingerprint_distinct"],
            f"response fingerprint {str(fingerprint)[:16]} is distinct from siblings",
        )

    # -- resolver agreement ----------------------------------------------- #
    wildcard_ip_list = tuple(str(item) for item in (wildcard_ips or ()))
    ip = _get(finding, "ip")
    if ip is not None and str(ip) in wildcard_ip_list:
        punish(
            WEIGHTS["wildcard_ip"],
            f"IP {ip} answers for non-existent labels (wildcard responder)",
        )
    agreeing = _as_int(resolvers_agreeing, 0)
    if agreeing == 1:
        punish(
            WEIGHTS["resolvers_single"],
            "only one resolver returned this IP — single-source resolution",
        )
    elif agreeing >= 2:
        reward(
            WEIGHTS["resolvers_agreeing"],
            f"{agreeing} independent resolvers agree on this IP",
        )

    if not reasons:
        reasons.append("no positive evidence was available for this finding")

    score = max(0, min(100, raw))
    return ConfidenceBreakdown(
        score=score,
        label=label_for(score),
        reasons=reasons,
        penalties=penalties,
    )


def _sort_key(finding: Any) -> tuple[str, int, str]:
    host = _get(finding, "subdomain") or _get(finding, "host") or ""
    return (
        str(host),
        _as_int(_get(finding, "port", 0), 0),
        str(_get(finding, "url", "") or ""),
    )


def rank_findings(findings: Sequence[Any], **context: Any) -> list[tuple[Any, ConfidenceBreakdown]]:
    """Score every finding and return them sorted by score (descending).

    Cross-finding signals are computed here and fed into :func:`score_finding`:
    the number of *other* findings sharing a content length, and the number
    sharing a response fingerprint.

    ``**context`` is forwarded to :func:`score_finding`.  The keys in
    :data:`PER_FINDING_KEYS` (``technologies``, ``data_files``, ``headers``,
    ``favicon_hash``) may be passed either as one value for every finding or as a
    ``{host: value}`` mapping that is resolved per finding.
    """
    items = list(findings)
    length_counts: dict[int, int] = {}
    #: fingerprint → set of (scheme, host) pairs, so "shared" means *different
    #: host on the same scheme* rather than the same host twice over HTTP/HTTPS.
    scheme_hosts: dict[str, set[tuple[str, str]]] = {}
    for finding in items:
        length = _as_int(_get(finding, "content_length", 0))
        length_counts[length] = length_counts.get(length, 0) + 1
        fingerprint = _get(finding, "fingerprint")
        if fingerprint:
            scheme_hosts.setdefault(str(fingerprint), set()).add(
                (
                    str(_get(finding, "scheme", "")),
                    str(_get(finding, "subdomain", _get(finding, "host", ""))),
                )
            )

    scored: list[tuple[Any, ConfidenceBreakdown]] = []
    for finding in items:
        resolved: dict[str, Any] = {}
        for key, value in context.items():
            if key not in _SCORE_KWARGS:
                continue
            resolved[key] = _resolve_context(value, finding, key)
        length = _as_int(_get(finding, "content_length", 0))
        resolved.setdefault(
            "shared_content_lengths", max(0, length_counts.get(length, 1) - 1)
        )
        fingerprint = _get(finding, "fingerprint")
        if fingerprint:
            # Uniformity only matters *across different hosts* on the same
            # scheme.  A host serving the same page over both HTTP and HTTPS is
            # completely normal, and penalising it made small legitimate sites
            # look suspicious.
            resolved.setdefault(
                "shared_fingerprints",
                max(
                    0,
                    _cross_host_duplicates(str(fingerprint), scheme_hosts),
                ),
            )
        else:
            resolved.setdefault("shared_fingerprints", 0)
        breakdown = score_finding(finding, **resolved)
        scored.append((finding, breakdown))

    scored.sort(key=lambda pair: (-pair[1].score, _sort_key(pair[0])))
    return scored


def _cross_host_duplicates(
    fingerprint: str,
    scheme_hosts: dict[str, set[tuple[str, str]]],
) -> int:
    """Largest number of *other hosts* sharing this fingerprint on one scheme.

    Grouped by scheme on purpose: ``example.com`` and ``www.example.com`` both
    serving the same page over HTTPS is a real uniformity signal, but the same
    host answering identically over HTTP *and* HTTPS is not — that is just one
    site reachable two ways.  Taking the per-scheme maximum catches the former
    without penalising the latter.
    """
    pairs = scheme_hosts.get(fingerprint) or set()
    if not pairs:
        return 0
    per_scheme: dict[str, set[str]] = {}
    for scheme, host in pairs:
        per_scheme.setdefault(scheme, set()).add(host)
    return max((len(hosts) - 1 for hosts in per_scheme.values()), default=0)


def confidence_summary(
    breakdowns: Iterable[ConfidenceBreakdown],
) -> dict[str, int]:
    """Count breakdowns by label — used for the scan summary line."""
    summary = {"high": 0, "medium": 0, "low": 0}
    for breakdown in breakdowns:
        summary[breakdown.label] = summary.get(breakdown.label, 0) + 1
    return summary
