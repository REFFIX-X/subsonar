"""Fingerprinting: favicon hashing, technology detection, data-file probing.

This module is deliberately **self-contained**: it never imports
:mod:`subsonar.core.web_probe` (so it cannot create an import cycle with the
engine workstream), it never mutates the object it is handed, and every public
entry point is exception-free — a hostile, missing or broken HTTP session can
only ever produce a smaller result, never a raised exception.

Three independent pieces of evidence are collected per interface:

``favicon_hash``
    Shodan-compatible favicon hash.  Shodan computes ``mmh3.hash()`` over the
    **MIME base64** encoding of ``/favicon.ico`` (76-column, newline
    terminated), not over the raw bytes and not over plain ``b64encode``.  That
    detail is what makes a hash comparable between this scanner and Shodan, so
    :func:`favicon_base64` uses :func:`base64.encodebytes` and the difference is
    covered by a test.
``technologies``
    Matches from the :mod:`subsonar.core.signatures` table across header
    names/values, body, cookies, ``<meta name="generator">``, favicon hash and
    probed paths.
``data_files`` / ``interesting_paths``
    HEAD-then-GET status probes of well-known paths.  For ``/.env``,
    ``/.git/config`` and friends this is a **capability check**: the status code
    is recorded and the body is never read, never stored and never returned.
    That is enforced structurally — those probes run with ``read_limit=0``, so
    the response body is not touched at all.

Response headers are read from the session that already belongs to the caller's
prober (see :func:`fingerprint` for the exact accessor order) so that the
anonymous-resolver privacy guarantee of :class:`~subsonar.core.web_probe.WebProbe`
is preserved.  This module never opens an HTTP session of its own — doing so
would silently fall back to the OS resolver.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .events import BUS, EventBus
from .signatures import (
    DEFAULT_PATH_STATUS,
    CompiledSignature,
    Signature,
    compile_signature,
    compile_signatures,
)

__all__ = [
    "DATA_PATHS",
    "INTERESTING_PATHS",
    "SECURITY_HEADERS",
    "FAVICON_MAX_BYTES",
    "MAX_HTML_BYTES",
    "FAVICON_PATH",
    "PROBE_CONCURRENCY",
    "TechMatch",
    "FingerprintResult",
    "murmur3_x86_32",
    "to_signed32",
    "favicon_base64",
    "favicon_hash",
    "extract_security_headers",
    "detect_technologies",
    "fetch_favicon",
    "fingerprint",
]

#: Well-known data files probed for their HTTP status only.
DATA_PATHS: tuple[str, ...] = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.git/config",
    "/.env",
    "/.svn/entries",
    "/server-status",
    "/phpinfo.php",
    "/.DS_Store",
    "/crossdomain.xml",
)

#: Additional paths worth a status probe — they either identify a product or
#: expose an administrative surface.  Only non-404 answers are reported.
INTERESTING_PATHS: tuple[str, ...] = (
    "/wp-login.php",
    "/wp-admin/",
    "/administrator/",
    "/phpmyadmin/",
    "/adminer.php",
    "/manager/html",
    "/jenkins/",
    "/actuator/health",
    "/graphql",
    "/openapi.json",
    "/swagger-ui.html",
    "/server-info",
    "/login",
)

#: Header allow-list for :attr:`FingerprintResult.headers`.  ``Set-Cookie`` is
#: reported separately and **by name only**.
SECURITY_HEADERS: tuple[str, ...] = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Server",
    "X-Powered-By",
    "Via",
    "CF-RAY",
)

#: Cookie attributes that can appear before the ``name=value`` pair.
_COOKIE_ATTRIBUTES = frozenset(
    {"expires", "path", "domain", "max-age", "samesite", "comment", "version"}
)

#: Hard cap on a favicon we are willing to hash.
FAVICON_MAX_BYTES = 256 * 1024

#: Hard cap on the HTML we use for body matching.
MAX_HTML_BYTES = 96 * 1024

#: Default favicon location.
FAVICON_PATH = "/favicon.ico"

#: Parallelism used for the (independent) data-file status probes.
PROBE_CONCURRENCY = 8

#: Statuses that make an "interesting path" worth reporting.
_INTERESTING_STATUS = frozenset({200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405})

#: Statuses that mean "this method is not supported, try another one".
_METHOD_UNSUPPORTED = frozenset({405, 501})

_META_GENERATOR_RES = (
    re.compile(
        r"""<meta[^>]+name=["']?generator["']?[^>]*content=["']([^"']*)["']""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""<meta[^>]+content=["']([^"']*)["'][^>]*name=["']?generator["']?""",
        re.IGNORECASE,
    ),
)


# --------------------------------------------------------------------------- #
# MurmurHash3 x86 32-bit (pure Python, no dependency)
# --------------------------------------------------------------------------- #


def murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, returned **unsigned**.

    This is the exact algorithm ``mmh3.hash()`` implements
    (Austin Appleby's MurmurHash3_x86_32): little-endian 4-byte blocks,
    ``c1 = 0xCC9E2D51``, ``c2 = 0x1B873593``, a 13/19-bit rotate per block and
    the ``fmix32`` finaliser.  Implemented here so the scanner gains Shodan
    favicon compatibility without a new dependency.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("murmur3_x86_32 expects bytes")
    blob = bytes(data)
    length = len(blob)
    h1 = seed & 0xFFFFFFFF
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    nblocks = length // 4
    for index in range(nblocks):
        k1 = int.from_bytes(blob[index * 4 : index * 4 + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = blob[nblocks * 4 :]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 & 0xFFFFFFFF


def to_signed32(value: int) -> int:
    """Reinterpret an unsigned 32-bit value as a signed one (``mmh3`` does)."""
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def favicon_base64(data: bytes) -> bytes:
    """Shodan's favicon encoding: MIME base64 (76 columns + trailing newline).

    ``base64.b64encode`` (single line) produces a **different** hash, which is
    why Shodan queries cannot be reproduced with it.
    """
    return base64.encodebytes(bytes(data))


def favicon_hash(data: bytes) -> str:
    """Shodan-compatible favicon hash, as a *signed* 32-bit decimal string.

    ``str(mmh3.hash(base64.encodebytes(data)))`` — the exact expression used by
    Shodan's own favicon tooling.
    """
    return str(to_signed32(murmur3_x86_32(favicon_base64(data))))


# --------------------------------------------------------------------------- #
# Result containers
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class TechMatch:
    """One detected technology, with the evidence that proves it."""

    name: str
    category: str
    evidence: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "category": self.category, "evidence": self.evidence}


@dataclass(slots=True)
class FingerprintResult:
    """Everything fingerprinting learned about one ``scheme://host:port``."""

    favicon_hash: str | None = None
    technologies: list[TechMatch] = field(default_factory=list)
    data_files: dict[str, int] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    interesting_paths: dict[str, int] = field(default_factory=dict)
    server: str | None = None
    notes: list[str] = field(default_factory=list)

    # -- convenience ------------------------------------------------------- #
    @property
    def names(self) -> list[str]:
        return [tech.name for tech in self.technologies]

    def in_category(self, category: str) -> list[TechMatch]:
        return [tech for tech in self.technologies if tech.category == category]

    def to_dict(self) -> dict[str, Any]:
        return {
            "favicon_hash": self.favicon_hash,
            "technologies": [tech.to_dict() for tech in self.technologies],
            "data_files": dict(self.data_files),
            "headers": dict(self.headers),
            "interesting_paths": dict(self.interesting_paths),
            "server": self.server,
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- #
# Small internals: URLs, headers, responses
# --------------------------------------------------------------------------- #


def _build_url(scheme: str, host: str, port: int, path: str) -> str:
    scheme = (scheme or "http").lower()
    if not path.startswith("/"):
        path = "/" + path
    authority = host
    if ":" in host and not host.startswith("["):
        authority = f"[{host}]"
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    if port and not default_port:
        authority = f"{authority}:{port}"
    return f"{scheme}://{authority}{path}"


def _norm_headers(raw: Any) -> list[tuple[str, str]]:
    """Normalise any header container into ``[(name, value), ...]``.

    Duplicates are preserved (``Set-Cookie`` depends on it).
    """
    if raw is None:
        return []
    items: Any = None
    getter = getattr(raw, "items", None)
    if callable(getter):
        try:
            items = list(getter())
        except Exception:
            items = None
    if items is None and isinstance(raw, Mapping):
        items = list(raw.items())
    if items is None and isinstance(raw, Iterable) and not isinstance(raw, (str, bytes)):
        items = list(raw)
    if items is None:
        return []
    pairs: list[tuple[str, str]] = []
    for item in items:
        try:
            name, value = item
        except Exception:
            continue
        try:
            pairs.append((str(name), str(value)))
        except Exception:  # pragma: no cover - defensive
            continue
    return pairs


def _header_values(headers: Sequence[tuple[str, str]], name: str) -> list[str]:
    wanted = name.lower()
    return [value for key, value in headers if key.lower() == wanted]


def _first(values: Sequence[Any] | None) -> Any | None:
    if not values:
        return None
    return values[0]


def _header_names(headers: Sequence[tuple[str, str]]) -> list[str]:
    return [key for key, _ in headers]


def _cookie_names(headers: Sequence[tuple[str, str]]) -> list[str]:
    """Cookie **names** from every ``Set-Cookie`` value (never the values)."""
    names: list[str] = []
    for key, value in headers:
        if key.lower() != "set-cookie":
            continue
        for part in str(value).split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            candidate = part.split("=", 1)[0].strip()
            if candidate and candidate.lower() not in _COOKIE_ATTRIBUTES:
                if candidate not in names:
                    names.append(candidate)
            break
    return names


def _clip(value: Any, limit: int = 60) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _coerce_status(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass(slots=True)
class _Fetched:
    """One completed request: status, headers and (optionally) body."""

    status: int | None
    headers: list[tuple[str, str]]
    body: bytes = b""
    truncated: bool = False


def _filter_kwargs(func: Any, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Keep only the keyword arguments *func* can actually accept.

    Fake/duck-typed sessions are common in tests and third-party probers may
    have narrower signatures than ``aiohttp``; passing an unsupported keyword
    would turn a working probe into a ``TypeError``.
    """
    try:
        params = inspect.signature(func).parameters
    except (TypeError, ValueError):  # pragma: no cover - C callables
        return dict(kwargs)
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return dict(kwargs)
    return {key: value for key, value in kwargs.items() if key in params}


async def _read_limited(response: Any, limit: int) -> tuple[bytes, bool]:
    """Read at most *limit* bytes; the second element flags truncation."""
    chunks: list[bytes] = []
    total = 0
    stream = getattr(response, "content", None)
    reader = getattr(stream, "read", None)
    if callable(reader):
        try:
            while total <= limit:
                chunk = await reader(min(16384, limit + 1 - total))
                if not chunk:
                    break
                chunk = bytes(chunk)
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    return b"".join(chunks)[:limit], True
            return b"".join(chunks)[:limit], False
        except TypeError:
            pass  # read() takes no size argument
        except Exception:
            return b"".join(chunks)[:limit], True
    plain = getattr(response, "read", None)
    if callable(plain):
        try:
            data = bytes(await plain())
        except Exception:
            return b"".join(chunks)[:limit], True
        return data[:limit], len(data) > limit
    return b"".join(chunks)[:limit], False


async def _fetch(
    session: Any,
    url: str,
    *,
    timeout: float,
    method: str = "get",
    allow_redirects: bool = True,
    max_redirects: int = 6,
    read_limit: int = 0,
) -> _Fetched | None:
    """Issue exactly one request through *session*, or return ``None``.

    ``read_limit=0`` means "status only": the body is left unread so sensitive
    paths (``/.env``, ``/.git/config``) can never be captured.  The whole
    request — including the read — is bounded by ``timeout`` via
    :func:`asyncio.wait_for`, so a session that ignores the ``timeout`` keyword
    cannot hang the caller.
    """
    request = getattr(session, method, None)
    if not callable(request):
        return None
    kwargs = _filter_kwargs(
        request,
        {
            "allow_redirects": allow_redirects,
            "max_redirects": max_redirects,
            "timeout": timeout,
        },
    )

    async def _run() -> _Fetched | None:
        pending = request(url, **kwargs)
        if inspect.isawaitable(pending) and not hasattr(pending, "__aenter__"):
            pending = await pending
        if hasattr(pending, "__aenter__"):
            async with pending as response:
                return await _consume(response, read_limit)
        return await _consume(pending, read_limit)

    try:
        budget = float(timeout)
    except (TypeError, ValueError):
        budget = 5.0
    try:
        return await asyncio.wait_for(_run(), timeout=max(0.05, budget))
    except Exception:
        return None


async def _consume(response: Any, read_limit: int) -> _Fetched:
    status = _coerce_status(getattr(response, "status", None))
    if status is None:
        status = _coerce_status(getattr(response, "status_code", None))
    headers = _norm_headers(getattr(response, "headers", None))
    if read_limit <= 0:
        return _Fetched(status=status, headers=headers)
    body, truncated = await _read_limited(response, read_limit)
    return _Fetched(status=status, headers=headers, body=body, truncated=truncated)


async def _path_status(session: Any, url: str, *, timeout: float) -> int | None:
    """HEAD first, GET fallback — returns the status of *url* only."""
    methods: list[str] = []
    if callable(getattr(session, "head", None)):
        methods.append("head")
    if callable(getattr(session, "get", None)):
        methods.append("get")
    for method in methods:
        fetched = await _fetch(
            session,
            url,
            timeout=timeout,
            method=method,
            allow_redirects=False,
            read_limit=0,
        )
        if fetched is None or fetched.status is None:
            continue
        if method == "head" and fetched.status in _METHOD_UNSUPPORTED:
            continue
        return fetched.status
    return None


async def _probe_path_statuses(
    session: Any,
    scheme: str,
    host: str,
    port: int,
    paths: Sequence[str],
    *,
    timeout: float,
    concurrency: int = PROBE_CONCURRENCY,
) -> dict[str, int]:
    """Probe every path concurrently, bounded by a per-call semaphore."""
    if session is None or not paths:
        return {}
    limiter = asyncio.Semaphore(max(1, concurrency))

    async def one(path: str) -> tuple[str, int | None]:
        try:
            async with limiter:
                status = await _path_status(
                    session, _build_url(scheme, host, port, path), timeout=timeout
                )
            return path, status
        except Exception:
            return path, None

    results = await asyncio.gather(*(one(path) for path in paths), return_exceptions=True)
    out: dict[str, int] = {}
    for item in results:
        if isinstance(item, BaseException) or not isinstance(item, tuple):
            continue
        path, status = item
        if status is not None:
            out[path] = status
    return out


def _extract_meta_generator(body: str) -> str | None:
    for pattern in _META_GENERATOR_RES:
        match = pattern.search(body)
        if match:
            value = match.group(1).strip()
            if value:
                return value[:120]
    return None


def _decode(body: bytes, content_type: str | None = None) -> str:
    charset = "utf-8"
    if content_type:
        match = re.search(r"charset=([\w\-]+)", content_type, re.IGNORECASE)
        if match:
            charset = match.group(1)
    for candidate in (charset, "utf-8", "latin-1"):
        try:
            return body.decode(candidate, "replace")
        except (LookupError, TypeError):  # pragma: no cover - bad charset label
            continue
    return body.decode("utf-8", "replace")  # pragma: no cover


# --------------------------------------------------------------------------- #
# Header extraction
# --------------------------------------------------------------------------- #


def extract_security_headers(headers: Any) -> dict[str, str]:
    """Return the interesting subset of *headers*.

    ``Set-Cookie`` is represented by its cookie **names** only — a session
    token must never reach a report.  Unknown/absent headers are omitted.
    """
    pairs = _norm_headers(headers)
    out: dict[str, str] = {}
    for name in SECURITY_HEADERS:
        values = [value for value in _header_values(pairs, name) if value.strip()]
        if not values:
            continue
        out[name] = "; ".join(_clip(value, 300) for value in values)
    cookie_names = _cookie_names(pairs)
    if cookie_names:
        out["Set-Cookie"] = ", ".join(cookie_names)
    return out


# --------------------------------------------------------------------------- #
# Technology detection
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class _TechContext:
    headers: list[tuple[str, str]]
    body: str
    cookie_names: list[str]
    meta_generator: str | None
    favicon_hash: str | None
    paths: dict[str, int]


def _resolve_signatures(
    signatures: Sequence[Signature | CompiledSignature] | None,
) -> tuple[CompiledSignature, ...]:
    if signatures is None:
        return compile_signatures()
    out: list[CompiledSignature] = []
    for item in signatures:
        if isinstance(item, CompiledSignature):
            out.append(item)
        elif isinstance(item, Signature):
            out.append(compile_signature(item))
        else:  # pragma: no cover - defensive
            raise TypeError(f"unsupported signature type: {type(item)!r}")
    return tuple(out)


def _evidence_for(compiled: CompiledSignature, context: _TechContext) -> list[str]:
    """All evidence strings for one signature (deduplicated, order stable)."""
    signature = compiled.signature
    evidence: list[str] = []

    def add(text: str) -> None:
        if text and text not in evidence:
            evidence.append(text)

    if signature.header:
        values = _header_values(context.headers, signature.header)
        if signature.header_re is not None:
            pattern = compiled.header_re
            if pattern is not None:
                for value in values:
                    if pattern.search(value):
                        add(f"header {signature.header}: {_clip(value)!r}")
        elif values:
            add(f"header {signature.header} present")

    pattern = compiled.header_name_re
    if pattern is not None:
        for name, value in context.headers:
            if pattern.search(name):
                add(f"header {name}: {_clip(value)!r}")

    pattern = compiled.body_re
    if pattern is not None and context.body:
        match = pattern.search(context.body)
        if match:
            add(f"body matches {_clip(match.group(0), 40)!r}")

    if signature.cookie:
        wanted = signature.cookie.lower()
        for name in context.cookie_names:
            if name.lower() == wanted:
                add(f"cookie {name}")

    pattern = compiled.cookie_re
    if pattern is not None:
        for name in context.cookie_names:
            if pattern.search(name):
                add(f"cookie {name}")

    pattern = compiled.meta_re
    if pattern is not None and context.meta_generator:
        if pattern.search(context.meta_generator):
            add(f"meta generator {_clip(context.meta_generator, 40)!r}")

    if signature.favicon is not None and context.favicon_hash is not None:
        if str(signature.favicon) == str(context.favicon_hash):
            add(f"favicon hash {signature.favicon}")

    if signature.path and context.paths:
        status = context.paths.get(signature.path)
        allowed = signature.path_status or DEFAULT_PATH_STATUS
        if status is not None and status in allowed:
            add(f"GET {signature.path} -> {status}")

    return evidence


def detect_technologies(
    *,
    headers: Any = (),
    body: bytes | str = b"",
    cookie_names: Iterable[str] = (),
    favicon_hash: str | None = None,
    paths: Mapping[str, int] | None = None,
    meta_generator: str | None = None,
    signatures: Sequence[Signature | CompiledSignature] | None = None,
) -> list[TechMatch]:
    """Match every signature against one response's evidence.

    Pure function: no I/O, no globals mutated, safe to call concurrently.
    Results are deduplicated by ``(name, category)`` with the evidence of
    duplicate signatures merged.
    """
    compiled_table = _resolve_signatures(signatures)
    if not compiled_table:
        return []
    if isinstance(body, (bytes, bytearray, memoryview)):
        body_text = bytes(body).decode("utf-8", "replace")
    else:
        body_text = str(body)
    context = _TechContext(
        headers=_norm_headers(headers),
        body=body_text,
        cookie_names=[str(name) for name in cookie_names],
        meta_generator=meta_generator,
        favicon_hash=str(favicon_hash) if favicon_hash is not None else None,
        paths={str(k): v for k, v in dict(paths or {}).items()},
    )
    if not (
        context.headers
        or context.body
        or context.cookie_names
        or context.meta_generator
        or context.favicon_hash
        or context.paths
    ):
        return []

    merged: dict[tuple[str, str], TechMatch] = {}
    for compiled in compiled_table:
        evidence = _evidence_for(compiled, context)
        if not evidence:
            continue
        key = (compiled.name, compiled.category)
        joined = " · ".join(evidence[:3])
        if len(evidence) > 3:
            joined += f" (+{len(evidence) - 3} more)"
        existing = merged.get(key)
        if existing is None:
            merged[key] = TechMatch(compiled.name, compiled.category, _clip(joined, 240))
        else:
            combined = f"{existing.evidence}; {joined}"
            merged[key] = TechMatch(
                existing.name, existing.category, _clip(combined, 240)
            )
    return list(merged.values())


# --------------------------------------------------------------------------- #
# Favicon
# --------------------------------------------------------------------------- #


async def fetch_favicon(
    session: Any,
    scheme: str,
    host: str,
    port: int,
    *,
    timeout: float,
    path: str = FAVICON_PATH,
) -> tuple[bytes | None, str | None]:
    """Fetch ``/favicon.ico``; returns ``(bytes, content_type)``.

    Follows redirects, refuses to hash anything larger than
    :data:`FAVICON_MAX_BYTES` (a truncated icon would produce a hash that can
    never match Shodan), and never raises.
    """
    try:
        if session is None:
            return None, None
        fetched = await _fetch(
            session,
            _build_url(scheme, host, port, path),
            timeout=timeout,
            method="get",
            allow_redirects=True,
            read_limit=FAVICON_MAX_BYTES,
        )
        if fetched is None or fetched.status is None:
            return None, None
        if not 200 <= fetched.status < 300:
            return None, None
        if not fetched.body or fetched.truncated:
            return None, None
        content_types = _header_values(fetched.headers, "Content-Type")
        return fetched.body, (content_types[0] if content_types else None)
    except Exception:
        return None, None


# --------------------------------------------------------------------------- #
# Live-log helper
# --------------------------------------------------------------------------- #


class _Emitter:
    """Best-effort live-log emitter — a broken bus must never break a scan."""

    __slots__ = ("_bus",)

    def __init__(self, bus: EventBus | None) -> None:
        self._bus = bus

    def emit(self, message: str, severity: str = "info", **data: Any) -> None:
        bus = self._bus
        if bus is None:
            return
        emit = getattr(bus, "emit", None)
        if not callable(emit):
            return
        try:
            emit(message, severity, "fingerprint", **data)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Session + root-response resolution
# --------------------------------------------------------------------------- #


async def _resolve_session(probe: Any) -> Any | None:
    """Find the HTTP session that belongs to *probe*.

    Order: a public ``session`` attribute, the private ``_session`` that
    :class:`~subsonar.core.web_probe.WebProbe` keeps, the probe itself if it
    already *is* a session, then ``await probe.start()`` followed by a re-check.
    A session of our own is never created — it would use the OS resolver.
    """
    if probe is None:
        return None

    def candidate_from(target: Any) -> Any | None:
        candidate = getattr(target, "session", None)
        if candidate is None:
            candidate = getattr(target, "_session", None)
        if candidate is None or getattr(candidate, "closed", False):
            return None
        if not callable(getattr(candidate, "get", None)):
            return None
        return candidate

    found = candidate_from(probe)
    if found is not None:
        return found
    if callable(getattr(probe, "get", None)) and callable(getattr(probe, "head", None)):
        return probe
    starter = getattr(probe, "start", None)
    if callable(starter):
        try:
            await starter()
        except Exception:
            return None
        return candidate_from(probe)
    return None


async def _call_probe(
    probe: Any, host: str, ip: str, port: int, scheme: str, timeout: float
) -> Any | None:
    """Best-effort ``probe.probe(...)`` used only when no session is reachable."""
    fn = getattr(probe, "probe", None)
    if not callable(fn):
        return None
    kwargs = _filter_kwargs(fn, {"schemes": [scheme]})
    try:
        pending = fn(host, ip, port, **kwargs)
        if inspect.isawaitable(pending):
            pending = await asyncio.wait_for(pending, timeout=max(0.05, timeout * 2 + 1))
        return pending
    except Exception:
        return None


@dataclass(slots=True)
class _RootFetch:
    status: int | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    truncated: bool = False
    meta: Any = None
    source: str = "none"


async def _fetch_root(
    probe: Any,
    session: Any,
    scheme: str,
    host: str,
    ip: str,
    port: int,
    *,
    timeout: float,
    meta: Any = None,
) -> _RootFetch:
    """One GET of ``/`` plus a fallback to whatever the caller's prober knows."""
    out = _RootFetch()
    declared = getattr(probe, "last_response_headers", None)
    declared_headers: list[tuple[str, str]] = []
    if declared is not None and not isinstance(declared, (str, bytes)):
        declared_headers = _norm_headers(declared)

    if session is not None:
        fetched = await _fetch(
            session,
            _build_url(scheme, host, port, "/"),
            timeout=timeout,
            method="get",
            allow_redirects=True,
            read_limit=MAX_HTML_BYTES,
        )
        if fetched is not None:
            out.status = fetched.status
            out.headers = fetched.headers
            out.body = fetched.body
            out.truncated = fetched.truncated
            out.source = "session"

    if out.status is None and meta is None:
        meta = await _call_probe(probe, host, ip, port, scheme, timeout)
        if meta is not None:
            out.source = "probe"
    out.meta = meta

    if out.status is None and meta is not None:
        out.status = _coerce_status(getattr(meta, "status", None))
    if meta is not None and not out.body:
        snippet = getattr(meta, "body_snippet", None)
        if isinstance(snippet, str) and snippet:
            out.body = snippet.encode("utf-8", "replace")
    if not out.headers and declared_headers:
        out.headers = declared_headers
        if out.source == "none":
            out.source = "headers"
    elif not out.headers and meta is not None:
        meta_headers = _norm_headers(getattr(meta, "headers", None))
        if meta_headers:
            out.headers = meta_headers
    if out.source == "none" and out.status is not None:
        out.source = "meta"
    return out


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


async def fingerprint(
    probe: Any,
    scheme: str,
    host: str,
    ip: str,
    port: int,
    *,
    bus: EventBus | None = None,
    timeout: float = 5.0,
    meta: Any = None,
    fetch_icon: bool = True,
    probe_paths: bool = True,
) -> FingerprintResult:
    """Fingerprint one ``scheme://host:port``.

    * ``probe`` — anything that carries an HTTP session: a
      :class:`~subsonar.core.web_probe.WebProbe`, a bare ``aiohttp`` session, or
      a test double.  The session is discovered, never created (see
      :func:`_resolve_session`), so the caller's resolver/TLS policy is kept.
    * ``meta`` — an already-obtained ``WebProbeResult``.  Supplying it avoids a
      second ``GET /``; without it and without a reachable session the prober's
      own ``probe()`` method is used.

    Never raises: every network step is independently guarded, so the worst case
    is a result with fewer fields populated (recorded in ``notes``).
    """
    emitter = _Emitter(bus if bus is not None else BUS)
    result = FingerprintResult()
    emitter.emit(
        f"Fingerprinting ://{host}:{port} ({scheme})...",
        "info",
        host=host,
        port=port,
        ip=ip,
    )
    try:
        session = await _resolve_session(probe)
        root = await _fetch_root(
            probe, session, scheme, host, ip, port, timeout=timeout, meta=meta
        )
        result.server = _first(_header_values(root.headers, "Server")) or (
            getattr(root.meta, "server", None) if root.meta is not None else None
        )
        result.headers = extract_security_headers(root.headers)

        content_type = _first(_header_values(root.headers, "Content-Type")) or (
            getattr(root.meta, "content_type", None) if root.meta is not None else None
        )
        body_text = _decode(root.body, content_type) if root.body else ""
        meta_generator = _extract_meta_generator(body_text) if body_text else None

        if root.status is None:
            result.notes.append(
                "no HTTP response could be read — status, headers and body were "
                "not fingerprinted"
            )
        elif root.source in ("probe", "headers", "meta"):
            result.notes.append(
                "response details came from the caller's probe result"
                + (
                    " (no live session was reachable)"
                    if root.source in ("probe", "meta")
                    else ""
                )
            )
        if session is None:
            result.notes.append(
                "no HTTP session was reachable on the prober — data-file and "
                "favicon probing skipped"
            )
        if root.truncated:
            result.notes.append(f"body truncated at {MAX_HTML_BYTES} bytes")
        if root.headers and not result.server:
            result.notes.append("no Server header returned")

        if fetch_icon and session is not None:
            icon, icon_type = await fetch_favicon(
                session, scheme, host, port, timeout=timeout
            )
            if icon:
                result.favicon_hash = favicon_hash(icon)
                result.notes.append(
                    f"favicon.ico hashed ({len(icon)} bytes, "
                    f"{icon_type or 'unknown type'}) -> {result.favicon_hash}"
                )
            else:
                result.notes.append(
                    "favicon.ico unavailable (missing, too large to hash, or "
                    "the request failed)"
                )

        if probe_paths and session is not None:
            statuses = await _probe_path_statuses(
                session, scheme, host, port, DATA_PATHS, timeout=timeout
            )
            result.data_files = statuses
            result.notes.append(
                f"{len(statuses)}/{len(DATA_PATHS)} well-known data files answered "
                "(status only — no body was read for /.env or /.git/config)"
            )
            extra = await _probe_path_statuses(
                session, scheme, host, port, INTERESTING_PATHS, timeout=timeout
            )
            result.interesting_paths = {
                path: status
                for path, status in extra.items()
                if status in _INTERESTING_STATUS
            }

        path_map: dict[str, int] = dict(result.data_files)
        path_map.update(result.interesting_paths)
        result.technologies = detect_technologies(
            headers=root.headers,
            body=body_text,
            cookie_names=_cookie_names(root.headers),
            favicon_hash=result.favicon_hash,
            paths=path_map,
            meta_generator=meta_generator,
        )

        by_category: dict[str, int] = {}
        for tech in result.technologies:
            by_category[tech.category] = by_category.get(tech.category, 0) + 1
        summary = ", ".join(
            f"{count} {category}" for category, count in sorted(by_category.items())
        )
        emitter.emit(
            f"Fingerprint ://{host}:{port} — {len(result.technologies)} technologies"
            + (f" ({summary})" if summary else "")
            + f", favicon {result.favicon_hash or 'n/a'}"
            + f", {len(result.data_files)} data files",
            "success" if result.technologies else "info",
            host=host,
            port=port,
            ip=ip,
            server=result.server,
            favicon_hash=result.favicon_hash,
            technologies=len(result.technologies),
            data_files=len(result.data_files),
        )
    except Exception as exc:  # pragma: no cover - last-ditch guard
        result.notes.append(f"fingerprinting aborted: {exc.__class__.__name__}: {exc}")
        emitter.emit(
            f"Fingerprinting ://{host}:{port} aborted — {exc.__class__.__name__}",
            "warn",
            host=host,
            port=port,
            ip=ip,
        )
    return result
