"""Asynchronous HTTP/HTTPS verification and metadata extraction.

Every candidate host is verified with ``aiohttp`` — the exact probe order
depends on the port (TLS-first ports try ``https`` first).  The module extracts
the HTTP status, ``<title>``, ``Server`` header, redirect chain, TLS details and
a **wildcard fingerprint** used to suppress soft-404 false positives.

Name resolution is performed by :class:`AnonymousResolver` through a custom
aiohttp resolver, so the OS resolver (and therefore Google/Cloudflare, if the
host machine uses them) is never used for web probes either.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Sequence
from urllib.parse import urljoin, urlsplit

try:  # pragma: no cover - exercised indirectly
    import aiohttp
    from aiohttp.abc import AbstractResolver
    from aiohttp.resolver import ResolveResult

    AIOHTTP_AVAILABLE = True
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore[assignment]
    AbstractResolver = object  # type: ignore[assignment,misc]
    ResolveResult = dict  # type: ignore[assignment,misc]
    AIOHTTP_AVAILABLE = False

from .dns import AnonymousResolver
from .events import BUS, EventBus

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_META_REFRESH_RE = re.compile(
    rb"""<meta[^>]+http-equiv=["']?refresh["']?[^>]+url=([^"'>\s]+)""", re.IGNORECASE
)
_CHARSET_RE = re.compile(rb"""charset=["']?([\w-]+)""", re.IGNORECASE)
_TAG_RE = re.compile(rb"<[^>]+>")
_WS_RE = re.compile(rb"\s+")

MAX_BODY_BYTES = 64 * 1024

#: Read in 8 KiB chunks and stop as soon as the document head is complete —
#: everything subsonar extracts (title, meta, signatures) lives above it.
_READ_CHUNK = 8192
_HEAD_END_RE = re.compile(rb"</head\s*>", re.IGNORECASE)


@dataclass(slots=True)
class WebProbeResult:
    """Result of one HTTP/HTTPS verification."""

    host: str
    ip: str
    port: int
    scheme: str
    url: str
    status: int | None = None
    title: str | None = None
    server: str | None = None
    content_type: str | None = None
    content_length: int = 0
    redirect_chain: list[str] = field(default_factory=list)
    final_url: str | None = None
    tls: bool = False
    tls_version: str | None = None
    fingerprint: str | None = None
    body_snippet: str | None = None
    latency_ms: float = 0.0
    ok: bool = False
    kind: str = "interface"
    initial_status: int | None = None
    redirected: bool = False
    #: ``Content-Length`` the server declared, when it sent one.  Kept separate
    #: from :attr:`content_length`, which is what subsonar actually read.
    declared_length: int | None = None
    error: str | None = None
    attempted_schemes: list[str] = field(default_factory=list)

    @property
    def clickable_url(self) -> str:
        """Actionable link: ``http(s)://domain:port``."""
        return self.url

    def to_dict(self) -> dict[str, Any]:
        return {
            "subdomain": self.host,
            "ip": self.ip,
            "port": self.port,
            "scheme": self.scheme,
            "url": self.url,
            "status": self.status,
            "title": self.title,
            "server": self.server,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "declared_length": self.declared_length,
            "redirect_chain": self.redirect_chain,
            "final_url": self.final_url,
            "tls": self.tls,
            "tls_version": self.tls_version,
            "fingerprint": self.fingerprint,
            "latency_ms": round(self.latency_ms, 1),
            "ok": self.ok,
            "kind": self.kind,
            "initial_status": self.initial_status,
            "redirected": self.redirected,
            "error": self.error,
        }


class AnonymousAiohttpResolver(AbstractResolver):  # type: ignore[misc]
    """Routes every aiohttp DNS lookup through :class:`AnonymousResolver`."""

    def __init__(self, resolver: AnonymousResolver) -> None:
        self._resolver = resolver

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[dict[str, Any]]:
        """Resolve through the anonymous pool.

        ``family`` is honoured: ``AF_UNSPEC`` returns both address families,
        ``AF_INET``/``AF_INET6`` restrict to one.  aiohttp uses this for its
        happy-eyeballs and IPv4-retry paths, so returning the wrong family here
        makes those retries fail for no reason.
        """
        result = await self._resolver.resolve(host, log=False)
        entries: list[dict[str, Any]] = []
        for addr in result.addresses:
            is_v6 = ":" in addr
            if family == socket.AF_INET and is_v6:
                continue
            if family == socket.AF_INET6 and not is_v6:
                continue
            entries.append(
                {
                    "hostname": host,
                    "host": addr,
                    "port": port,
                    "family": socket.AF_INET6 if is_v6 else socket.AF_INET,
                    "proto": socket.IPPROTO_TCP,
                    "flags": 0,
                }
            )
        if not entries and result.addresses:
            # The requested family was unavailable — fall back to whatever the
            # anonymous resolver returned rather than failing the connection.
            for addr in result.addresses:
                is_v6 = ":" in addr
                entries.append(
                    {
                        "hostname": host,
                        "host": addr,
                        "port": port,
                        "family": socket.AF_INET6 if is_v6 else socket.AF_INET,
                        "proto": socket.IPPROTO_TCP,
                        "flags": 0,
                    }
                )
        if not entries:
            raise OSError(f"anonymous resolver could not resolve {host}")
        return entries

    async def close(self) -> None:
        return None


class WebProbe:
    """Shared aiohttp based HTTP/HTTPS prober."""

    def __init__(
        self,
        *,
        resolver: AnonymousResolver | None = None,
        timeout: float = 4.0,
        concurrency: int = 60,
        bus: EventBus | None = None,
        verify_tls: bool = False,
        max_body: int = MAX_BODY_BYTES,
    ) -> None:
        self.resolver = resolver or AnonymousResolver()
        self.timeout = timeout
        self.bus = bus or BUS
        self.verify_tls = verify_tls
        self.max_body = max_body
        self._semaphore = asyncio.Semaphore(concurrency)
        self._session: Any | None = None
        self._connector: Any | None = None
        self.probes = 0

    # -- lifecycle --------------------------------------------------------- #
    async def start(self) -> None:
        if not AIOHTTP_AVAILABLE:
            self.bus.warn(
                "aiohttp is not installed — HTTP verification disabled"
            )
            return
        if self._session is not None:
            return
        ssl_context = ssl.create_default_context()
        if not self.verify_tls:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        self._connector = aiohttp.TCPConnector(
            resolver=AnonymousAiohttpResolver(self.resolver),
            limit=512,
            limit_per_host=16,
            ttl_dns_cache=300,
            ssl=ssl_context,
            force_close=False,
            # Anonymous probing must not leak through an OS/env proxy, and a
            # proxy would also break plain-HTTP probes with bogus SSL errors.
            use_dns_cache=True,
        )
        self._session = aiohttp.ClientSession(
            connector=self._connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout),
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 subsonar/1.0"
                ),
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "close",
            },
            trust_env=False,
        )

    async def close(self) -> None:
        if self._session is not None:
            try:
                await self._session.close()
            except Exception:  # pragma: no cover
                pass
            self._session = None
        self._connector = None

    async def __aenter__(self) -> "WebProbe":
        await self.start()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    # -- probing ----------------------------------------------------------- #
    async def probe_multi(
        self, host: str, ip: str, ports: Sequence[int]
    ) -> list[WebProbeResult]:
        """Probe several ports concurrently.

        Returns confirmed interfaces *and* redirect-only ports (``kind ==
        "redirect"``).  The engine decides whether a bounce is worth reporting as
        a fallback, so it must not be dropped here.
        """
        tasks = [asyncio.create_task(self.probe(host, ip, port)) for port in ports]
        results: list[WebProbeResult] = []
        for task in asyncio.as_completed(tasks):
            result = await task
            if result is not None and (result.ok or result.kind == "redirect"):
                results.append(result)
        results.sort(key=lambda r: (r.port, r.scheme))
        return results

    async def probe(
        self,
        host: str,
        ip: str,
        port: int,
        *,
        schemes: Sequence[str] | None = None,
    ) -> WebProbeResult:
        """Send a GET request to *host*:*port* and extract page metadata.

        If a plain HTTP probe comes back with the classic
        ``400 The plain HTTP request was sent to HTTPS port`` body, the port is
        TLS-only regardless of what the matrix assumed, so HTTPS is retried
        automatically before the port is written off.
        """
        order = tuple(schemes) if schemes else _scheme_order(port)
        tried: list[str] = []
        result: WebProbeResult | None = None
        fallback: WebProbeResult | None = None
        for scheme in order:
            result = await self._probe_scheme(host, ip, port, scheme)
            tried.append(scheme)
            if result.ok:
                break
            # Keep the first answer that actually came from this port (a real
            # status line) so the caller can classify and log it meaningfully.
            if fallback is None and result.status is not None:
                fallback = result
            if scheme == "http" and https_pending(result) and "https" not in tried:
                self.bus.http(
                    f"Port {port} speaks TLS only — upgrading ://{host}:{port} to "
                    f"https and retrying",
                    host=host,
                    port=port,
                    ip=ip,
                )
                result = await self._probe_scheme(host, ip, port, "https")
                tried.append("https")
                break
        assert result is not None
        if not result.ok and fallback is not None:
            result = fallback
        result.attempted_schemes = tried
        return result

    async def _probe_scheme(
        self, host: str, ip: str, port: int, scheme: str
    ) -> WebProbeResult:
        default_port = (scheme == "http" and port == 80) or (
            scheme == "https" and port == 443
        )
        url = f"{scheme}://{host}" + ("" if default_port else f":{port}")
        result = WebProbeResult(host=host, ip=ip, port=port, scheme=scheme, url=url)
        if self._session is None:
            await self.start()
        if self._session is None:
            result.error = "aiohttp unavailable"
            return result

        async with self._semaphore:
            self.probes += 1
            self.bus.bump("http_probes")
            started = time.perf_counter()
            try:
                async with self._session.get(
                    url,
                    allow_redirects=True,
                    max_redirects=6,
                    ssl=False if not self.verify_tls else None,
                ) as response:
                    # Confusingly, aiohttp releases a redirected response's body
                    # (it is not in connection._responses), so the *final*
                    # response must still be read first to drain the connection.
                    # We then report whichever hop belongs to the port we
                    # actually scanned.
                    body, truncated = await self._read_body(response)
                    hop = response.history[0] if response.history else response
                    result.status = hop.status
                    result.server = hop.headers.get("Server") or response.headers.get("Server")
                    result.content_type = hop.headers.get("Content-Type")
                    result.redirect_chain = [str(h.url) for h in response.history]
                    result.final_url = str(response.url)
                    result.initial_status = hop.status
                    result.redirected = bool(response.history)
                    if hop is not response:
                        # The scanned port only bounced us: use the redirect's
                        # own body so its title/length are never confused with
                        # the content served on the redirect target.
                        hop_body, hop_truncated = await self._read_body(hop)
                        body, truncated = hop_body, hop_truncated
                    # Bytes actually read (bounded by ``max_body``, stopping at
                    # ``</head>``) — deliberately not the server's
                    # ``Content-Length``, which is recorded separately.
                    result.content_length = len(body)
                    result.declared_length = _int_or_none(
                        hop.headers.get("Content-Length")
                    )
                    result.latency_ms = (time.perf_counter() - started) * 1000
                    title = extract_title(body, result.content_type)
                    result.title = title or _fallback_title(result)
                    result.body_snippet = _snippet(body)
                    result.tls = scheme == "https"
                    if result.tls:
                        ssl_object = response.connection and getattr(
                            response.connection, "transport", None
                        )
                        try:
                            ssl_obj = ssl_object.get_extra_info("ssl_object") if ssl_object else None
                            if ssl_obj is not None:
                                result.tls_version = ssl_obj.version()
                        except Exception:
                            result.tls_version = None
                    result.fingerprint = _fingerprint(result, body)
                    redirect_only = is_redirect_only(result)
                    result.ok = _is_web_interface(result, body)
                    if result.ok:
                        result.kind = classify_finding(result)
                    elif redirect_only:
                        result.kind = "redirect"
                    else:
                        result.kind = "rejected"
                    if result.title is None:
                        # Needs ``kind``/``final_url``, which are settled above.
                        result.title = _fallback_title(result)
                    hop = (
                        f" (via {result.initial_status} from "
                        f"{result.redirect_chain[0]})"
                        if result.redirected and result.initial_status
                        else ""
                    )
                    self.bus.http(
                        f"Sending GET request to {url}... Status: {result.status}{hop}"
                        + (f" · Title: {result.title!r}" if result.title else ""),
                        host=host,
                        port=port,
                        ip=ip,
                        url=url,
                        status=result.status,
                        initial_status=result.initial_status,
                        title=result.title,
                        kind=result.kind,
                    )
                    if result.ok and result.redirected:
                        self.bus.emit(
                            f"{host}:{port} redirects to {result.final_url} "
                            f"(same port — keeping the finding)",
                            "debug",
                            "http",
                            host=host,
                            port=port,
                        )
                    if redirect_only:
                        self.bus.filtered(
                            f"Filtered out ://{host} - Port {port} is redirect-only: "
                            f"{result.initial_status} → {result.final_url} (kept as a "
                            f"fallback for {host})",
                            host=host,
                            port=port,
                            ip=ip,
                        )
                    elif not result.ok:
                        self.bus.filtered(
                            f"Filtered out ://{host} - Port {port} responded "
                            f"without a web interface (status {result.status})",
                            host=host,
                            port=port,
                            ip=ip,
                        )
                    return result
            except asyncio.TimeoutError:
                result.error = "timeout"
                self.bus.bump("timeouts")
                self.bus.filtered(
                    f"Timeout on ://{host}:{port} ({scheme}) — dropping socket",
                    host=host,
                    port=port,
                    ip=ip,
                )
            except ssl.SSLError as exc:
                result.error = f"ssl: {exc.__class__.__name__}"
                self.bus.filtered(
                    f"TLS error on ://{host}:{port} ({scheme}) — "
                    f"{exc.__class__.__name__}: {exc}",
                    host=host,
                    port=port,
                    ip=ip,
                )
            except Exception as exc:
                if aiohttp is not None and isinstance(
                    exc, (aiohttp.ClientError, OSError)
                ):
                    result.error = f"{exc.__class__.__name__}: {exc}"
                    self.bus.filtered(
                        f"Filtered out ://{host} - Port {port} unreachable "
                        f"({exc.__class__.__name__})",
                        host=host,
                        port=port,
                        ip=ip,
                    )
                else:  # pragma: no cover - defensive
                    result.error = f"{exc.__class__.__name__}: {exc}"
                    self.bus.bump("errors")
                    self.bus.error(
                        f"Unexpected probe error on ://{host}:{port} — {result.error}",
                        host=host,
                        port=port,
                        ip=ip,
                    )
        return result

    async def _read_body(self, response: Any) -> tuple[bytes, bool]:
        """Read the response body, stopping at ``</head>`` or the size cap.

        Returns ``(body, truncated)``.  Halting at the end of ``<head>`` keeps
        large pages cheap: everything extracted from the body (title, meta
        generator, script signatures, favicon links) lives above it.  The size
        cap is a hard budget — the final chunk is sliced so the returned body can
        never exceed :attr:`max_body`.
        """
        chunks: list[bytes] = []
        total = 0
        truncated = False
        previous = b""
        try:
            async for chunk in response.content.iter_chunked(_READ_CHUNK):
                remaining = self.max_body - total
                if remaining <= 0:
                    truncated = True
                    break
                if len(chunk) > remaining:
                    chunk = chunk[:remaining]
                    truncated = True
                chunks.append(chunk)
                total += len(chunk)
                # A tag can straddle a chunk boundary, so check the seam too.
                if _HEAD_END_RE.search(chunk) or _HEAD_END_RE.search(previous + chunk):
                    # Stopping at </head> is the normal, complete case — the
                    # document head was fully read, so nothing was lost.
                    break
                if truncated:
                    break
                previous = chunk
        except Exception:
            truncated = True
        return b"".join(chunks), truncated

    async def probe_status(
        self, host: str, port: int, path: str = "", *, scheme: str | None = None
    ) -> dict[str, Any]:
        """Status-only GET for a specific *path* — the body is never read.

        Used by template-style exposure checks so a match against ``/.env`` or
        ``/.git/config`` records the status code and nothing else.  Never
        raises; returns ``{"status": None}`` on failure.
        """
        scheme = scheme or _scheme_order(port)[0]
        default_port = (scheme == "http" and port == 80) or (
            scheme == "https" and port == 443
        )
        url = f"{scheme}://{host}" + ("" if default_port else f":{port}")
        if path:
            url += path if path.startswith("/") else "/" + path
        if self._session is None:
            await self.start()
        if self._session is None:
            return {"status": None, "error": "aiohttp unavailable", "url": url}
        async with self._semaphore:
            self.probes += 1
            self.bus.bump("http_probes")
            try:
                async with self._session.get(
                    url, allow_redirects=False,
                    ssl=False if not self.verify_tls else None,
                ) as response:
                    return {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "url": url,
                        "final_url": str(response.url),
                        "error": None,
                    }
            except asyncio.TimeoutError:
                return {"status": None, "error": "timeout", "url": url}
            except Exception as exc:
                return {
                    "status": None,
                    "error": f"{exc.__class__.__name__}: {exc}",
                    "url": url,
                }

    async def probe_head(self, host: str, port: int, *, scheme: str | None = None) -> dict[str, Any]:
        """Cheap HEAD request — headers only, no body transferred.

        Used by fingerprinting and data-file checks where only the status and
        headers matter.  Never raises; returns ``{"status": None}`` on failure.
        """
        scheme = scheme or _scheme_order(port)[0]
        default_port = (scheme == "http" and port == 80) or (
            scheme == "https" and port == 443
        )
        url = f"{scheme}://{host}" + ("" if default_port else f":{port}")
        if self._session is None:
            await self.start()
        if self._session is None:
            return {"status": None, "error": "aiohttp unavailable", "url": url}
        async with self._semaphore:
            self.probes += 1
            self.bus.bump("http_probes")
            try:
                async with self._session.head(
                    url, allow_redirects=True, max_redirects=5,
                    ssl=False if not self.verify_tls else None,
                ) as response:
                    return {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "url": url,
                        "final_url": str(response.url),
                        "content_length": int(response.headers.get("Content-Length") or 0),
                        "server": response.headers.get("Server"),
                        "error": None,
                    }
            except asyncio.TimeoutError:
                return {"status": None, "error": "timeout", "url": url}
            except Exception as exc:
                return {
                    "status": None,
                    "error": f"{exc.__class__.__name__}: {exc}",
                    "url": url,
                }

    async def fetch(
        self,
        url: str,
        *,
        max_bytes: int = 256 * 1024,
        timeout: float | None = None,
    ) -> tuple[bytes, str | None, int | None]:
        """Fetch an arbitrary URL, capped at *max_bytes*.

        Returns ``(body, content_type, status)``.  Used for data files and
        favicons; never raises.
        """
        if self._session is None:
            await self.start()
        if self._session is None:
            return b"", None, None
        async with self._semaphore:
            self.probes += 1
            self.bus.bump("http_probes")
            try:
                request_timeout = (
                    aiohttp.ClientTimeout(total=timeout) if timeout else None
                )
                async with self._session.get(
                    url,
                    allow_redirects=True,
                    max_redirects=5,
                    ssl=False if not self.verify_tls else None,
                    timeout=request_timeout,
                ) as response:
                    chunks: list[bytes] = []
                    total = 0
                    async for chunk in response.content.iter_chunked(_READ_CHUNK):
                        chunks.append(chunk)
                        total += len(chunk)
                        if total >= max_bytes:
                            break
                    return (
                        b"".join(chunks)[:max_bytes],
                        response.headers.get("Content-Type"),
                        response.status,
                    )
            except Exception:
                return b"", None, None


# --------------------------------------------------------------------------- #
# Extraction helpers
# --------------------------------------------------------------------------- #


def _scheme_order(port: int) -> tuple[str, ...]:
    from .ports import prefers_tls

    return ("https", "http") if prefers_tls(port) else ("http", "https")


def extract_title(body: bytes, content_type: str | None) -> str | None:
    """Extract and clean the HTML ``<title>``."""
    if not body:
        return None
    if content_type and not any(
        token in content_type.lower()
        for token in ("html", "xml", "text", "json", "javascript")
    ):
        return None
    match = _TITLE_RE.search(body)
    if not match:
        return None
    raw = match.group(1)
    raw = _TAG_RE.sub(b" ", raw)
    raw = _WS_RE.sub(b" ", raw).strip()
    if not raw:
        return None
    charset = "utf-8"
    charset_match = _CHARSET_RE.search(body[:4096])
    if charset_match:
        charset = charset_match.group(1).decode("latin-1", "replace")
    for candidate in (charset, "utf-8", "latin-1"):
        try:
            text = raw.decode(candidate)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    else:  # pragma: no cover
        text = raw.decode("latin-1", "replace")
    text = " ".join(text.split())
    return text[:180] or None


def _fallback_title(result: WebProbeResult) -> str | None:
    """When no ``<title>`` exists, synthesise a descriptive label."""
    if result.kind == "redirect" and result.final_url:
        return f"redirects to {result.final_url}"
    parts: list[str] = []
    if result.server:
        parts.append(result.server.split("/")[0])
    if result.content_type:
        parts.append(result.content_type.split(";")[0].strip())
    if result.status:
        parts.append(f"HTTP {result.status}")
    return " · ".join(parts) if parts else None


def _snippet(body: bytes) -> str | None:
    if not body:
        return None
    text = _TAG_RE.sub(b" ", body[:4096])
    text = _WS_RE.sub(b" ", text).strip()
    if not text:
        return None
    return text.decode("utf-8", "replace")[:200]


def _fingerprint(result: WebProbeResult, body: bytes) -> str:
    """Stable signature used to detect wildcard/soft-404 responders."""
    digest = hashlib.sha1()
    digest.update(str(result.status or 0).encode())
    digest.update(b"|")
    digest.update((result.title or "").encode("utf-8", "replace"))
    digest.update(b"|")
    digest.update(str(len(body) // 512).encode())
    digest.update(b"|")
    digest.update((result.content_type or "").encode("utf-8", "replace"))
    return digest.hexdigest()[:16]


#: Markers found in the bodies of protocol-level rejections.
_PROTOCOL_ERROR_MARKERS = (
    b"plain http request was sent to https port",
    b"the plain http request was sent",
    b"was sent to https port",
    b"client sent an http request to an https server",
    b"http request was sent to https",
)

#: Markers that specifically mean "this port expects TLS", i.e. the port *is*
#: speaking HTTP and telling us to come back over HTTPS.
_HTTPS_PENDING_MARKERS = (
    b"plain http request was sent to https port",
    b"http request was sent to https",
    b"client sent an http request to an https server",
    b"was sent to https port",
)

#: Generic malformed/unsupported-request rejections (no TLS hint).
_PROTOCOL_REJECT_STATUS = frozenset({400, 405, 408, 414, 426, 431, 501, 505})

#: Client errors that still prove a real application is listening.
_ACCEPTED_CLIENT_ERRORS = frozenset({401, 403, 407, 451, 429})


def https_pending(result: WebProbeResult) -> bool:
    """True when the response tells us the port actually expects TLS.

    Apache answers a plain HTTP request on an SSL vhost with
    ``400 The plain HTTP request was sent to HTTPS port`` — the port is alive and
    speaking HTTP, it just wants a TLS handshake first.
    """
    if result.status not in (400, 403, 405, 426, 501):
        return False
    haystack = " ".join(
        filter(None, (result.title or "", result.body_snippet or ""))
    ).lower().encode("utf-8", "replace")
    return any(marker in haystack for marker in _HTTPS_PENDING_MARKERS)


def is_redirect_only(result: WebProbeResult) -> bool:
    """True when the scanned port merely *bounces* the request elsewhere.

    ``http://support.example.com:2082`` answers ``301 → https://support.example.com/``.
    Nothing is served on 2082: the port is a redirect gateway. Reporting it as a
    web interface (or worse, crediting it with the 200 that came back from 443)
    is wrong, so these are filtered and logged instead.

    A redirect that stays on the same port — ``http://www.x.com:80`` →
    ``https://www.x.com`` — keeps its finding, because the port does host the
    service and simply prefers TLS.
    """
    if result.status is None:
        return False
    if result.initial_status not in (301, 302, 303, 307, 308):
        return False
    target = result.final_url or urljoin(result.url, "/")
    try:
        target_port = _effective_port(target)
        scanned_port = _effective_port(result.url)
    except ValueError:
        return False
    return target_port != scanned_port


def _int_or_none(value: Any) -> int | None:
    """Parse a header value into an ``int``, tolerating junk."""
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _effective_port(url: str) -> int:
    parts = urlsplit(url if "//" in url else f"//{url}")
    if parts.port:
        return parts.port
    return 443 if parts.scheme == "https" else 80


def is_protocol_error(result: WebProbeResult, body: bytes) -> bool:
    """True when the response is an HTTP-layer rejection, not an application."""
    if result.status is None:
        return False
    haystack = body[:4096].lower() if body else b""
    if not haystack and result.body_snippet:
        haystack = result.body_snippet.lower().encode("utf-8", "replace")
    if any(marker in haystack for marker in _PROTOCOL_ERROR_MARKERS):
        return True
    if result.status in _PROTOCOL_REJECT_STATUS:
        return True
    if 400 <= result.status < 500 and result.status not in _ACCEPTED_CLIENT_ERRORS:
        # 404/410 etc.: the port speaks HTTP but serves nothing here.  Only keep
        # it if it is clearly an application (a real title + a real body).
        return not (result.title and result.content_length > 512)
    return False


def _is_web_interface(result: WebProbeResult, body: bytes = b"") -> bool:
    """Strict filter: does *this port* host a real web interface?

    A bare TCP accept is not enough — we require an HTTP status line *and*
    evidence of application payload.  Rejected:

    * redirect-only ports that bounce to a different host/port,
    * transport/protocol errors (400/405/501/505 and the Apache
      "plain HTTP request was sent to HTTPS port" page),
    * empty responses with no ``<title>``,
    * 5xx with no payload at all.
    """
    if result.status is None:
        return False
    if result.status < 200 or result.status >= 600:
        return False
    if is_redirect_only(result):
        return False
    if result.status >= 500 and result.content_length == 0 and not result.title:
        return False
    if result.content_length == 0 and not result.title:
        # 200/30x with a genuinely empty body is not a web interface.
        return False
    if is_protocol_error(result, body):
        return False
    return True


def classify_finding(result: WebProbeResult) -> str:
    """Confidence label used in reports and deduplication.

    ``interface``    — a real application answered (2xx/3xx, or auth-gated).
    ``restricted``   — application present but credentials required.
    ``redirect``     — the port only bounces elsewhere; kept as a fallback and
                       only surfaced when nothing else answers for the host.
    ``misconfigured`` — the port speaks HTTP but answers with an error page.
    """
    if is_redirect_only(result):
        return "redirect"
    status = result.status or 0
    if status in _ACCEPTED_CLIENT_ERRORS:
        return "restricted"
    if status >= 400:
        return "misconfigured"
    return "interface"
