"""Verification suite for :mod:`subsonar.core.fingerprint`.

No test touches the network: every HTTP interaction goes through a fake session
that speaks the small aiohttp/duck-typed surface the module uses
(``async with session.get(...)``, ``.status``, ``.headers``, ``.content.read()``,
``.read()``, ``.text()``, ``.json()``).  A hostile session — one that raises
synchronously, raises asynchronously, or raises from ``__aenter__`` — is used to
prove that the public functions degrade instead of propagating.
"""

from __future__ import annotations

import asyncio
import base64
import json
import random
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import pytest

from subsonar.core import fingerprint as fp
from subsonar.core.events import EventBus
from subsonar.core.fingerprint import (
    DATA_PATHS,
    FAVICON_MAX_BYTES,
    INTERESTING_PATHS,
    SECURITY_HEADERS,
    FingerprintResult,
    TechMatch,
    detect_technologies,
    extract_security_headers,
    favicon_base64,
    favicon_hash,
    fetch_favicon,
    fingerprint,
    murmur3_x86_32,
    to_signed32,
)
from subsonar.core.signatures import (
    CATEGORIES,
    KNOWN_FAVICON_HASHES,
    MATCH_FIELDS,
    REQUIRED_FIELDS,
    SIGNATURES,
    category_breakdown,
    compile_signature,
    compile_signatures,
    signature_count,
    validate_signatures,
)

# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #

#: The well-known 1x1 transparent PNG — a *real* base64 string.
PNG_1X1_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAF"
    "AAH/q842iQAAAABJRU5ErkJggg=="
)
PNG_1X1 = base64.b64decode(PNG_1X1_B64)

SECRET_ENV_VALUE = "s3cr3t-env-token-9f2b"
SECRET_GIT_VALUE = "repositoryformatversion-do-not-store"
COOKIE_SECRET = "s3ss10n-c00k13-value"


def _path_of(url: str) -> str:
    return urlsplit(str(url)).path or "/"


class FakeContent:
    """Stream-like body reader (aiohttp ``response.content``)."""

    def __init__(self, body: bytes) -> None:
        self._body = body
        self._offset = 0
        self.read_calls = 0

    async def read(self, size: int = -1) -> bytes:
        self.read_calls += 1
        if size is None or size < 0:
            chunk = self._body[self._offset :]
            self._offset = len(self._body)
            return chunk
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk


class FakeResponse:
    """Minimal aiohttp-compatible response, usable as an async context manager."""

    def __init__(
        self,
        status: int = 200,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> None:
        self.status = status
        self.headers = dict(headers or {})
        self._body = body
        self.content = FakeContent(body)
        self.read_calls = 0
        self.entered = False

    async def __aenter__(self) -> "FakeResponse":
        self.entered = True
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    async def read(self) -> bytes:
        self.read_calls += 1
        return self._body

    async def text(self) -> str:
        return self._body.decode("utf-8", "replace")

    async def json(self) -> Any:
        return json.loads(self._body)


class FakeSession:
    """Routes by URL path; records every ``(method, url, kwargs)`` call."""

    def __init__(
        self,
        routes: dict[str, Any] | None = None,
        default: FakeResponse | None = None,
        *,
        raise_on_request: bool = False,
        raise_on_enter: bool = False,
    ) -> None:
        self.routes = dict(routes or {})
        self.default = default if default is not None else FakeResponse(404)
        self.requests: list[tuple[str, str, dict[str, Any]]] = []
        self.raise_on_request = raise_on_request
        self.raise_on_enter = raise_on_enter

    # -- helpers ---------------------------------------------------------- #
    def methods_for(self, path: str) -> list[str]:
        return [method for method, url, _ in self.requests if _path_of(url) == path]

    def _route(self, method: str, url: str) -> Any:
        route = self.routes.get(_path_of(url), self.default)
        if isinstance(route, dict):
            route = route.get(method, route.get("get"))
        if route is None:
            raise ConnectionResetError(f"no route for {url}")
        if self.raise_on_enter:
            return EnterRaisesResponse()
        return route

    def _record(self, method: str, url: str, kwargs: dict[str, Any]) -> Any:
        self.requests.append((method, str(url), dict(kwargs)))
        if self.raise_on_request:
            raise RuntimeError("session is broken")
        return self._route(method, url)

    # -- aiohttp-ish surface ---------------------------------------------- #
    def get(self, url: str, **kwargs: Any) -> Any:
        return self._record("get", url, kwargs)

    def head(self, url: str, **kwargs: Any) -> Any:
        return self._record("head", url, kwargs)


class AsyncRaisingSession:
    """Raises from inside the coroutine (not from the call)."""

    def __init__(self) -> None:
        self.calls = 0

    async def get(self, url: str, **kwargs: Any) -> Any:
        self.calls += 1
        raise RuntimeError("async boom")

    async def head(self, url: str, **kwargs: Any) -> Any:
        self.calls += 1
        raise RuntimeError("async boom")


class HangingSession:
    """Accepts the call, then never answers within the probe budget."""

    def __init__(self) -> None:
        self.calls = 0

    async def get(self, url: str, **kwargs: Any) -> Any:
        self.calls += 1
        await asyncio.sleep(30)
        return FakeResponse(200, body=b"late")

    async def head(self, url: str, **kwargs: Any) -> Any:
        self.calls += 1
        await asyncio.sleep(30)
        return FakeResponse(200)


class EnterRaisesResponse:
    async def __aenter__(self) -> Any:
        raise RuntimeError("cannot enter")

    async def __aexit__(self, *exc: Any) -> bool:
        return False


@dataclass
class ProbeResultStub:
    """Stand-in for ``WebProbeResult`` (identical field names)."""

    host: str = "a.example.com"
    ip: str = "203.0.113.10"
    port: int = 443
    scheme: str = "https"
    url: str = "https://a.example.com"
    status: int | None = 200
    title: str | None = "Example Domain"
    server: str | None = "nginx"
    content_type: str | None = "text/html"
    content_length: int = 512
    redirect_chain: list[str] = field(default_factory=list)
    final_url: str | None = None
    tls: bool = True
    tls_version: str | None = "TLSv1.3"
    fingerprint: str | None = "0123456789abcdef"
    body_snippet: str | None = None
    latency_ms: float = 1.0
    ok: bool = True
    kind: str = "interface"
    initial_status: int | None = 200
    redirected: bool = False
    error: str | None = None


class ProbeStub:
    """Stand-in for ``WebProbe``: optional private session + ``probe()``."""

    def __init__(
        self,
        session: Any = None,
        result: Any = None,
        *,
        start_session: Any = None,
    ) -> None:
        self._session = session
        self._result = result
        self._start_session = start_session
        self.probed = 0
        self.started = 0

    async def start(self) -> None:
        self.started += 1
        if self._start_session is not None and self._session is None:
            self._session = self._start_session

    async def probe(
        self, host: str, ip: str, port: int, *, schemes: Any = None
    ) -> Any:
        self.probed += 1
        if self._result is None:
            raise RuntimeError("prober is broken")
        return self._result


def _names(**kwargs: Any) -> set[str]:
    return {tech.name for tech in detect_technologies(**kwargs)}


# --------------------------------------------------------------------------- #
# MurmurHash3 vectors
# --------------------------------------------------------------------------- #


def reference_murmur3(data: bytes, seed: int = 0) -> int:
    """Second, independently written MurmurHash3_x86_32 (test-side reference).

    Written byte-at-a-time with ``struct``-free little-endian assembly so a
    transcription slip in the module implementation cannot hide behind a shared
    helper.
    """
    h = seed & 0xFFFFFFFF
    c1, c2 = 0xCC9E2D51, 0x1B873593
    blocks = len(data) // 4
    for i in range(blocks):
        k = (
            data[i * 4]
            | (data[i * 4 + 1] << 8)
            | (data[i * 4 + 2] << 16)
            | (data[i * 4 + 3] << 24)
        )
        k = (k * c1) & 0xFFFFFFFF
        k = (k << 15 & 0xFFFFFFFF) | (k >> 17)
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = (h << 13 & 0xFFFFFFFF) | (h >> 19)
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[blocks * 4 :]
    k = 0
    if len(tail) == 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = (k << 15 & 0xFFFFFFFF) | (k >> 17)
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h & 0xFFFFFFFF


def test_murmur3_empty_vector() -> None:
    assert murmur3_x86_32(b"") == 0


def test_murmur3_hello_vector() -> None:
    assert murmur3_x86_32(b"hello") == 613153351


def test_murmur3_matches_reference_implementation() -> None:
    rng = random.Random(1337)
    samples = [b"", b"a", b"ab", b"abc", b"abcd", b"hello", b"\x00" * 7, b"\xff" * 33]
    samples += [bytes(rng.randrange(256) for _ in range(n)) for n in range(0, 40)]
    for data in samples:
        assert murmur3_x86_32(data) == reference_murmur3(data), data
        assert murmur3_x86_32(data, 42) == reference_murmur3(data, 42), data
    # 32-bit range + signed reinterpretation
    assert 0 <= murmur3_x86_32(b"hello") <= 0xFFFFFFFF
    assert to_signed32(0xFFFFFFFF) == -1
    assert to_signed32(0x80000000) == -2147483648
    assert to_signed32(0x7FFFFFFF) == 2147483647


def test_murmur3_rejects_non_bytes() -> None:
    with pytest.raises(TypeError):
        murmur3_x86_32("hello")  # type: ignore[arg-type]


def test_favicon_base64_uses_mime_encoding() -> None:
    blob = bytes(range(100))
    assert favicon_base64(blob) == base64.encodebytes(blob)
    assert b"\n" in favicon_base64(blob)
    assert favicon_base64(blob).endswith(b"\n")
    assert favicon_base64(blob) != base64.b64encode(blob)


def test_favicon_hash_matches_shodan_recipe_on_real_base64() -> None:
    """Round-trip over a real PNG (and a real base64 string)."""
    assert len(PNG_1X1) == 70
    encoded = base64.encodebytes(PNG_1X1)
    assert encoded == favicon_base64(PNG_1X1)
    assert encoded.decode("ascii").startswith("iVBORw0KGgo")

    expected = str(to_signed32(reference_murmur3(encoded)))
    observed = favicon_hash(PNG_1X1)
    assert observed == expected
    # ...and it is *not* the plain single-line b64 hash, which is the classic bug.
    assert observed != str(to_signed32(reference_murmur3(base64.b64encode(PNG_1X1))))
    # a signed decimal string, i.e. Shodan's mmh3.hash() semantics
    assert observed.lstrip("-").isdigit()
    assert -(2**31) <= int(observed) <= 2**31 - 1


def test_favicon_hash_over_explicit_base64_strings() -> None:
    for text in (PNG_1X1_B64, "aGVsbG8=", "aGVsbG8gd29ybGQ=", ""):
        payload = base64.b64decode(text)
        assert favicon_hash(payload) == str(
            to_signed32(reference_murmur3(base64.encodebytes(payload)))
        )
    # mmh3.hash(b64 of b"hello") is a fixed, reproducible value
    assert favicon_hash(base64.b64decode("aGVsbG8=")) == str(
        to_signed32(reference_murmur3(base64.encodebytes(b"hello")))
    )


# --------------------------------------------------------------------------- #
# Signature table integrity
# --------------------------------------------------------------------------- #


def test_signature_table_has_at_least_sixty_entries() -> None:
    assert signature_count() >= 60
    assert len(SIGNATURES) >= 60


def test_signature_table_has_no_duplicate_ids() -> None:
    ids = [signature.id for signature in SIGNATURES]
    assert len(ids) == len(set(ids))


def test_every_signature_has_the_required_fields() -> None:
    for signature in SIGNATURES:
        for required in REQUIRED_FIELDS:
            assert getattr(signature, required), f"{signature.id} lacks {required}"
        assert signature.category in CATEGORIES, signature.id
        assert signature.matchers(), f"{signature.id} has no matcher"
        for matcher in signature.matchers():
            assert matcher in MATCH_FIELDS, f"{signature.id}: {matcher}"


def test_signature_table_validates_and_compiles() -> None:
    assert validate_signatures() == []
    compiled = compile_signatures()
    assert len(compiled) == len(SIGNATURES)
    for item in compiled:
        assert compile_signature(item.signature).signature == item.signature


def test_every_matcher_dimension_is_used_by_the_table() -> None:
    used: set[str] = set()
    for signature in SIGNATURES:
        used.update(signature.matchers())
    # header name/value regex, body regex, cookie name, meta generator, favicon
    # hash and path probing must all be exercised by the shipped table.
    assert {
        "header",
        "header_re",
        "header_name_re",
        "body_re",
        "cookie",
        "cookie_re",
        "meta_re",
        "favicon",
        "path",
    } <= used


def test_signature_categories_are_covered() -> None:
    breakdown = category_breakdown()
    assert sum(breakdown.values()) == len(SIGNATURES)
    assert set(breakdown) == set(CATEGORIES)
    for category in (
        "web server",
        "language",
        "framework",
        "CMS",
        "JS library",
        "analytics",
        "CDN",
        "WAF",
        "panel",
    ):
        assert breakdown[category] > 0, category
    assert KNOWN_FAVICON_HASHES["116323821"].startswith("Spring Boot")


def test_validate_signatures_detects_injected_problems() -> None:
    from subsonar.core.signatures import Signature

    bad = (
        Signature("", "", "web server", body_re="x"),
        Signature("dup", "Dup", "made up", body_re="x"),
        Signature("dup", "Dup", "web server", body_re="x"),
        Signature("empty", "Empty", "web server"),
        Signature("pathless", "Pathless", "web server", path="no-slash"),
        Signature("badre", "BadRe", "web server", body_re="("),
    )
    problems = validate_signatures(bad)
    joined = " | ".join(problems)
    assert "missing name" in joined or "missing id" in joined
    assert "unknown category" in joined
    assert "duplicate signature id: dup" in joined
    assert "no matcher set" in joined
    assert "must start with '/'" in joined
    assert "bad regex" in joined


# --------------------------------------------------------------------------- #
# Technology detection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("case", "kwargs", "expected"),
    [
        ("server-nginx", {"headers": [("Server", "nginx/1.24.0")]}, "nginx"),
        ("server-apache", {"headers": [("Server", "Apache/2.4.57 (Ubuntu)")]}, "Apache httpd"),
        ("server-iis", {"headers": [("Server", "Microsoft-IIS/10.0")]}, "Microsoft IIS"),
        ("server-litespeed", {"headers": [("Server", "LiteSpeed")]}, "LiteSpeed"),
        ("server-caddy", {"headers": [("Server", "Caddy")]}, "Caddy"),
        ("server-openresty", {"headers": [("Server", "openresty/1.21")]}, "OpenResty"),
        ("server-gunicorn", {"headers": [("Server", "gunicorn/20.1.0")]}, "Gunicorn"),
        ("server-werkzeug", {"headers": [("Server", "Werkzeug/2.3.0 Python/3.11")]}, "Werkzeug"),
        ("x-powered-express", {"headers": [("X-Powered-By", "Express")]}, "Express"),
        ("x-powered-php", {"headers": [("X-Powered-By", "PHP/8.2.7")]}, "PHP"),
        ("cookie-phpsessid", {"cookie_names": ["PHPSESSID"]}, "PHP"),
        ("cookie-jsessionid", {"cookie_names": ["JSESSIONID"]}, "Java"),
        ("x-aspnet-version", {"headers": [("X-AspNet-Version", "4.0.30319")]}, "ASP.NET"),
        ("body-wordpress", {"body": b'<link href="/wp-content/themes/x/style.css">'}, "WordPress"),
        ("body-wp-login-path", {"paths": {"/wp-login.php": 200}}, "WordPress"),
        ("header-x-drupal-cache", {"headers": [("X-Drupal-Cache", "HIT")]}, "Drupal"),
        ("header-x-generator-drupal", {"headers": [("X-Generator", "Drupal 10")]}, "Drupal"),
        ("cookie-cfduid", {"cookie_names": ["__cfduid"]}, "Cloudflare"),
        ("header-cf-ray", {"headers": [("CF-RAY", "7f1a2b3c4d5e-LHR")]}, "Cloudflare"),
        ("body-next-data", {"body": b'<script id="__NEXT_DATA__" type="application/json">'}, "Next.js"),
        ("body-react-root", {"body": b'<div id="root" data-reactroot=""></div>'}, "React"),
        ("body-ng-app", {"body": b'<html ng-app="app">'}, "Angular"),
        ("body-ng-version", {"body": b'<app-root ng-version="16.2.0">'}, "Angular"),
        ("body-django-csrf", {"body": b'<input name="csrfmiddlewaretoken" value="x">'}, "Django"),
        ("header-x-shopify-stage", {"headers": [("X-Shopify-Stage", "production")]}, "Shopify"),
        ("header-x-magento", {"headers": [("X-Magento-Vary", "abc")]}, "Magento"),
        ("header-x-gitlab", {"headers": [("X-Gitlab-Meta", "{}")]}, "GitLab"),
        ("cookie-gitlab", {"cookie_names": ["_gitlab_session"]}, "GitLab"),
        ("header-x-jenkins", {"headers": [("X-Jenkins", "2.401.3")]}, "Jenkins"),
        ("header-x-confluence", {"headers": [("X-Confluence-Request-Time", "12")]}, "Confluence"),
        ("cookie-grafana", {"cookie_names": ["grafana_session"]}, "Grafana"),
        ("body-kibana", {"body": b'<script src="/bundles/kibana.js">'}, "Kibana"),
        ("header-x-portainer", {"headers": [("X-Portainer", "2.19")]}, "Portainer"),
        ("favicon-spring-boot", {"favicon_hash": "116323821"}, "Spring Boot"),
        ("path-graphql", {"paths": {"/graphql": 400}}, "GraphQL endpoint"),
        ("meta-generator-ghost", {"meta_generator": "Ghost 5.75"}, "Ghost"),
        ("body-google-analytics", {"body": b'<script src="https://www.google-analytics.com/analytics.js">'}, "Google Analytics"),
        ("body-apache-mod-status", {"paths": {"/server-status": 200}}, "Apache mod_status"),
    ],
)
def test_detection_of_specific_technologies(
    case: str, kwargs: dict[str, Any], expected: str
) -> None:
    assert expected in _names(**kwargs), case


def test_unrelated_response_detects_nothing() -> None:
    assert (
        detect_technologies(
            headers=[("Content-Type", "text/html"), ("Date", "Mon, 01 Jan 2035 00:00:00 GMT")],
            body=b"<html><head><title>hello</title></head><body>nothing here</body></html>",
            cookie_names=["_ga_XYZ"],
        )
        == []
    )


def test_empty_evidence_short_circuits() -> None:
    assert detect_technologies() == []
    assert detect_technologies(headers=None, body=b"", paths={}) == []


def test_detection_merges_duplicate_technologies_and_keeps_evidence() -> None:
    matches = detect_technologies(
        headers=[("Server", "nginx")],
        body=b'<link href="/wp-content/x.css"><script src="/wp-includes/js/jquery.min.js">',
        paths={"/wp-login.php": 200},
    )
    by_name = {match.name: match for match in matches}
    assert set(by_name) >= {"nginx", "WordPress", "jQuery"}
    wordpress = by_name["WordPress"]
    assert "wp-content" in wordpress.evidence
    assert "/wp-login.php" in wordpress.evidence
    assert wordpress.category == "CMS"
    assert [match.name for match in matches].count("WordPress") == 1


def test_detection_records_negative_favicon_hashes() -> None:
    assert "Spring Boot" not in _names(favicon_hash="-391155043", headers=[("Server", "x")])


def test_tech_match_and_result_serialisation() -> None:
    match = TechMatch(name="nginx", category="web server", evidence="header Server: 'nginx'")
    assert match.to_dict() == {
        "name": "nginx",
        "category": "web server",
        "evidence": "header Server: 'nginx'",
    }
    result = FingerprintResult(
        favicon_hash="-391155043",
        technologies=[match],
        data_files={"/robots.txt": 200},
        headers={"Server": "nginx"},
        interesting_paths={"/actuator/health": 200},
        server="nginx",
        notes=["note"],
    )
    payload = result.to_dict()
    assert payload["favicon_hash"] == "-391155043"
    assert payload["technologies"] == [match.to_dict()]
    assert payload["data_files"] == {"/robots.txt": 200}
    assert result.names == ["nginx"]
    assert result.in_category("web server") == [match]
    assert result.in_category("CMS") == []


# --------------------------------------------------------------------------- #
# Header extraction
# --------------------------------------------------------------------------- #


def test_extract_security_headers_keeps_the_allow_list() -> None:
    headers = [
        ("Strict-Transport-Security", "max-age=63072000"),
        ("Content-Security-Policy", "default-src 'self'"),
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "geolocation=()"),
        ("Server", "nginx"),
        ("X-Powered-By", "PHP/8.2"),
        ("Via", "1.1 varnish"),
        ("CF-RAY", "7f1a-LHR"),
    ]
    extracted = extract_security_headers(headers)
    assert list(extracted) == [*SECURITY_HEADERS]
    assert extracted["Server"] == "nginx"
    assert extracted["CF-RAY"] == "7f1a-LHR"


def test_extract_security_headers_drops_uninteresting_headers() -> None:
    extracted = extract_security_headers(
        [("Date", "now"), ("Content-Type", "text/html"), ("Age", "3")]
    )
    assert extracted == {}


def test_extract_security_headers_never_keeps_cookie_values() -> None:
    extracted = extract_security_headers(
        [
            ("Set-Cookie", f"PHPSESSID={COOKIE_SECRET}; Path=/; HttpOnly"),
            ("Set-Cookie", f"csrftoken={COOKIE_SECRET}; Secure"),
            ("Set-Cookie", "grafana_session=x"),
        ]
    )
    assert extracted["Set-Cookie"] == "PHPSESSID, csrftoken, grafana_session"
    assert COOKIE_SECRET not in json.dumps(extracted)


def test_extract_security_headers_survives_garbage() -> None:
    assert extract_security_headers(None) == {}
    assert extract_security_headers(object()) == {}
    assert extract_security_headers([("Server", "nginx"), "broken"]) == {"Server": "nginx"}


def test_module_is_self_contained() -> None:
    """No aiohttp and no web_probe import — the module cannot build its own session."""
    assert not hasattr(fp, "aiohttp")
    assert not hasattr(fp, "web_probe")
    assert "aiohttp" not in {name for name in dir(fp)}


# --------------------------------------------------------------------------- #
# fetch_favicon
# --------------------------------------------------------------------------- #


async def test_fetch_favicon_success() -> None:
    session = FakeSession(
        {"/favicon.ico": FakeResponse(200, {"Content-Type": "image/x-icon"}, PNG_1X1)}
    )
    data, content_type = await fetch_favicon(session, "https", "a.example.com", 443, timeout=1.0)
    assert data == PNG_1X1
    assert content_type == "image/x-icon"
    method, url, kwargs = session.requests[0]
    assert method == "get"
    assert url == "https://a.example.com/favicon.ico"
    assert kwargs.get("allow_redirects") is True


async def test_fetch_favicon_respects_non_default_port() -> None:
    session = FakeSession({"/favicon.ico": FakeResponse(200, {}, PNG_1X1)})
    await fetch_favicon(session, "http", "a.example.com", 8080, timeout=1.0)
    assert session.requests[0][1] == "http://a.example.com:8080/favicon.ico"


async def test_fetch_favicon_rejects_oversized_icon() -> None:
    big = b"\x00" * (FAVICON_MAX_BYTES + 1024)
    session = FakeSession({"/favicon.ico": FakeResponse(200, {}, big)})
    data, content_type = await fetch_favicon(session, "https", "a.example.com", 443, timeout=1.0)
    assert data is None
    assert content_type is None


async def test_fetch_favicon_accepts_icon_at_the_cap() -> None:
    exact = b"\x01" * FAVICON_MAX_BYTES
    session = FakeSession({"/favicon.ico": FakeResponse(200, {}, exact)})
    data, _ = await fetch_favicon(session, "https", "a.example.com", 443, timeout=1.0)
    assert data == exact


async def test_fetch_favicon_handles_error_statuses() -> None:
    for status in (301, 403, 404, 500):
        session = FakeSession({"/favicon.ico": FakeResponse(status, {}, b"nope")})
        assert await fetch_favicon(session, "https", "a.example.com", 443, timeout=1.0) == (
            None,
            None,
        )


@pytest.mark.parametrize(
    "session",
    [
        FakeSession(raise_on_request=True),
        AsyncRaisingSession(),
        FakeSession(raise_on_enter=True),
        FakeSession({"/favicon.ico": None}),
        None,
        object(),
    ],
    ids=["sync-raise", "async-raise", "enter-raise", "connection-reset", "none", "not-a-session"],
)
async def test_fetch_favicon_never_raises(session: Any) -> None:
    assert await fetch_favicon(session, "https", "a.example.com", 443, timeout=0.2) == (
        None,
        None,
    )


async def test_fetch_favicon_is_timeout_bounded() -> None:
    session = HangingSession()
    loop = asyncio.get_running_loop()
    started = loop.time()
    data, content_type = await fetch_favicon(session, "https", "a.example.com", 443, timeout=0.05)
    elapsed = loop.time() - started
    assert (data, content_type) == (None, None)
    assert elapsed < 2.0, f"favicon fetch ignored the timeout ({elapsed:.2f}s)"
    assert session.calls == 1


# --------------------------------------------------------------------------- #
# fingerprint() end to end
# --------------------------------------------------------------------------- #


def _full_session() -> tuple[FakeSession, dict[str, FakeResponse]]:
    responses = {
        "root": FakeResponse(
            200,
            {
                "Server": "nginx/1.24.0",
                "Content-Type": "text/html; charset=utf-8",
                "Set-Cookie": f"PHPSESSID={COOKIE_SECRET}; Path=/; HttpOnly",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=63072000",
                "X-Powered-By": "PHP/8.2.7",
                "CF-RAY": "7f1a2b3c4d5e-LHR",
            },
            (
                b"<html><head><title>Example Domain</title>"
                b'<meta name="generator" content="WordPress 6.4">'
                b'<script src="/wp-content/themes/twentytwenty/js/jquery.min.js"></script>'
                b"</head><body>hello</body></html>"
            ),
        ),
        "icon": FakeResponse(200, {"Content-Type": "image/x-icon"}, PNG_1X1),
        "env": FakeResponse(200, {"Content-Type": "text/plain"}, f"SECRET_KEY={SECRET_ENV_VALUE}\n".encode()),
        "git": FakeResponse(
            200, {"Content-Type": "text/plain"}, f"[core]\n\t{SECRET_GIT_VALUE} = 0\n".encode()
        ),
        "robots": FakeResponse(200, {"Content-Type": "text/plain"}, b"User-agent: *\n"),
    }
    session = FakeSession(
        {
            "/": responses["root"],
            "/favicon.ico": responses["icon"],
            "/robots.txt": responses["robots"],
            "/.env": responses["env"],
            "/.git/config": responses["git"],
        },
        default=FakeResponse(404, {"Content-Type": "text/html"}, b"not found"),
    )
    return session, responses


async def test_fingerprint_collects_every_evidence_type() -> None:
    session, responses = _full_session()
    probe = ProbeStub(session=session, result=ProbeResultStub())
    result = await fingerprint(probe, "https", "a.example.com", "203.0.113.10", 443, timeout=1.0)

    assert isinstance(result, FingerprintResult)
    assert result.server == "nginx/1.24.0"
    # favicon hash must equal the independent Shodan recipe over the served icon
    assert result.favicon_hash == str(
        to_signed32(murmur3_x86_32(base64.encodebytes(PNG_1X1)))
    )
    names = result.names
    assert "nginx" in names
    assert "WordPress" in names
    assert "PHP" in names
    assert "Cloudflare" in names
    assert "jQuery" in names
    assert result.data_files["/robots.txt"] == 200
    assert result.data_files["/sitemap.xml"] == 404
    assert result.data_files["/.env"] == 200
    assert len(result.data_files) == len(DATA_PATHS)
    assert result.headers["Server"] == "nginx/1.24.0"
    assert result.headers["Strict-Transport-Security"] == "max-age=63072000"
    assert result.headers["X-Frame-Options"] == "DENY"
    assert result.headers["X-Powered-By"] == "PHP/8.2.7"
    assert result.headers["CF-RAY"] == "7f1a2b3c4d5e-LHR"
    assert result.headers["Set-Cookie"] == "PHPSESSID"
    assert result.notes
    # the probe result was already supplied, so probe() must not be called again
    assert probe.probed == 0


async def test_fingerprint_records_path_statuses_without_storing_bodies() -> None:
    session, responses = _full_session()
    probe = ProbeStub(session=session, result=ProbeResultStub())
    result = await fingerprint(probe, "https", "a.example.com", "203.0.113.10", 443, timeout=1.0)

    assert result.data_files["/.env"] == 200
    assert result.data_files["/.git/config"] == 200
    # the capability check must never read (let alone keep) those bodies
    assert responses["env"].content.read_calls == 0
    assert responses["env"].read_calls == 0
    assert responses["git"].content.read_calls == 0
    assert responses["git"].read_calls == 0
    serialised = json.dumps(result.to_dict())
    assert SECRET_ENV_VALUE not in serialised
    assert SECRET_GIT_VALUE not in serialised
    assert "SECRET_KEY" not in serialised
    assert COOKIE_SECRET not in serialised


async def test_fingerprint_status_probes_use_head_then_get() -> None:
    head_only = FakeResponse(405, {}, b"")
    get_ok = FakeResponse(200, {"Content-Type": "text/plain"}, b"ok")
    head_denied = FakeResponse(403, {}, b"")
    session = FakeSession(
        {
            "/": FakeResponse(200, {}, b"<html><title>t</title></html>"),
            "/favicon.ico": FakeResponse(404, {}, b""),
            "/robots.txt": {"head": head_only, "get": get_ok},
            "/.env": {"head": head_denied, "get": FakeResponse(200, {}, b"x")},
        },
        default=FakeResponse(404, {}, b""),
    )
    probe = ProbeStub(session=session, result=ProbeResultStub())
    result = await fingerprint(probe, "https", "a.example.com", "203.0.113.10", 443, timeout=1.0)

    assert result.data_files["/robots.txt"] == 200  # HEAD said 405 → GET fallback
    assert session.methods_for("/robots.txt") == ["head", "get"]
    assert result.data_files["/.env"] == 403  # HEAD answered definitively → no GET
    assert session.methods_for("/.env") == ["head"]
    assert result.data_files["/sitemap.xml"] == 404
    assert set(result.data_files) == set(DATA_PATHS)


async def test_fingerprint_reports_interesting_paths_separately() -> None:
    session = FakeSession(
        {
            "/": FakeResponse(200, {}, b"<html><title>t</title></html>"),
            "/favicon.ico": FakeResponse(404, {}, b""),
            "/actuator/health": FakeResponse(200, {}, b'{"status":"UP"}'),
            "/wp-login.php": FakeResponse(302, {"Location": "/login"}, b""),
            "/jenkins/": FakeResponse(404, {}, b""),
        },
        default=FakeResponse(404, {}, b""),
    )
    probe = ProbeStub(session=session, result=ProbeResultStub())
    result = await fingerprint(probe, "https", "a.example.com", "203.0.113.10", 443, timeout=1.0)
    assert result.interesting_paths == {"/actuator/health": 200, "/wp-login.php": 302}
    assert "/jenkins/" not in result.interesting_paths
    assert "Spring Boot" in result.names
    assert "WordPress" in result.names
    assert set(INTERESTING_PATHS).isdisjoint(DATA_PATHS)


async def test_fingerprint_can_skip_icon_and_path_probes() -> None:
    session, _ = _full_session()
    probe = ProbeStub(session=session, result=ProbeResultStub())
    result = await fingerprint(
        probe,
        "https",
        "a.example.com",
        "203.0.113.10",
        443,
        timeout=1.0,
        fetch_icon=False,
        probe_paths=False,
    )
    assert result.favicon_hash is None
    assert result.data_files == {}
    assert result.interesting_paths == {}
    assert not any("/favicon.ico" == _path_of(url) for _, url, _ in session.requests)
    assert not any("/robots.txt" == _path_of(url) for _, url, _ in session.requests)


async def test_fingerprint_uses_the_callers_probe_result_without_a_session() -> None:
    probe = ProbeStub(
        session=None,
        result=ProbeResultStub(
            server="nginx",
            status=200,
            body_snippet="/wp-content/ content",
        ),
    )
    result = await fingerprint(probe, "https", "a.example.com", "203.0.113.10", 443, timeout=1.0)
    assert probe.probed == 1
    assert result.server == "nginx"
    assert result.notes
    assert result.favicon_hash is None
    assert result.data_files == {}
    assert any("no live session" in note for note in result.notes)


async def test_fingerprint_reads_last_response_headers_accessor() -> None:
    probe = ProbeStub(session=None, result=ProbeResultStub())
    probe.last_response_headers = {  # type: ignore[attr-defined]
        "Server": "nginx/1.24.0",
        "X-Powered-By": "PHP/8.2.7",
        "Set-Cookie": f"PHPSESSID={COOKIE_SECRET}",
    }
    result = await fingerprint(probe, "https", "a.example.com", "203.0.113.10", 443, timeout=1.0)
    assert result.server == "nginx/1.24.0"
    assert result.headers["X-Powered-By"] == "PHP/8.2.7"
    assert result.headers["Set-Cookie"] == "PHPSESSID"
    assert {"nginx", "PHP"} <= set(result.names)


async def test_fingerprint_starts_the_prober_when_the_session_is_lazy() -> None:
    lazy = FakeSession(
        {
            "/": FakeResponse(
                200,
                {"Server": "nginx/1.24.0", "Content-Type": "text/html"},
                b"<html><title>t</title></html>",
            )
        },
        default=FakeResponse(404, {}, b""),
    )
    probe = ProbeStub(session=None, result=ProbeResultStub(), start_session=lazy)
    result = await fingerprint(probe, "https", "a.example.com", "203.0.113.10", 443, timeout=1.0)
    assert probe.started == 1
    assert result.server == "nginx/1.24.0"
    assert probe.probed == 0  # the lazily started session answered instead


@pytest.mark.parametrize(
    "session",
    [
        FakeSession(raise_on_request=True),
        AsyncRaisingSession(),
        FakeSession(raise_on_enter=True),
        None,
        object(),
    ],
    ids=["sync-raise", "async-raise", "enter-raise", "none", "not-a-session"],
)
async def test_fingerprint_never_raises_on_hostile_sessions(session: Any) -> None:
    probe = ProbeStub(session=session, result=None)  # probe() raises too
    result = await fingerprint(probe, "https", "a.example.com", "203.0.113.10", 443, timeout=0.2)
    assert isinstance(result, FingerprintResult)
    assert result.favicon_hash is None
    assert result.technologies == []
    assert result.data_files == {}
    assert result.interesting_paths == {}
    assert result.headers == {}
    assert result.server is None
    assert result.notes


async def test_fingerprint_never_raises_on_a_broken_bus() -> None:
    class HostileBus:
        def emit(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("bus is broken")

    session, _ = _full_session()
    probe = ProbeStub(session=session, result=ProbeResultStub())
    result = await fingerprint(
        probe, "https", "a.example.com", "203.0.113.10", 443, timeout=1.0, bus=HostileBus()  # type: ignore[arg-type]
    )
    assert "WordPress" in result.names


async def test_fingerprint_survives_a_hanging_session() -> None:
    session = HangingSession()
    probe = ProbeStub(session=session, result=None)
    loop = asyncio.get_running_loop()
    started = loop.time()
    result = await fingerprint(
        probe, "https", "a.example.com", "203.0.113.10", 443, timeout=0.05
    )
    elapsed = loop.time() - started
    assert isinstance(result, FingerprintResult)
    assert result.favicon_hash is None
    assert elapsed < 5.0, f"fingerprint ignored its timeout budget ({elapsed:.2f}s)"


async def test_fingerprint_emits_start_and_summary_events() -> None:
    bus = EventBus()
    session, _ = _full_session()
    probe = ProbeStub(session=session, result=ProbeResultStub())
    await fingerprint(
        probe, "https", "a.example.com", "203.0.113.10", 443, timeout=1.0, bus=bus
    )
    events = [event for event in bus.drain() if event.category == "fingerprint"]
    assert events, "fingerprinting emitted no live-log events"
    assert any("Fingerprinting" in event.message for event in events)
    summary = [event for event in events if event.message.startswith("Fingerprint ")]
    assert summary, [event.message for event in events]
    assert "WordPress" not in summary[0].message  # summary counts, it does not list
    assert "technologies" in summary[0].message
    assert summary[0].host == "a.example.com"
    assert summary[0].port == 443
    assert summary[0].data["favicon_hash"] == str(
        to_signed32(murmur3_x86_32(base64.encodebytes(PNG_1X1)))
    )


async def test_fingerprint_does_no_network_work_without_a_session() -> None:
    result = await fingerprint(object(), "https", "a.example.com", "203.0.113.10", 443, timeout=0.2)
    assert result.favicon_hash is None
    assert result.technologies == []
    assert result.data_files == {}
    assert result.headers == {}
    assert any("no HTTP session" in note or "no HTTP response" in note for note in result.notes)


def test_data_paths_are_the_documented_set() -> None:
    assert DATA_PATHS == (
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


def test_url_builder_handles_ports_and_ipv6() -> None:
    assert fp._build_url("https", "a.example.com", 443, "/x") == "https://a.example.com/x"
    assert fp._build_url("http", "a.example.com", 80, "x") == "http://a.example.com/x"
    assert fp._build_url("https", "a.example.com", 8443, "/x") == "https://a.example.com:8443/x"
    assert fp._build_url("http", "2001:db8::1", 8080, "/x") == "http://[2001:db8::1]:8080/x"


# --------------------------------------------------------------------------- #
# Integration against a real aiohttp server + a real WebProbe (loopback only)
# --------------------------------------------------------------------------- #


class _LoopbackResolver:
    """Resolver stub pinning every name to 127.0.0.1 (no DNS, no internet)."""

    def __init__(self, ip: str = "127.0.0.1") -> None:
        self.ip = ip

    async def resolve(self, host: str, log: bool = False) -> Any:
        class _Result:
            addresses = (self.ip,)

        return _Result()

    async def close(self) -> None:  # pragma: no cover - interface parity
        return None


async def test_fingerprint_against_a_live_loopback_webprobe() -> None:
    """End-to-end proof that the private-session accessor works on the real class.

    Nothing leaves the machine: an in-process ``aiohttp`` server is bound to
    ``127.0.0.1`` and a real :class:`WebProbe` resolves ``a.example.com`` to that
    loopback address through :class:`_LoopbackResolver`.
    """
    aiohttp_web = pytest.importorskip("aiohttp.web")
    try:
        from subsonar.core.web_probe import WebProbe
    except Exception as exc:  # pragma: no cover - concurrent workstream
        pytest.skip(f"web_probe unavailable: {exc}")

    seen: list[tuple[str, str]] = []

    @aiohttp_web.middleware
    async def recorder(request: Any, handler: Any) -> Any:
        # Middleware sees every request, including the 405 the router raises for a
        # method that is not registered (which never reaches the handler).
        seen.append((request.method, request.path))
        return await handler(request)

    async def root(request: Any) -> Any:
        response = aiohttp_web.Response(
            status=200,
            text=(
                "<html><head><title>Live Loopback</title>"
                '<meta name="generator" content="WordPress 6.4">'
                '<script src="/wp-content/themes/x/js/jquery.min.js"></script>'
                "</head><body>ok</body></html>"
            ),
            content_type="text/html",
        )
        response.headers["Server"] = "nginx/1.24.0"
        response.headers["X-Powered-By"] = "PHP/8.2.7"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=63072000"
        # two Set-Cookie headers exercise CIMultiDict handling (no dict collapse)
        response.headers.add("Set-Cookie", f"PHPSESSID={COOKIE_SECRET}; Path=/; HttpOnly")
        response.headers.add("Set-Cookie", "csrf_token=zzz; Path=/")
        return response

    async def icon(request: Any) -> Any:
        return aiohttp_web.Response(body=PNG_1X1, content_type="image/x-icon")

    async def robots(request: Any) -> Any:
        return aiohttp_web.Response(text="User-agent: *\n", content_type="text/plain")

    async def env(request: Any) -> Any:
        return aiohttp_web.Response(
            text=f"SECRET_KEY={SECRET_ENV_VALUE}\n", content_type="text/plain"
        )

    async def server_status(request: Any) -> Any:
        if request.method == "HEAD":
            return aiohttp_web.Response(status=405)
        return aiohttp_web.Response(text="Apache Server Status", content_type="text/html")

    app = aiohttp_web.Application(middlewares=[recorder])
    app.router.add_get("/", root)
    app.router.add_get("/favicon.ico", icon)
    app.router.add_get("/robots.txt", robots)
    app.router.add_get("/.env", env)
    app.router.add_get("/server-status", server_status, allow_head=False)

    runner = aiohttp_web.AppRunner(app)
    await runner.setup()
    site = aiohttp_web.TCPSite(runner, "127.0.0.1", 0)
    try:
        await site.start()
    except OSError as exc:  # pragma: no cover - sandbox without loopback binds
        await runner.cleanup()
        pytest.skip(f"loopback bind unavailable: {exc}")
    port = runner.addresses[0][1]
    probe = WebProbe(resolver=_LoopbackResolver(), timeout=5.0, concurrency=4)
    try:
        result = await fingerprint(
            probe, "http", "a.example.com", "127.0.0.1", port, timeout=5.0, bus=EventBus()
        )
    finally:
        await probe.close()
        await runner.cleanup()

    # headers came off a real aiohttp response through WebProbe._session
    assert result.server == "nginx/1.24.0"
    assert result.headers["X-Powered-By"] == "PHP/8.2.7"
    assert result.headers["X-Frame-Options"] == "DENY"
    assert result.headers["Strict-Transport-Security"] == "max-age=63072000"
    assert result.headers["Set-Cookie"] == "PHPSESSID, csrf_token"
    assert COOKIE_SECRET not in json.dumps(result.to_dict())
    # a real favicon was hashed with the Shodan recipe
    assert result.favicon_hash == str(
        to_signed32(murmur3_x86_32(base64.encodebytes(PNG_1X1)))
    )
    # technologies detected from a real body, real headers and real cookies
    assert {"nginx", "PHP", "WordPress", "jQuery"} <= set(result.names)
    # data-file statuses from a real server: 200, 404 and the HEAD→GET fallback
    assert result.data_files["/robots.txt"] == 200
    assert result.data_files["/.env"] == 200
    assert result.data_files["/sitemap.xml"] == 404
    assert result.data_files["/server-status"] == 200
    assert ("HEAD", "/.env") in seen and ("GET", "/.env") not in seen
    assert ("HEAD", "/server-status") in seen and ("GET", "/server-status") in seen
    assert result.interesting_paths.get("/wp-login.php") is None  # 404 on this server


def test_signatures_module_has_no_network_or_project_imports() -> None:
    """``signatures`` must stay importable on its own (pure data + ``re``)."""
    import inspect
    import re as _re

    from subsonar.core import signatures as signatures_module

    source = inspect.getsource(signatures_module)
    imported = set(_re.findall(r"^(?:from|import)\s+([\w.]+)", source, _re.MULTILINE))
    assert imported <= {"__future__", "re", "dataclasses", "functools", "typing"}, imported


def test_fingerprint_module_does_not_import_the_prober() -> None:
    """No web_probe / engine / aiohttp import — the engine workstream stays decoupled."""
    import inspect
    import re as _re

    source = inspect.getsource(fp)
    imported = set(_re.findall(r"^(?:from|import)\s+([\w.]+)", source, _re.MULTILINE))
    assert imported == {
        "__future__",
        "asyncio",
        "base64",
        "inspect",
        "re",
        "collections.abc",
        "dataclasses",
        "typing",
        ".events",
        ".signatures",
    }, imported
    assert not any(
        token in name for name in imported for token in ("web_probe", "engine", "aiohttp")
    )
