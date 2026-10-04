"""Web mining — robots.txt / sitemap.xml / security.txt / header host extraction.

The parsers are pure and tested directly; the fetcher is exercised through a
stubbed aiohttp module, so no test here touches the network.
"""

from __future__ import annotations

from typing import Any

import pytest

from subsonar.core import miner, mining
from subsonar.core.events import EventBus


# --------------------------------------------------------------------------- #
# Pure parsing
# --------------------------------------------------------------------------- #


def test_extract_hosts_keeps_only_in_scope_names() -> None:
    text = (
        "see https://api.example.com/v1 and //cdn.example.com/x "
        "and https://evil.test/ and https://example.com/ and "
        "not-a-host and http://192.0.2.1/"
    )
    assert mining.extract_hosts(text, "example.com") == [
        "api.example.com",
        "cdn.example.com",
        "example.com",
    ]
    assert mining.extract_hosts(text, "example.com", allow_subdomains=False) == [
        "example.com"
    ]
    assert mining.extract_hosts("", "example.com") == []


def test_sitemap_locations_and_entries() -> None:
    body = (
        "<?xml version='1.0'?>"
        "<urlset><url><loc>https://shop.example.com/a</loc></url>"
        "<url><loc>https://www.example.com/b</loc></url>"
        "<url><loc>https://evil.test/c</loc></url></urlset>"
    )
    assert mining.extract_sitemap_locations(body) == [
        "https://shop.example.com/a",
        "https://www.example.com/b",
        "https://evil.test/c",
    ]
    assert mining.mine_sitemap_entries(body, "example.com") == [
        "shop.example.com",
        "www.example.com",
    ]
    # A sitemap index names further sitemaps, not hosts.
    index = "<sitemapindex><sitemap><loc>https://sub.example.com/s.xml</loc></sitemap></sitemapindex>"
    assert mining.mine_sitemap_entries(index, "example.com") == ["sub.example.com"]
    assert mining.mine_sitemap_entries("<loc>x</loc>", "example.com") == []


def test_mine_headers_only_reads_host_bearing_headers() -> None:
    headers = {
        "Content-Security-Policy": (
            "default-src 'self'; report-uri https://reports.example.com/csp; "
            "img-src https://cdn.example.com"
        ),
        "Link": "<https://rel.example.com/x>; rel=preconnect",
        "Location": "https://redirected.example.com/landing",
        "X-Backend-Server": "internal.example.com",
        "Set-Cookie": "session=abc; Domain=cookies.example.com",
        "Content-Type": "text/html",
    }
    found = mining.mine_headers(headers, "example.com")
    assert "reports.example.com" in found
    assert "cdn.example.com" in found
    assert "rel.example.com" in found
    assert "redirected.example.com" in found
    assert "internal.example.com" in found
    # The cookie domain is deliberately not on the header allow-list.
    assert "cookies.example.com" not in found


def test_mine_headers_accepts_a_list_of_pairs() -> None:
    pairs = [("Content-Security-Policy", "script-src https://scripts.example.com")]
    assert mining.mine_headers(pairs, "example.com") == ["scripts.example.com"]


def test_summarise_is_human_readable() -> None:
    assert mining.summarise([], "example.com", source="headers").endswith(
        "no new in-scope hostname"
    )
    message = mining.summarise(
        [f"h{index}.example.com" for index in range(7)], "example.com", source="sitemap"
    )
    assert "7 in-scope hostname(s)" in message and "+2 more" in message


# --------------------------------------------------------------------------- #
# Fetching (stubbed aiohttp)
# --------------------------------------------------------------------------- #


class _Content:
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def read(self, size: int = -1) -> bytes:
        return self.body if size is None or size < 0 else self.body[:size]


class _Response:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.content = _Content(body)

    async def __aenter__(self) -> "_Response":
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False


class _Session:
    """Session that answers from a ``{url: (status, body)}`` map."""

    def __init__(self, routes: dict[str, tuple[int, bytes]], **kwargs: Any) -> None:
        self.routes = routes
        self.requests: list[str] = []

    async def __aenter__(self) -> "_Session":
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    def get(self, url: str) -> _Response:
        self.requests.append(url)
        status, body = self.routes.get(url, (404, b""))
        return _Response(status, body)


class _Aiohttp:
    """Minimal stand-in for the ``aiohttp`` module surface the miner uses."""

    def __init__(self, routes: dict[str, tuple[int, bytes]]) -> None:
        self.routes = routes
        self.sessions: list[_Session] = []

    @staticmethod
    def ClientTimeout(**kwargs: Any) -> Any:  # noqa: N802 - aiohttp casing
        return kwargs

    @staticmethod
    def TCPConnector(**kwargs: Any) -> Any:  # noqa: N802 - aiohttp casing
        return kwargs

    def ClientSession(self, **kwargs: Any) -> _Session:  # noqa: N802 - aiohttp casing
        session = _Session(self.routes, **kwargs)
        self.sessions.append(session)
        return session


ROBOTS = (
    "User-agent: *\n"
    "Disallow: /admin\n"
    "Sitemap: https://sub.example.com/sitemap.xml\n"
    "Sitemap: https://evil.test/sitemap.xml\n"
)
SITEMAP = (
    "<urlset><url><loc>https://shop.example.com/a</loc></url>"
    "<url><loc>https://www.example.com/</loc></url></urlset>"
)
SECURITY = (
    "Contact: mailto:security@example.com\n"
    "Policy: https://policies.example.com/security\n"
    "Canonical: https://www.example.com/.well-known/security.txt\n"
)


def _routes() -> dict[str, tuple[int, bytes]]:
    return {
        "https://example.com/robots.txt": (200, ROBOTS.encode()),
        "https://example.com/sitemap.xml": (200, SITEMAP.encode()),
        "https://example.com/.well-known/security.txt": (200, SECURITY.encode()),
        "https://sub.example.com/sitemap.xml": (
            200,
            b"<urlset><url><loc>https://blog.example.com/post</loc></url></urlset>",
        ),
        "https://api.example.com/robots.txt": (403, b"forbidden"),
    }


async def test_fetch_and_mine_collects_hosts_from_every_source(monkeypatch) -> None:
    fake = _Aiohttp(_routes())
    monkeypatch.setattr(miner, "aiohttp", fake)
    bus = EventBus()
    found = await miner.fetch_and_mine(
        [
            ("https", "example.com", 443),
            ("https", "api.example.com", 443),
        ],
        "example.com",
        bus=bus,
    )
    assert set(found) == {
        "sub.example.com",
        "shop.example.com",
        "www.example.com",
        "policies.example.com",
        "blog.example.com",
    }
    assert "evil.test" not in found
    assert "192.0.2.1" not in found
    # Only published files are requested, never anything else.
    requested = {url for session in fake.sessions for url in session.requests}
    assert "https://example.com/robots.txt" in requested
    assert all(url.endswith(("robots.txt", "sitemap.xml", "security.txt")) for url in requested)


async def test_fetch_and_mine_skips_non_200_and_empty_bodies(monkeypatch) -> None:
    monkeypatch.setattr(miner, "aiohttp", _Aiohttp({}))
    assert await miner.fetch_and_mine([("https", "example.com", 443)], "example.com") == []


async def test_fetch_paths_builds_urls_with_an_explicit_port(monkeypatch) -> None:
    fake = _Aiohttp({"https://example.com:8443/robots.txt": (200, b"ok")})
    monkeypatch.setattr(miner, "aiohttp", fake)
    fetched = await miner.fetch_paths([("https", "example.com", 8443)])
    assert fetched == [("example.com", "/robots.txt", "ok")]


async def test_fetcher_degrades_gracefully_without_aiohttp(monkeypatch) -> None:
    monkeypatch.setattr(miner, "aiohttp", None)
    assert await miner.fetch_and_mine([("https", "example.com", 443)], "example.com") == []


async def test_fetch_errors_do_not_abort_the_mining(monkeypatch) -> None:
    class Exploding(_Session):
        def get(self, url: str) -> _Response:  # type: ignore[override]
            raise OSError("connection reset")

    class Fake(_Aiohttp):
        def ClientSession(self, **kwargs):  # noqa: N802
            return Exploding({}, **kwargs)

    monkeypatch.setattr(miner, "aiohttp", Fake({}))
    assert await miner.fetch_paths([("https", "example.com", 443)]) == []



# --------------------------------------------------------------------------- #
# Engine integration (mining phase + second wave)
# --------------------------------------------------------------------------- #


def _engine(**kwargs):
    from subsonar.core.config import ScanConfig
    from subsonar.core.engine import ScanEngine

    config = ScanConfig(domain="example.com", **kwargs)
    return ScanEngine(config, profile=3, bus=EventBus())


def _finding_with_headers(**headers: str):
    from subsonar.core.engine import Finding

    finding = Finding(
        subdomain="www.example.com",
        ip="203.0.113.5",
        port=443,
        scheme="https",
        url="https://www.example.com",
        status=200,
        title="Home",
    )
    finding.headers = {"content-security-policy": "; ".join(
        f"{key} {value}" for key, value in headers.items()
    )}
    return finding


async def test_mining_phase_collects_header_and_file_hosts(monkeypatch) -> None:
    engine = _engine(mining_wave2=False)
    engine.result.findings.append(
        _finding_with_headers(**{"report-uri": "https://csp.example.com/r"})
    )

    async def fake_fetch(targets, domain, *, bus=None, concurrency=6, timeout=6.0):
        assert targets and domain == "example.com"
        return ["fromfile.example.com"]

    monkeypatch.setattr(miner, "fetch_and_mine", fake_fetch)
    await engine._phase_mining()
    assert engine.result.mined_hosts == {"csp.example.com", "fromfile.example.com"}
    assert "csp.example.com" in engine.result.osint_hosts
    assert engine.result.wave2_hosts == set()  # wave 2 disabled in the config


async def test_mining_phase_is_skippable(monkeypatch) -> None:
    engine = _engine(web_mining=False)
    engine.result.findings.append(_finding_with_headers(**{"report-uri": "https://csp.example.com"}))

    async def boom(*args, **kwargs):  # pragma: no cover - must not be called
        raise AssertionError("mining must be disabled")

    monkeypatch.setattr(miner, "fetch_and_mine", boom)
    await engine._phase_mining()
    assert engine.result.mined_hosts == set()


async def test_mining_phase_survives_a_failing_fetcher(monkeypatch) -> None:
    engine = _engine(mining_wave2=False)
    engine.result.findings.append(_finding_with_headers(**{"x-host": "hdr.example.com"}))

    async def boom(*args, **kwargs):
        raise OSError("socket closed")

    monkeypatch.setattr(miner, "fetch_and_mine", boom)
    await engine._phase_mining()
    # The header host is still reported even though the fetcher exploded.
    assert engine.result.mined_hosts == {"hdr.example.com"}


async def test_already_known_hosts_are_not_reported_as_mined(monkeypatch) -> None:
    from subsonar.core.dns import DNSResult

    engine = _engine(mining_wave2=False)
    engine.result.resolutions["www.example.com"] = DNSResult(
        name="www.example.com", addresses=["203.0.113.5"]
    )
    engine.result.findings.append(
        _finding_with_headers(**{"report-uri": "https://www.example.com/r"})
    )

    async def fake_fetch(*args, **kwargs):
        return ["www.example.com"]

    monkeypatch.setattr(miner, "fetch_and_mine", fake_fetch)
    await engine._phase_mining()
    assert engine.result.mined_hosts == set()


async def test_second_wave_resolves_and_sweeps_mined_hosts(monkeypatch) -> None:
    from subsonar.core.dns import DNSResult

    engine = _engine()
    engine.result.findings.append(
        _finding_with_headers(**{"report-uri": "https://csp.example.com/r"})
    )

    async def fake_fetch(*args, **kwargs):
        return ["mined.example.com"]

    monkeypatch.setattr(miner, "fetch_and_mine", fake_fetch)
    swept: list[list[str]] = []

    async def fake_resolve(hosts, *, label="batch"):
        return [DNSResult(name=host, addresses=["203.0.113.7"]) for host in hosts]

    async def fake_sweep(batch, ports):
        swept.append([item.name for item in batch])

    monkeypatch.setattr(engine, "_resolve_batch", fake_resolve)
    monkeypatch.setattr(engine, "_sweep_batch", fake_sweep)
    await engine._phase_mining()

    assert engine.result.mined_hosts == {"csp.example.com", "mined.example.com"}
    assert engine.result.wave2_hosts == {"csp.example.com", "mined.example.com"}
    assert swept == [["csp.example.com", "mined.example.com"]]
    assert "second wave     : 2 mined host(s) scanned" in engine.result.summary_lines()
    assert engine.result.to_dict()["wave2_hosts"] == [
        "csp.example.com",
        "mined.example.com",
    ]


async def test_second_wave_is_capped_by_max_wave2_hosts(monkeypatch) -> None:
    from subsonar.core.dns import DNSResult

    engine = _engine()
    engine.config.max_wave2_hosts = 3
    engine.result.findings.append(_finding_with_headers())

    async def fake_fetch(*args, **kwargs):
        return [f"h{index}.example.com" for index in range(10)]

    async def fake_resolve(hosts, *, label="batch"):
        return [DNSResult(name=host, addresses=["203.0.113.7"]) for host in hosts]

    async def fake_sweep(batch, ports):
        return None

    monkeypatch.setattr(miner, "fetch_and_mine", fake_fetch)
    monkeypatch.setattr(engine, "_resolve_batch", fake_resolve)
    monkeypatch.setattr(engine, "_sweep_batch", fake_sweep)
    await engine._phase_mining()
    assert len(engine.result.wave2_hosts) == 3
    assert len(engine.result.mined_hosts) == 10

