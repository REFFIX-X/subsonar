"""Verification suite for the discovery-source plugin architecture.

Every test is offline: sources are driven through a fake ``aiohttp`` session whose
``get()`` returns an async context manager exposing ``.status``, ``.text()`` and
``.json()``.  A stray request to an unmocked URL fails the test loudly
(``pytest.fail`` raises ``Failed``, a ``BaseException`` the source's own
``except Exception`` guard cannot swallow).
"""

from __future__ import annotations

import asyncio
import inspect
import json
import time
from types import SimpleNamespace
from typing import Any, AsyncIterator, Iterable

import aiohttp
import pytest

from subsonar.core.events import EventBus
from subsonar.core.sources import (
    DISCOVERED,
    REGISTRY,
    DiscoverySource,
    all_sources,
    collect,
    discover_plugins,
    free_sources,
    get_source,
    register,
)
from subsonar.core.sources import (
    certspotter,
    commoncrawl,
    otx,
    rapiddns,
    threatminer,
    urlscan,
)

DOMAIN = "example.com"

# --------------------------------------------------------------------------- #
# Fake aiohttp transport
# --------------------------------------------------------------------------- #


class FakeResponse:
    """Stands in for ``aiohttp.ClientResponse`` (async context manager)."""

    def __init__(self, status: int = 200, text: str = "", json_data: Any = None) -> None:
        self.status = status
        self._text = text
        self._json = json_data

    async def __aenter__(self) -> "FakeResponse":
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    async def text(self) -> str:
        return self._text

    async def json(self, **kwargs: Any) -> Any:
        if self._json is None:
            raise ValueError("no JSON body")
        return self._json


class FakeSession:
    """Minimal ``aiohttp.ClientSession`` replacement."""

    def __init__(self, handler: Any, **kwargs: Any) -> None:
        self._handler = handler
        self.kwargs = kwargs
        self.urls: list[str] = []
        self.closed = 0

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.urls.append(url)
        return self._handler(url)

    async def close(self) -> None:
        self.closed += 1


def routed_session(routes: dict[str, Any]) -> FakeSession:
    """Session whose response depends on a substring of the requested URL."""

    def handler(url: str) -> FakeResponse:
        for needle, response in routes.items():
            if needle in url:
                if isinstance(response, BaseException):
                    raise response
                if callable(response):
                    return response(url)
                return response
        pytest.fail(f"unexpected network request: {url}")

    return FakeSession(handler)


def offline_session() -> FakeSession:
    """Session that fails the test if a source actually performs a request."""

    def handler(url: str) -> FakeResponse:
        pytest.fail(f"unexpected network request: {url}")

    return FakeSession(handler)


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


def messages(bus: EventBus) -> list[str]:
    return [event.message for event in bus.history()]


def warnings(bus: EventBus) -> list[str]:
    return [event.message for event in bus.history() if event.severity == "warn"]


async def stream(source: DiscoverySource, domain: str = DOMAIN) -> list[Any]:
    return [result async for result in source.fetch(domain)]


# --------------------------------------------------------------------------- #
# Saved fixtures (shapes captured from each public API)
# --------------------------------------------------------------------------- #

HTML_ERROR = (
    "<!doctype html><html><head><title>429 Too Many Requests</title></head>"
    "<body><h1>Rate limited</h1><p>Slow down.</p></body></html>"
)

CERTSPOTTER_FIXTURE = """
[
  {"id": 101, "dns_names": ["www.example.com", "*.example.com", "api.example.com",
                            "api.example.com"], "issuer": {"name": "R3"}},
  {"id": 102, "dns_names": ["dev.example.com", "notexample.com", "evil.test",
                            "1.2.3.4"], "issuer": {"name": "R10"}}
]
"""

URLSCAN_FIXTURE = """
{"results": [
   {"page": {"domain": "shop.example.com", "url": "https://shop.example.com/"}},
   {"page": {"domain": "EXAMPLE.com"}},
   {"page": {"domain": "other.org"}},
   {"page": {}},
   {"task": {"uuid": "x"}}
 ],
 "total": 4}
"""

OTX_FIXTURE = """
{"passive_dns": [
   {"hostname": "mail.example.com", "address": "203.0.113.10", "record_type": "A"},
   {"hostname": "cdn.example.com", "address": "not-an-ip", "record_type": "CNAME"},
   {"hostname": "old.example.net", "address": "198.51.100.3", "record_type": "A"},
   {"address": "203.0.113.11", "record_type": "A"}
 ],
 "count": 4}
"""

THREATMINER_FIXTURE = """
{"status_code": "200", "status_message": "Results found.",
 "results": ["vpn.example.com", "ftp.example.com", "ftp.example.com",
             "badexample.com"]}
"""

THREATMINER_EMPTY_FIXTURE = (
    '{"status_code": "404", "status_message": "No results found.", "results": []}'
)

RAPIDDNS_FIXTURE = """
<!doctype html><html><body>
<nav><ul><li><a href="/">RapidDNS</a></li></ul></nav>
<table class="table table-striped">
  <thead><tr><th>#</th><th>Subdomain</th><th>Type</th><th>IP</th><th>Date</th></tr></thead>
  <tbody>
    <tr><td>1</td><td>blog.example.com</td><td>A</td><td>203.0.113.7</td>
        <td>2024-01-01</td></tr>
    <tr><td>2</td><td><a href="//store.example.com">store.example.com</a></td>
        <td>CNAME</td><td>203.0.113.8</td><td>2024-01-02</td></tr>
    <tr><td>3</td><td>evil.test</td><td>A</td><td>198.51.100.2</td>
        <td>2024-01-03</td></tr>
    <tr><td>4</td><td>blog.example.com</td><td>A</td><td>203.0.113.7</td>
        <td>2024-01-04</td></tr>
  </tbody>
</table>
<footer><p>&copy; RapidDNS</p></footer>
</body></html>
"""

COLLINFO_FIXTURE = """
[{"id": "CC-MAIN-2023-50", "name": "December 2023 Index",
  "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2023-50-index"},
 {"id": "CC-MAIN-2024-38", "name": "September 2024 Index",
  "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2024-38-index"},
 {"id": "CC-MAIN-2024-33", "name": "August 2024 Index",
  "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2024-33-index"}]
"""

COMMONCRAWL_FIXTURE = (
    '{"urlkey": "com,example)/blog", "timestamp": "20240101120000",'
    ' "url": "https://blog.example.com/post/1", "status": "200",'
    ' "mime": "text/html"}\n'
    '{"urlkey": "com,example)/", "timestamp": "20240101120001",'
    ' "url": "http://example.com/", "status": "200", "mime": "text/html"}\n'
    '{"urlkey": "test,evil)/", "timestamp": "20240101120002",'
    ' "url": "https://evil.test/x", "status": "200", "mime": "text/html"}\n'
    "this line is not JSON at all\n"
    '{"urlkey": "com,example)/cart", "timestamp": "20240101120003",'
    ' "url": "https://shop.example.com:8443/cart", "status": "200"}'
)

NO_CAPTURES_FIXTURE = "No Captures found for: example.com"

# --------------------------------------------------------------------------- #
# Expected results
# --------------------------------------------------------------------------- #

EXPECTED_CERTSPOTTER = {
    "www.example.com",
    "example.com",
    "api.example.com",
    "dev.example.com",
}
EXPECTED_URLSCAN = {"shop.example.com", "example.com"}
EXPECTED_OTX = {"mail.example.com", "cdn.example.com"}
EXPECTED_THREATMINER = {"vpn.example.com", "ftp.example.com"}
EXPECTED_RAPIDDNS = {"blog.example.com", "store.example.com"}
EXPECTED_COMMONCRAWL = {"blog.example.com", "example.com", "shop.example.com"}


def _certspotter_routes() -> dict[str, Any]:
    return {"api.certspotter.com": FakeResponse(200, CERTSPOTTER_FIXTURE)}


def _urlscan_routes() -> dict[str, Any]:
    return {"urlscan.io/api/v1/search": FakeResponse(200, URLSCAN_FIXTURE)}


def _otx_routes() -> dict[str, Any]:
    return {"otx.alienvault.com": FakeResponse(200, OTX_FIXTURE)}


def _threatminer_routes() -> dict[str, Any]:
    return {"api.threatminer.org": FakeResponse(200, THREATMINER_FIXTURE)}


def _rapiddns_routes() -> dict[str, Any]:
    return {"rapiddns.io/subdomain": FakeResponse(200, RAPIDDNS_FIXTURE)}


def _commoncrawl_routes() -> dict[str, Any]:
    return {
        "collinfo.json": FakeResponse(200, COLLINFO_FIXTURE),
        "-index": FakeResponse(200, COMMONCRAWL_FIXTURE),
    }


MOCKED_CASES = [
    pytest.param(
        certspotter.CertSpotterSource,
        _certspotter_routes,
        EXPECTED_CERTSPOTTER,
        id="certspotter",
    ),
    pytest.param(
        rapiddns.RapidDNSSource, _rapiddns_routes, EXPECTED_RAPIDDNS, id="rapiddns"
    ),
    pytest.param(
        urlscan.UrlScanSource, _urlscan_routes, EXPECTED_URLSCAN, id="urlscan"
    ),
    pytest.param(otx.OTXSource, _otx_routes, EXPECTED_OTX, id="otx"),
    pytest.param(
        threatminer.ThreatMinerSource,
        _threatminer_routes,
        EXPECTED_THREATMINER,
        id="threatminer",
    ),
    pytest.param(
        commoncrawl.CommonCrawlSource,
        _commoncrawl_routes,
        EXPECTED_COMMONCRAWL,
        id="commoncrawl",
    ),
]

ALL_PLUGINS = (
    "certspotter",
    "rapiddns",
    "urlscan",
    "otx",
    "threatminer",
    "commoncrawl",
    "subdomain-center",
)

#: Module basenames — what :func:`discover_plugins` reports (the module and the
#: registry name differ wherever the name uses a dash).
ALL_MODULES = (
    "certspotter",
    "rapiddns",
    "urlscan",
    "otx",
    "threatminer",
    "commoncrawl",
    "subdomaincenter",
)

# --------------------------------------------------------------------------- #
# Registry / plugin architecture
# --------------------------------------------------------------------------- #


def test_registry_auto_discovers_every_plugin() -> None:
    for name in ALL_PLUGINS:
        source = get_source(name)
        assert isinstance(source, DiscoverySource)
        assert source.name == name
        assert REGISTRY[name] is source


def test_discover_plugins_reports_every_module_and_is_idempotent() -> None:
    known = {source.name: source for source in all_sources()}
    loaded = discover_plugins()
    assert set(ALL_MODULES) <= set(loaded)
    assert loaded == sorted(loaded)
    assert len(REGISTRY) == len(loaded)
    for name, source in known.items():
        assert get_source(name) is source


def test_discovered_module_list_matches_every_plugin() -> None:
    assert set(DISCOVERED) == set(ALL_MODULES)


def test_get_source_rejects_unknown_names() -> None:
    assert get_source("CERTSPOTTER") is get_source("certspotter")
    with pytest.raises(KeyError) as excinfo:
        get_source("nope")
    assert "unknown discovery source" in str(excinfo.value)


def test_all_and_free_sources_are_consistent() -> None:
    everything = all_sources()
    assert len(everything) == len(REGISTRY) == len(ALL_PLUGINS)
    assert [source.name for source in everything] == sorted(REGISTRY)
    assert all(source.free for source in everything)
    assert free_sources() == everything


def test_every_source_honours_the_plugin_contract() -> None:
    for source in all_sources():
        assert source.description
        assert source.free is True
        assert source.requires_key is False
        assert source.available() is True
        assert source.timeout < 60.0
        assert source.max_results == 5000
        assert inspect.isasyncgenfunction(source.fetch)
        assert inspect.isasyncgenfunction(source.fetch_hosts)


def test_register_decorator_adds_and_protects_entries() -> None:
    try:

        @register
        class EphemeralSource(DiscoverySource):
            name = "ephemeral"
            description = "test-only source"

        assert REGISTRY["ephemeral"].name == "ephemeral"
        assert isinstance(REGISTRY["ephemeral"], EphemeralSource)
        assert get_source("ephemeral") is REGISTRY["ephemeral"]

        with pytest.warns(RuntimeWarning):

            @register
            class DuplicateSource(DiscoverySource):
                name = "ephemeral"

        assert isinstance(REGISTRY["ephemeral"], EphemeralSource)
    finally:
        REGISTRY.pop("ephemeral", None)


def test_register_supports_a_custom_name() -> None:
    try:

        @register("custom-name")
        class CustomSource(DiscoverySource):
            description = "named via decorator argument"

        assert REGISTRY["custom-name"].name == "custom-name"
    finally:
        REGISTRY.pop("custom-name", None)


def test_register_rejects_non_sources() -> None:
    with pytest.raises(TypeError):
        register(object)  # type: ignore[arg-type]


def test_free_sources_filters_non_free_and_unavailable() -> None:
    try:

        @register
        class PaidSource(DiscoverySource):
            name = "paid-test"
            free = False

        @register
        class KeyedSource(DiscoverySource):
            name = "keyed-test"
            requires_key = True
            env_var = "SUBSONAR_TEST_KEY"

            def available(self) -> bool:
                return False

        names = {source.name for source in free_sources()}
        assert "paid-test" not in names
        assert "keyed-test" not in names
        assert names == set(ALL_PLUGINS)
    finally:
        REGISTRY.pop("paid-test", None)
        REGISTRY.pop("keyed-test", None)


# --------------------------------------------------------------------------- #
# Offline parse steps
# --------------------------------------------------------------------------- #

PARSE_CASES = [
    pytest.param(
        certspotter.parse_dns_names,
        CERTSPOTTER_FIXTURE,
        [
            "www.example.com",
            "*.example.com",
            "api.example.com",
            "api.example.com",
            "dev.example.com",
            "notexample.com",
            "evil.test",
            "1.2.3.4",
        ],
        id="certspotter",
    ),
    pytest.param(
        rapiddns.parse_table,
        RAPIDDNS_FIXTURE,
        [
            ("blog.example.com", "203.0.113.7"),
            ("store.example.com", "203.0.113.8"),
            ("evil.test", "198.51.100.2"),
            ("blog.example.com", "203.0.113.7"),
        ],
        id="rapiddns",
    ),
    pytest.param(
        urlscan.parse_results,
        URLSCAN_FIXTURE,
        ["shop.example.com", "EXAMPLE.com", "other.org"],
        id="urlscan",
    ),
    pytest.param(
        otx.parse_passive_dns,
        OTX_FIXTURE,
        [
            ("mail.example.com", "203.0.113.10"),
            ("cdn.example.com", "not-an-ip"),
            ("old.example.net", "198.51.100.3"),
        ],
        id="otx",
    ),
    pytest.param(
        threatminer.parse_results,
        THREATMINER_FIXTURE,
        ["vpn.example.com", "ftp.example.com", "ftp.example.com", "badexample.com"],
        id="threatminer",
    ),
    pytest.param(
        commoncrawl.parse_index_hosts,
        COMMONCRAWL_FIXTURE,
        ["blog.example.com", "example.com", "evil.test", "shop.example.com"],
        id="commoncrawl",
    ),
]


@pytest.mark.parametrize("parser, fixture, expected", PARSE_CASES)
def test_parse_step_works_on_saved_fixture(parser: Any, fixture: str, expected: Any) -> None:
    assert parser(fixture) == expected


@pytest.mark.parametrize("parser, fixture, expected", PARSE_CASES)
def test_parse_step_tolerates_garbage(parser: Any, fixture: str, expected: Any) -> None:
    for broken in (HTML_ERROR, "", "{not json", "null"):
        assert parser(broken) == []


def test_threatminer_empty_and_missing_result_shapes() -> None:
    assert threatminer.parse_results(THREATMINER_EMPTY_FIXTURE) == []
    assert threatminer.parse_results('{"status_code": "200"}') == []


def test_commoncrawl_collinfo_parsing() -> None:
    assert commoncrawl.parse_collinfo(COLLINFO_FIXTURE) == "CC-MAIN-2024-38"
    assert commoncrawl.parse_collinfo("[]") is None
    assert commoncrawl.parse_collinfo(HTML_ERROR) is None
    # An unparseable id still yields the newest entry reported by the API.
    assert commoncrawl.parse_collinfo('[{"id": "custom-index"}]') == "custom-index"


def test_commoncrawl_no_captures_fixture_is_empty() -> None:
    assert commoncrawl.parse_index_hosts(NO_CAPTURES_FIXTURE) == []


# --------------------------------------------------------------------------- #
# Mocked end-to-end fetch per source
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("source_cls, routes, expected", MOCKED_CASES)
async def test_mocked_source_filters_dedupes_and_logs(
    bus: EventBus,
    source_cls: type[DiscoverySource],
    routes: Any,
    expected: set[str],
) -> None:
    session = routed_session(routes())
    source = source_cls(session=session, bus=bus)
    results = await stream(source)

    hosts = [result.host for result in results]
    assert set(hosts) == expected
    assert len(hosts) == len(set(hosts)), "duplicates must collapse"
    assert all(result.source == source.name for result in results)
    assert all(result.target == DOMAIN for result in results)
    assert all(result.host == result.host.lower() for result in results)

    log = messages(bus)
    assert f"Querying {source.name} asynchronously..." in log
    assert (
        f"{source.name} returned {len(expected)} in-scope hostname(s) for {DOMAIN}"
        in log
    )
    assert source.report.hosts == len(expected)
    assert source.report.errors == 0
    assert source.report.requests >= 1


@pytest.mark.parametrize("source_cls, routes, expected", MOCKED_CASES)
async def test_malformed_html_response_yields_zero_without_raising(
    bus: EventBus,
    source_cls: type[DiscoverySource],
    routes: Any,
    expected: set[str],
) -> None:
    session = FakeSession(lambda url: FakeResponse(200, HTML_ERROR))
    source = source_cls(session=session, bus=bus)
    results = await stream(source)

    assert results == []
    log = messages(bus)
    assert f"Querying {source.name} asynchronously..." in log
    assert f"{source.name} returned 0 in-scope hostname(s) for {DOMAIN}" in log


async def test_out_of_scope_hostnames_are_filtered(bus: EventBus) -> None:
    payload = json.dumps(
        [
            {
                "dns_names": [
                    "evil.com",
                    "notexample.com",
                    "example.com.evil.net",
                    "-bad-.example.com",
                    "1.2.3.4",
                    "deep.sub.example.com",
                    "trailing.example.com.",
                    "*.example.com",
                    "EXAMPLE.com",
                ]
            }
        ]
    )
    session = routed_session(
        {"api.certspotter.com": FakeResponse(200, payload)}
    )
    source = certspotter.CertSpotterSource(session=session, bus=bus)
    results = await stream(source)

    assert {result.host for result in results} == {
        "deep.sub.example.com",
        "example.com",
        "trailing.example.com",
    }


async def test_otx_and_rapiddns_attach_ips(bus: EventBus) -> None:
    otx_session = routed_session({"otx.alienvault.com": FakeResponse(200, OTX_FIXTURE)})
    otx_results = await stream(otx.OTXSource(session=otx_session, bus=bus))
    resolved = {result.host: result.ip for result in otx_results}
    assert resolved["mail.example.com"] == "203.0.113.10"
    assert resolved["cdn.example.com"] is None  # "not-an-ip" is discarded

    dns_session = routed_session(
        {"rapiddns.io/subdomain": FakeResponse(200, RAPIDDNS_FIXTURE)}
    )
    dns_results = await stream(rapiddns.RapidDNSSource(session=dns_session, bus=bus))
    assert {result.host: result.ip for result in dns_results} == {
        "blog.example.com": "203.0.113.7",
        "store.example.com": "203.0.113.8",
    }


async def test_rapiddns_falls_back_to_the_plain_endpoint(bus: EventBus) -> None:
    def handler(url: str) -> FakeResponse:
        if "full=1" in url:
            return FakeResponse(503, "upstream unavailable")
        return FakeResponse(200, RAPIDDNS_FIXTURE)

    session = FakeSession(handler)
    source = rapiddns.RapidDNSSource(session=session, bus=bus)
    results = await stream(source)

    assert len(session.urls) == 2
    assert "full=1" in session.urls[0] and "full=1" not in session.urls[1]
    assert {result.host for result in results} == EXPECTED_RAPIDDNS
    assert any("HTTP 503" in message for message in warnings(bus))


async def test_commoncrawl_queries_the_newest_index_and_handles_no_captures(
    bus: EventBus,
) -> None:
    session = routed_session(_commoncrawl_routes())
    await stream(commoncrawl.CommonCrawlSource(session=session, bus=bus))
    index_url = session.urls[1]
    assert "CC-MAIN-2024-38-index" in index_url
    assert "output=json" in index_url
    assert "limit=" in index_url
    assert "example.com" in index_url

    empty_bus = EventBus()
    empty_session = routed_session(
        {
            "collinfo.json": FakeResponse(200, COLLINFO_FIXTURE),
            "-index": FakeResponse(404, NO_CAPTURES_FIXTURE),
        }
    )
    results = await stream(
        commoncrawl.CommonCrawlSource(session=empty_session, bus=empty_bus)
    )
    assert results == []
    assert any("no captures" in message for message in messages(empty_bus))
    assert warnings(empty_bus) == []


# --------------------------------------------------------------------------- #
# Invariants every source must honour
# --------------------------------------------------------------------------- #


async def test_result_cap_truncates_a_huge_response(bus: EventBus) -> None:
    names = [f"host{index}.example.com" for index in range(50)]
    session = routed_session(
        {"api.certspotter.com": FakeResponse(200, json.dumps([{"dns_names": names}]))}
    )
    source = certspotter.CertSpotterSource(session=session, bus=bus, max_results=3)
    results = await stream(source)

    assert [result.host for result in results] == [
        "host0.example.com",
        "host1.example.com",
        "host2.example.com",
    ]
    assert any("result cap reached" in message for message in warnings(bus))


async def test_non_200_status_is_warned_and_never_raised(bus: EventBus) -> None:
    session = routed_session({"api.certspotter.com": FakeResponse(503, "nope")})
    source = certspotter.CertSpotterSource(session=session, bus=bus)
    results = await stream(source)

    assert results == []
    assert source.report.errors == 1
    assert any("HTTP 503" in message for message in warnings(bus))


async def test_network_error_is_caught_and_warned(bus: EventBus) -> None:
    session = routed_session(
        {"api.certspotter.com": aiohttp.ClientConnectionError("connection refused")}
    )
    source = certspotter.CertSpotterSource(session=session, bus=bus)
    results = await stream(source)

    assert results == []
    assert source.report.errors == 1
    assert any(
        "ClientConnectionError" in message for message in warnings(bus)
    )


async def test_broken_json_is_an_empty_result_not_an_error(bus: EventBus) -> None:
    session = routed_session({"api.certspotter.com": FakeResponse(200, "{oops")})
    source = certspotter.CertSpotterSource(session=session, bus=bus)
    results = await stream(source)

    assert results == []
    assert source.report.errors == 0
    assert source.report.note == "no data returned"


async def test_injected_session_is_reused_and_never_closed(bus: EventBus) -> None:
    session = routed_session(_certspotter_routes())
    source = certspotter.CertSpotterSource(session=session, bus=bus)
    await stream(source)

    assert session.closed == 0
    assert source.session is session
    await source.close()
    assert session.closed == 0


async def test_source_closes_only_the_session_it_created(
    monkeypatch: pytest.MonkeyPatch, bus: EventBus
) -> None:
    created: list[FakeSession] = []

    def factory(**kwargs: Any) -> FakeSession:
        session = FakeSession(lambda url: FakeResponse(200, CERTSPOTTER_FIXTURE), **kwargs)
        created.append(session)
        return session

    monkeypatch.setattr(certspotter_module().aiohttp, "ClientSession", factory)
    source = certspotter.CertSpotterSource(bus=bus)
    results = await stream(source)

    assert {result.host for result in results} == EXPECTED_CERTSPOTTER
    assert len(created) == 1
    assert created[0].closed == 1
    assert source.session is None
    assert created[0].kwargs["trust_env"] is False
    assert "subsonar/1.0" in created[0].kwargs["headers"]["User-Agent"]
    timeout = created[0].kwargs["timeout"]
    assert timeout.total == source.timeout < 60.0


def certspotter_module() -> Any:
    """The plugin module's *base* module (it holds the guarded aiohttp import)."""
    from subsonar.core.sources import _base

    return _base


# --------------------------------------------------------------------------- #
# Test doubles for the base-class and merge behaviour
# --------------------------------------------------------------------------- #


class StaticSource(DiscoverySource):
    """Yields canned hostnames; deliberately not registered."""

    name = "static-test"
    description = "test double"

    def __init__(self, hosts: Iterable[Any] = (), **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.hosts = tuple(hosts)

    async def fetch_hosts(self, domain: str) -> AsyncIterator[Any]:
        for host in self.hosts:
            yield host


class ExplodingSource(DiscoverySource):
    """Raises outside the base class' own error handling."""

    name = "exploding-test"

    async def fetch(self, domain: str) -> AsyncIterator[Any]:  # type: ignore[override]
        raise RuntimeError("kaboom")
        yield  # pragma: no cover


class SlowSource(DiscoverySource):
    name = "slow-test"

    async def fetch_hosts(self, domain: str) -> AsyncIterator[Any]:
        await asyncio.sleep(30)
        yield f"late.{domain}"


class CancellingSource(DiscoverySource):
    name = "cancel-test"

    async def fetch_hosts(self, domain: str) -> AsyncIterator[Any]:
        raise asyncio.CancelledError()
        yield  # pragma: no cover


class UnavailableSource(DiscoverySource):
    name = "unavailable-test"
    requires_key = True
    env_var = "SUBSONAR_TEST_KEY"

    def available(self) -> bool:
        return False

    async def fetch_hosts(self, domain: str) -> AsyncIterator[Any]:
        yield f"never.{domain}"


class JsonSource(DiscoverySource):
    name = "json-test"

    async def fetch_hosts(self, domain: str) -> AsyncIterator[Any]:
        status, payload = await self.get_json(f"https://json.test/{domain}")
        if status == 200 and isinstance(payload, dict):
            for host in payload.get("hosts", []):
                yield host


class FakeResolver:
    def __init__(self, ip: str = "203.0.113.99") -> None:
        self.ip = ip
        self.calls: list[str] = []

    async def resolve(self, name: str, *, log: bool = True, ipv6: bool = False) -> Any:
        self.calls.append(name)
        return SimpleNamespace(name=name, ip=self.ip)


async def test_unavailable_source_stops_before_anything_else(bus: EventBus) -> None:
    source = UnavailableSource(session=offline_session(), bus=bus)
    assert await stream(source) == []
    assert any("unavailable" in message for message in warnings(bus))
    assert messages(bus)[0] == "Querying unavailable-test asynchronously..."


async def test_cancelled_error_is_re_raised(bus: EventBus) -> None:
    source = CancellingSource(session=offline_session(), bus=bus)
    with pytest.raises(asyncio.CancelledError):
        await stream(source)


async def test_disabled_available_flag_keeps_free_sources_intact() -> None:
    assert UnavailableSource().available() is False
    assert all(source.available() for source in all_sources())


async def test_get_json_uses_the_response_json_helper(bus: EventBus) -> None:
    payload = {"hosts": ["a.example.com", "b.example.com", "outside.test"]}
    session = routed_session(
        {"json.test": FakeResponse(200, "", json_data=payload)}
    )
    source = JsonSource(session=session, bus=bus)
    results = await stream(source)

    assert {result.host for result in results} == {"a.example.com", "b.example.com"}


async def test_optional_resolver_enriches_missing_ips(bus: EventBus) -> None:
    resolver = FakeResolver()
    source = StaticSource(
        hosts=[("dns.example.com", None), ("known.example.com", "198.51.100.5")],
        session=offline_session(),
        bus=bus,
        resolver=resolver,
    )
    results = await stream(source)

    assert {result.host: result.ip for result in results} == {
        "dns.example.com": "203.0.113.99",
        "known.example.com": "198.51.100.5",
    }
    assert resolver.calls == ["dns.example.com"]


async def test_static_source_never_touches_the_network(bus: EventBus) -> None:
    source = StaticSource(
        hosts=["one.example.com", "two.example.com", "outside.test"],
        session=offline_session(),
        bus=bus,
    )
    results = await stream(source)
    assert {result.host for result in results} == {"one.example.com", "two.example.com"}


# --------------------------------------------------------------------------- #
# collect()
# --------------------------------------------------------------------------- #


async def test_collect_merges_two_mocked_sources(bus: EventBus) -> None:
    first = StaticSource(
        hosts=["alpha.example.com", "beta.example.com"], session=offline_session(), bus=bus
    )
    second = StaticSource(
        hosts=["gamma.example.com", "outside.test"], session=offline_session(), bus=bus
    )
    merged = [result async for result in collect([first, second], DOMAIN, bus=bus)]

    assert {result.host for result in merged} == {
        "alpha.example.com",
        "beta.example.com",
        "gamma.example.com",
    }
    assert {result.source for result in merged} == {"static-test"}
    log = messages(bus)
    assert log.count("Querying static-test asynchronously...") == 2
    assert any("Discovery merge produced 3" in message for message in log)


async def test_collect_tolerates_a_failing_source(bus: EventBus) -> None:
    good = StaticSource(hosts=["survivor.example.com"], session=offline_session(), bus=bus)
    merged = [
        result
        async for result in collect(
            [ExplodingSource(session=offline_session(), bus=bus), good], DOMAIN, bus=bus
        )
    ]

    assert [result.host for result in merged] == ["survivor.example.com"]
    assert any("kaboom" in message for message in warnings(bus))


async def test_collect_accepts_registry_names_and_injects_one_session(
    bus: EventBus,
) -> None:
    routes = {
        "api.certspotter.com": FakeResponse(200, CERTSPOTTER_FIXTURE),
        "urlscan.io/api/v1/search": FakeResponse(200, URLSCAN_FIXTURE),
    }
    session = routed_session(routes)
    merged = [
        result
        async for result in collect(
            ["certspotter", "urlscan"], DOMAIN, bus=bus, session=session, timeout=5
        )
    ]

    assert {result.host for result in merged} == EXPECTED_CERTSPOTTER | EXPECTED_URLSCAN
    assert {result.source for result in merged} == {"certspotter", "urlscan"}
    assert session.closed == 0, "collect must never close a caller-owned session"
    # Registry singletons stay untouched by the per-run overrides.
    assert get_source("certspotter").session is None
    assert get_source("certspotter").report.hosts == 0


async def test_collect_skips_unknown_names(bus: EventBus) -> None:
    good = StaticSource(hosts=["kept.example.com"], session=offline_session(), bus=bus)
    merged = [
        result async for result in collect(["nope", good], DOMAIN, bus=bus)
    ]

    assert [result.host for result in merged] == ["kept.example.com"]
    assert any("unknown discovery source" in message for message in warnings(bus))


async def test_collect_honours_its_time_budget(bus: EventBus) -> None:
    slow = SlowSource(session=offline_session(), bus=bus)
    fast = StaticSource(hosts=["quick.example.com"], session=offline_session(), bus=bus)
    started = time.monotonic()
    merged = [
        result
        async for result in collect([slow, fast], DOMAIN, bus=bus, timeout=0.3)
    ]
    elapsed = time.monotonic() - started

    assert [result.host for result in merged] == ["quick.example.com"]
    assert elapsed < 5.0
    assert any("budget" in message for message in warnings(bus))


async def test_collect_passes_max_results_to_every_source(bus: EventBus) -> None:
    session = routed_session(
        {
            "api.certspotter.com": FakeResponse(
                200,
                json.dumps(
                    [{"dns_names": [f"h{index}.example.com" for index in range(10)]}]
                ),
            )
        }
    )
    merged = [
        result
        async for result in collect(
            ["certspotter"], DOMAIN, bus=bus, session=session, max_results=2, timeout=5
        )
    ]

    assert len(merged) == 2
    assert get_source("certspotter").max_results == 5000


async def test_collect_with_no_sources_yields_nothing(bus: EventBus) -> None:
    assert [result async for result in collect([], DOMAIN, bus=bus)] == []


async def test_collect_injects_the_bus_into_every_source(bus: EventBus) -> None:
    source = StaticSource(hosts=["default.bus.example.com"], session=offline_session())
    merged = [result async for result in collect([source], DOMAIN, bus=bus, timeout=5)]
    assert [result.host for result in merged] == ["default.bus.example.com"]
    assert any(
        "Querying static-test asynchronously..." == message for message in messages(bus)
    )


# --------------------------------------------------------------------------- #
# subdomain.center (keyless aggregator) — parsing + fetching
# --------------------------------------------------------------------------- #


def test_subdomain_center_parse_accepts_both_response_shapes() -> None:
    from subsonar.core.sources import subdomaincenter

    assert subdomaincenter.parse_payload(
        ["a.example.com", "B.example.com", "a.example.com"]
    ) == ["a.example.com", "b.example.com"]
    assert subdomaincenter.parse_payload(
        {"subdomains": ["x.example.com"], "total": 1}
    ) == ["x.example.com"]
    assert subdomaincenter.parse_payload(
        {"data": [{"host": "y.example.com"}, {"name": "z.example.com"}]}
    ) == ["y.example.com", "z.example.com"]
    # Anything else is simply "no data", never an exception.
    assert subdomaincenter.parse_payload(None) == []
    assert subdomaincenter.parse_payload({"unexpected": 1}) == []
    assert subdomaincenter.parse_payload(["", "  "]) == []


def test_subdomain_center_source_metadata() -> None:
    from subsonar.core.sources import subdomaincenter

    source = subdomaincenter.SubdomainCenterSource
    assert source.name == "subdomain-center"
    assert source.free is True
    assert source.requires_key is False
    assert source.ENDPOINT.startswith("https://api.subdomain.center/")


async def test_subdomain_center_fetch_streams_in_scope_hosts(bus: EventBus) -> None:
    from subsonar.core.sources import subdomaincenter

    payload = json.dumps(
        ["www.example.com", "api.example.com", "evil.test", "www.example.com"]
    )
    session = routed_session(
        {"api.subdomain.center": FakeResponse(200, payload)}
    )
    merged = [
        result
        async for result in collect(
            ["subdomain-center"], DOMAIN, bus=bus, session=session, timeout=5
        )
    ]
    assert {result.host for result in merged} == {"www.example.com", "api.example.com"}


async def test_subdomain_center_reports_a_bad_status(bus: EventBus) -> None:
    from subsonar.core.sources import subdomaincenter

    session = routed_session({"api.subdomain.center": FakeResponse(503, "nope")})
    merged = [
        result
        async for result in collect(
            ["subdomain-center"], DOMAIN, bus=bus, session=session, timeout=5
        )
    ]
    assert merged == []
    assert any("subdomain.center" in message for message in warnings(bus))

