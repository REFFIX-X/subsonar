"""Tests for the built-in OSINT collector (crt.sh / HackerTarget / Anubis).

The three sources are network-bound, so they were the biggest coverage gap in the
suite.  Each source accepts an injected ``session``, which these tests replace
with an in-memory fake so no network is ever touched.
"""

from __future__ import annotations

import json
from typing import Any

from subsonar.core.events import EventBus
from subsonar.core.osint import OSINTCollector, _salvage_json


class _Resp:
    """Stands in for ``aiohttp.ClientResponse`` (async context manager)."""

    def __init__(self, status: int = 200, text: str = "") -> None:
        self.status = status
        self._text = text

    async def __aenter__(self) -> "_Resp":
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    async def text(self) -> str:
        return self._text


class _Session:
    """Minimal ``aiohttp.ClientSession`` replacement driven by a handler."""

    def __init__(self, handler: Any) -> None:
        self._handler = handler
        self.urls: list[str] = []
        self.closed = 0

    def get(self, url: str, **kwargs: Any) -> _Resp:
        self.urls.append(url)
        return self._handler(url)

    async def close(self) -> None:
        self.closed += 1


# --------------------------------------------------------------------------- #
# crt.sh
# --------------------------------------------------------------------------- #


async def test_crtsh_parses_filters_and_dedupes() -> None:
    body = json.dumps(
        [
            {"name_value": "www.example.com\napi.example.com", "common_name": "example.com"},
            {"name_value": "evil.com", "common_name": ""},
            {"name_value": "api.example.com", "common_name": ""},
        ]
    )
    collector = OSINTCollector(
        "example.com", session=_Session(lambda url: _Resp(200, body)), bus=EventBus()
    )
    results = [r async for r in collector.crtsh()]
    hosts = {r.host for r in results}
    assert hosts == {"www.example.com", "api.example.com", "example.com"}
    assert "evil.com" not in hosts
    assert collector.reports["crt.sh"].hosts == 3
    assert all(r.source == "crt.sh" for r in results)


async def test_crtsh_falls_back_to_fallback_on_html_rate_limit() -> None:
    def handler(url: str) -> _Resp:
        if "%25." in url:  # the primary endpoint uses the %25.{domain} wildcard
            return _Resp(200, "<html><body>429 too many requests</body></html>")
        return _Resp(200, json.dumps([{"name_value": "www.example.com"}]))

    session = _Session(handler)
    collector = OSINTCollector("example.com", session=session, bus=EventBus())
    hosts = {r.host async for r in collector.crtsh()}
    assert hosts == {"www.example.com"}
    assert len(session.urls) == 2  # primary then fallback


async def test_crtsh_salvages_malformed_json() -> None:
    malformed = 'prefix {"name_value": "www.example.com"} suffix'
    collector = OSINTCollector(
        "example.com", session=_Session(lambda url: _Resp(200, malformed)), bus=EventBus()
    )
    hosts = {r.host async for r in collector.crtsh()}
    assert hosts == {"www.example.com"}


def test_salvage_json_recovers_name_value() -> None:
    text = 'garbage {"name_value": "www.example.com"} more junk'
    assert _salvage_json(text) == [{"name_value": "www.example.com"}]


def test_salvage_json_empty_on_no_match() -> None:
    assert _salvage_json("no name_value here") == []


# --------------------------------------------------------------------------- #
# HackerTarget
# --------------------------------------------------------------------------- #


async def test_hackertarget_parses_csv_and_attaches_ip() -> None:
    body = "www.example.com,203.0.113.1\napi.example.com,203.0.113.2\nevil.com,203.0.113.3\n"
    collector = OSINTCollector(
        "example.com", session=_Session(lambda url: _Resp(200, body)), bus=EventBus()
    )
    results = [r async for r in collector.hackertarget()]
    by_host = {r.host: r for r in results}
    assert set(by_host) == {"www.example.com", "api.example.com"}
    assert by_host["www.example.com"].ip == "203.0.113.1"
    assert by_host["api.example.com"].ip == "203.0.113.2"


async def test_hackertarget_detects_rate_limit() -> None:
    body = "API count exceeded - try again later"
    collector = OSINTCollector(
        "example.com", session=_Session(lambda url: _Resp(200, body)), bus=EventBus()
    )
    results = [r async for r in collector.hackertarget()]
    assert results == []
    assert collector.reports["hackertarget"].note == "rate limited"


# --------------------------------------------------------------------------- #
# Anubis
# --------------------------------------------------------------------------- #


async def test_anubis_parses_list_and_filters() -> None:
    body = json.dumps(
        ["www.example.com", "api.example.com", "*.cdn.example.com", "evil.com"]
    )
    collector = OSINTCollector(
        "example.com", session=_Session(lambda url: _Resp(200, body)), bus=EventBus()
    )
    hosts = {r.host async for r in collector.anubis()}
    assert hosts == {"www.example.com", "api.example.com", "cdn.example.com"}


async def test_anubis_tolerates_non_list_payload() -> None:
    collector = OSINTCollector(
        "example.com",
        session=_Session(lambda url: _Resp(200, json.dumps({"not": "a list"}))),
        bus=EventBus(),
    )
    results = [r async for r in collector.anubis()]
    assert results == []


# --------------------------------------------------------------------------- #
# Source registry
# --------------------------------------------------------------------------- #


def test_sources_maps_known_names_and_ignores_unknown() -> None:
    collector = OSINTCollector("example.com")
    names = [src.__name__ for src in collector.sources(["crt.sh", "anubis", "nope"])]
    assert names == ["crtsh", "anubis"]
