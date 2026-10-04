"""Regression tests for the correctness/performance/feature pass.

Each test pins one specific bug that was fixed, so it cannot silently come back.
"""

from __future__ import annotations

import asyncio
import json
import socket
import struct
from pathlib import Path
from typing import Any

import pytest

from subsonar.core.config import (
    DEFAULT_DNS_CONCURRENCY,
    PUBLIC_SUFFIXES,
    ScanConfig,
)
from subsonar.core.dns import (
    TYPE_MX,
    TYPE_NS,
    TYPE_SOA,
    TYPE_TXT,
    DNSConnection,
    DNSRecord,
    DNSResult,
    build_query,
)
from subsonar.core.engine import Finding, ScanResult, _wildcard_signature
from subsonar.core.events import EventBus
from subsonar.core.profiles import apply_profile, get_profile
from subsonar.core.scanner import _der_expired
from subsonar.core.web_probe import WebProbeResult


# --------------------------------------------------------------------------- #
# Config precedence (profile no longer clobbers explicit values)
# --------------------------------------------------------------------------- #


def test_explicit_concurrency_survives_profile() -> None:
    config = ScanConfig(domain="example.com", dns_concurrency=1000)
    assert config.concurrency_override is True
    apply_profile(get_profile(3), config)
    assert config.dns_concurrency == 1000


def test_profile_still_supplies_default_concurrency() -> None:
    config = ScanConfig(domain="example.com")
    apply_profile(get_profile(3), config)
    assert config.dns_concurrency != 0
    assert config.dns_concurrency == __import__(
        "subsonar.core.profiles", fromlist=["PROFILE_CONCURRENCY"]
    ).PROFILE_CONCURRENCY[3][0]


def test_explicit_wildcard_filter_survives_profile() -> None:
    config = ScanConfig(domain="example.com", wildcard_filter=False)
    assert config.wildcard_override is True
    apply_profile(get_profile(3), config)
    assert config.wildcard_filter is False


# --------------------------------------------------------------------------- #
# Public-suffix guard
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("suffix", sorted(PUBLIC_SUFFIXES)[:5])
def test_public_suffix_rejected(suffix: str) -> None:
    with pytest.raises(ValueError):
        ScanConfig(domain=suffix)


@pytest.mark.parametrize("domain", ["example.co.uk", "x.com.au", "a.b.example.com"])
def test_registrable_domain_accepted(domain: str) -> None:
    assert ScanConfig(domain=domain).domain == domain


# --------------------------------------------------------------------------- #
# DNS transaction ids: reserved values never used, in-flight tracking bounded
# --------------------------------------------------------------------------- #


def test_build_query_avoids_reserved_transaction_ids() -> None:
    ids = {build_query("a.example.com", 1)[1] for _ in range(4000)}
    assert 0 not in ids and 0xFFFF not in ids


async def test_dns_connection_tracks_inflight_without_preallocation() -> None:
    conn = DNSConnection("127.0.0.1", timeout=0.5)
    assert conn._inflight == set()
    conn._inflight.add(7)
    with pytest.raises(Exception):
        await conn.query(b"\x00\x07", 7)
    conn.close()


# --------------------------------------------------------------------------- #
# TLS certificate expiry reads notAfter (the *second* timestamp)
# --------------------------------------------------------------------------- #


def test_der_expiry_uses_not_after() -> None:
    def stamp(ts: bytes) -> bytes:
        return b"\x17\x0d" + ts

    future = stamp(b"240101000000Z") + stamp(b"350101000000Z")
    assert _der_expired(future) is False
    past = stamp(b"240101000000Z") + stamp(b"200101000000Z")
    assert _der_expired(past) is True


# --------------------------------------------------------------------------- #
# Technology signatures: no false positives on prose / shared server tokens
# --------------------------------------------------------------------------- #


def _tech_names(**kwargs: Any) -> set[str]:
    from subsonar.core.fingerprint import detect_technologies

    return {match.name for match in detect_technologies(**kwargs)}


@pytest.mark.parametrize(
    "word", ["gitlab", "kibana", "confluence", "portainer", "minio", "adminer"]
)
def test_panel_names_in_prose_do_not_match(word: str) -> None:
    body = f"<html><body>We use {word} and link to {word} here.</body></html>".encode()
    assert not any(word in name.lower() for name in _tech_names(body=body))


def test_cowboy_server_is_not_phoenix() -> None:
    names = _tech_names(headers=[("Server", "Cowboy")])
    assert "Phoenix" not in names
    assert "Cowboy" in names


def test_real_phoenix_markup_still_matches() -> None:
    assert "Phoenix" in _tech_names(body=b'<div data-phx-main="true">')


def test_kibana_still_detected_from_its_bundle() -> None:
    assert "Kibana" in _tech_names(body=b'<script src="/bundles/kibana.js">')


# --------------------------------------------------------------------------- #
# Templates: .env only on 200, and known statuses are reused (no re-fetch)
# --------------------------------------------------------------------------- #


class _Prober:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def probe_status(
        self, host: str, port: int, path: str, *, scheme: str
    ) -> dict[str, int]:
        self.calls.append(path)
        return {"status": 302}


async def test_dotenv_not_flagged_on_redirect() -> None:
    from subsonar.core.templates import run_template_checks

    prober = _Prober()  # everything redirects (302)
    matches = await run_template_checks(prober, "http", "a.example.com", "1.2.3.4", 80)
    assert "dotenv-exposed" not in {m.id for m in matches}


async def test_template_reuses_known_status_without_request() -> None:
    from subsonar.core.templates import run_template_checks

    class Exploding(_Prober):
        async def probe_status(self, host, port, path, *, scheme):  # type: ignore[override]
            if path == "/.env":
                raise AssertionError("re-probed a known path")
            return {"status": 404}

    matches = await run_template_checks(
        Exploding(), "http", "a.example.com", "1.2.3.4", 80,
        known_statuses={"/.env": 200},
    )
    assert "dotenv-exposed" in {m.id for m in matches}


# --------------------------------------------------------------------------- #
# Wordlist streaming
# --------------------------------------------------------------------------- #


def test_parse_wordlist_file_matches_string_and_honours_limit(tmp_path: Path) -> None:
    from subsonar.core.wordlist import parse_wordlist, parse_wordlist_file

    lines = [f"host-{i}.example.com" for i in range(500)]
    text = "# c\n\n" + "\n".join(lines) + "\nadmin\nADMIN\nbad..host\n"
    path = tmp_path / "wl.txt"
    path.write_text(text, encoding="utf-8")
    assert parse_wordlist_file(path, limit=25, domain="example.com") == [
        f"host-{i}" for i in range(25)
    ]
    assert parse_wordlist_file(path, domain="example.com") == parse_wordlist(
        text, domain="example.com"
    )


# --------------------------------------------------------------------------- #
# OSINT source pagination
# --------------------------------------------------------------------------- #


class _FakeResp:
    def __init__(self, status: int, text: str) -> None:
        self.status = status
        self._text = text

    async def __aenter__(self) -> "_FakeResp":
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    async def text(self) -> str:
        return self._text


class _FakeSession:
    def __init__(self, handler: Any) -> None:
        self._handler = handler
        self.urls: list[str] = []
        self.closed = 0

    def get(self, url: str, **kwargs: Any) -> _FakeResp:
        self.urls.append(url)
        return self._handler(url)

    async def close(self) -> None:
        self.closed += 1


async def _stream(source: Any, domain: str = "example.com") -> list[Any]:
    return [result async for result in source.fetch(domain)]


async def test_certspotter_paginates_with_after_cursor() -> None:
    from subsonar.core.sources import certspotter

    page1 = json.dumps([{"id": i, "dns_names": [f"h{i}.example.com"]} for i in range(1, 101)])
    page2 = json.dumps([{"id": 101, "dns_names": ["final.example.com"]}])
    session = _FakeSession(lambda url: _FakeResp(200, page2 if "after=" in url else page1))
    source = certspotter.CertSpotterSource(session=session, bus=EventBus())
    names = {r.host for r in await _stream(source)}
    assert "final.example.com" in names
    assert any("after=" in url for url in session.urls)


async def test_otx_paginates_on_has_next() -> None:
    from subsonar.core.sources import otx

    p1 = json.dumps({"passive_dns": [{"hostname": "a.example.com"}], "has_next": True})
    p2 = json.dumps({"passive_dns": [{"hostname": "b.example.com"}], "has_next": False})
    session = _FakeSession(lambda url: _FakeResp(200, p2 if "page=2" in url else p1))
    source = otx.OTXSource(session=session, bus=EventBus())
    names = {r.host for r in await _stream(source)}
    assert names == {"a.example.com", "b.example.com"}
    assert any("page=2" in url for url in session.urls)


async def test_urlscan_paginates_on_search_after() -> None:
    from subsonar.core.sources import urlscan

    p1 = json.dumps(
        {"results": [{"page": {"domain": "x.example.com"}}], "has_more": True,
         "search_after": "abc/def+12"}
    )
    p2 = json.dumps({"results": [{"page": {"domain": "y.example.com"}}], "has_more": False})
    session = _FakeSession(lambda url: _FakeResp(200, p2 if "search_after" in url else p1))
    source = urlscan.UrlScanSource(session=session, bus=EventBus())
    names = {r.host for r in await _stream(source)}
    assert names == {"x.example.com", "y.example.com"}
    assert any("search_after=abc%2Fdef%2B12" in url for url in session.urls)


# --------------------------------------------------------------------------- #
# DNS intelligence runs the independent apex lookups concurrently
# --------------------------------------------------------------------------- #


async def test_dns_intel_lookups_are_concurrent() -> None:
    from subsonar.core.dnsintel import collect_dns_intel

    script = {
        ("example.com", TYPE_MX): ["10 mx1.example.com"],
        ("example.com", TYPE_NS): ["ns1.example.com"],
        ("example.com", TYPE_SOA): ["ns1.example.com hostmaster.example.com 1"],
        ("example.com", TYPE_TXT): ["v=spf1 -all"],
    }

    class Counting:
        def __init__(self) -> None:
            self.active = 0
            self.max_active = 0

        async def query_raw(self, name: str, qtype: int = 1, **kw: Any) -> DNSResult:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            try:
                await asyncio.sleep(0.01)
                result = DNSResult(name=name)
                values = script.get((name.lower().rstrip("."), qtype))
                if values is None:
                    result.error = "NXDOMAIN"
                    return result
                for value in values:
                    result.records.append(
                        DNSRecord(name=name, rtype=qtype, ttl=300, value=value)
                    )
                return result
            finally:
                self.active -= 1

    resolver = Counting()
    intel = await collect_dns_intel("example.com", resolver)
    assert intel.mx and intel.ns and intel.spf
    assert resolver.max_active >= 4


# --------------------------------------------------------------------------- #
# GeoIP IPv6 RIR records carry a prefix length, not an address count
# --------------------------------------------------------------------------- #


def test_rir_ipv6_prefix_length_span() -> None:
    from subsonar.core.geoip import _key_v6, address_key, parse_rir_line

    record = parse_rir_line("ripencc|NL|ipv6|2001:db8::|32|20200101|allocated")
    assert record is not None
    family, start, end, *_ = record
    assert family == 6
    expected = _key_v6(int(address_key("2001:db8::")[1], 16) + (1 << 96) - 1)
    assert end == expected
    assert int(end, 16) > int(start, 16)


# --------------------------------------------------------------------------- #
# Reports: atomic writes, markdown escaping, urls.txt, SARIF
# --------------------------------------------------------------------------- #


def _sample_result() -> ScanResult:
    result = ScanResult(ScanConfig(domain="example.com"), get_profile(3))
    finding = Finding(
        subdomain="a.example.com", ip="1.2.3.4", port=443, scheme="https",
        url="https://a.example.com", status=200,
        title='pipe | and\nnewline "q"', confidence=80, confidence_label="high",
    )
    finding.exposures = [
        {"id": "dotenv-exposed", "name": "Environment file exposed",
         "severity": "critical", "evidence": "/.env → HTTP 200"}
    ]
    result.findings = [finding]
    return result


def test_markdown_escapes_cells_and_leaves_no_temp_files(tmp_path: Path) -> None:
    from subsonar.reporters import write_markdown

    md = write_markdown(_sample_result(), tmp_path / "r.md")
    body = md.read_text(encoding="utf-8")
    row = next(line for line in body.splitlines() if "a.example.com" in line and "|" in line)
    assert "\n" not in row
    assert "\\|" in row
    assert not [p for p in tmp_path.iterdir() if p.suffix == ".tmp"]


def test_urls_and_sarif_outputs(tmp_path: Path) -> None:
    from subsonar.reporters import write_sarif, write_urls

    urls = write_urls(_sample_result(), tmp_path / "r.urls.txt")
    assert urls.read_text(encoding="utf-8").splitlines() == ["https://a.example.com"]

    sarif = json.loads(write_sarif(_sample_result(), tmp_path / "r.sarif").read_text("utf-8"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "subsonar"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} >= {
        "subsonar.web-interface",
        "subsonar.dotenv-exposed",
    }


# --------------------------------------------------------------------------- #
# Wildcard soft-404 signature
# --------------------------------------------------------------------------- #


def test_wildcard_signature_falls_back_to_length_token() -> None:
    probe = WebProbeResult(host="h", ip="1.2.3.4", port=80, scheme="http", url="http://h")
    probe.content_length = 42
    probe.content_type = "text/html"
    probe.fingerprint = None
    assert _wildcard_signature(probe) == "len:42:text/html"


# --------------------------------------------------------------------------- #
# AXFR against a local loopback server
# --------------------------------------------------------------------------- #


def _axfr_response(qid: int, zone: str, hosts: list[str], rcode: int = 0) -> bytes:
    from subsonar.core.dns import encode_name

    def rr(name: str, rtype: int, rdata: bytes) -> bytes:
        return encode_name(name) + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata

    soa = (
        encode_name("ns1." + zone)
        + encode_name("hostmaster." + zone)
        + struct.pack("!IIIII", 1, 2, 3, 4, 5)
    )
    question = encode_name(zone) + struct.pack("!HH", 252, 1)
    answers = rr(zone, TYPE_SOA, soa)
    for host in hosts:
        answers += rr(host, 1, socket.inet_aton("203.0.113.5"))
    answers += rr(zone, TYPE_SOA, soa)
    header = struct.pack("!HHHHHH", qid, 0x8400 | rcode, 1, 1 + len(hosts) + 1, 0, 0)
    return header + question + answers


async def _axfr_server(hosts: list[str], rcode: int = 0) -> tuple[Any, int]:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
        packet = await reader.readexactly(length)
        qid = struct.unpack("!H", packet[:2])[0]
        response = _axfr_response(qid, "example.com", hosts, rcode)
        writer.write(struct.pack("!H", len(response)) + response)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def test_axfr_allowed_is_detected() -> None:
    from subsonar.core.axfr import _axfr_one

    server, port = await _axfr_server(["www.example.com", "mail.example.com"])
    async with server:
        transfer = await _axfr_one("127.0.0.1", "example.com", timeout=3, port=port)
    assert transfer.ok
    assert {"www.example.com", "mail.example.com"} <= set(transfer.names)


async def test_axfr_refusal_is_not_ok() -> None:
    from subsonar.core.axfr import _axfr_one

    server, port = await _axfr_server([], rcode=5)
    async with server:
        transfer = await _axfr_one("127.0.0.1", "example.com", timeout=3, port=port)
    assert not transfer.ok
    assert transfer.error is not None and "rcode" in transfer.error


async def test_attempt_zone_transfer_keeps_only_in_scope_names() -> None:
    from subsonar.core.axfr import attempt_zone_transfer

    class StubResolver:
        async def query_raw(self, name: str, qtype: int = 1, **kw: Any) -> DNSResult:
            result = DNSResult(name=name)
            if qtype == TYPE_NS:
                result.records.append(
                    DNSRecord(name=name, rtype=TYPE_NS, ttl=300, value="ns1.example.com")
                )
            return result

        async def resolve(self, name: str, **kw: Any) -> DNSResult:
            result = DNSResult(name=name)
            result.addresses = ["127.0.0.1"]
            return result

    server, port = await _axfr_server(["www.example.com", "out.of.scope.org"])
    async with server:
        transfers = await attempt_zone_transfer(
            StubResolver(), "example.com", timeout=3, port=port
        )
    assert len(transfers) == 1 and transfers[0].ok
    assert "www.example.com" in transfers[0].names
    assert "out.of.scope.org" not in transfers[0].names


# --------------------------------------------------------------------------- #
# Mining routes DNS through the anonymous pool
# --------------------------------------------------------------------------- #


async def test_mining_connector_uses_anonymous_resolver() -> None:
    pytest.importorskip("aiohttp")
    from subsonar.core.dns import AnonymousResolver
    from subsonar.core.miner import _anonymous_connector
    from subsonar.core.web_probe import AnonymousAiohttpResolver

    def resolver_of(connector: Any) -> Any:
        return getattr(connector, "_resolver", None) or getattr(connector, "resolver", None)

    resolver = AnonymousResolver(servers=("9.9.9.10",))
    connector = _anonymous_connector(resolver, 8)
    try:
        # With a resolver supplied (the engine always passes one) DNS goes
        # through the anonymous pool — not aiohttp's OS-resolver default.
        assert isinstance(resolver_of(connector), AnonymousAiohttpResolver)
    finally:
        await connector.close()
