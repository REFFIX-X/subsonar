"""Verification suite for subsonar — DNS, ports, filters, profiles, reports."""

from __future__ import annotations

import asyncio
import json
import socket
import struct
import time
from pathlib import Path

import pytest

from subsonar.core.config import (
    DNS_RESOLVER_POOL,
    FORBIDDEN_DNS_SERVERS,
    INFRASTRUCTURE_PORTS,
    PORT_MATRIX,
    TLS_FIRST_PORTS,
    ScanConfig,
)
from subsonar.core.dns import (
    TYPE_A,
    AnonymousResolver,
    DNSFormatError,
    build_query,
    encode_name,
    parse_response,
)
from subsonar.core.events import BUS, EventBus, ScanEvent
from subsonar.core.osint import is_valid_hostname
from subsonar.core.ports import (
    PORT_MATRIX_SIZE,
    audit_matrix,
    describe,
    prefers_tls,
    scheme_order,
    validate_matrix,
)
from subsonar.core.profiles import PROFILES, get_profile, render_profile_table
from subsonar.core.theme import Palette, banner_lines, logo_block
from subsonar.core.web_probe import (
    WebProbeResult,
    _is_web_interface,
    classify_finding,
    extract_title,
    is_protocol_error,
    is_redirect_only,
)
from subsonar.core.wordlist import EMBEDDED_SEED, parse_wordlist

# --------------------------------------------------------------------------- #
# DNS privacy + wire protocol
# --------------------------------------------------------------------------- #


def test_no_google_or_cloudflare_resolvers() -> None:
    assert not FORBIDDEN_DNS_SERVERS.intersection(DNS_RESOLVER_POOL)
    assert "8.8.8.8" not in DNS_RESOLVER_POOL
    assert "1.1.1.1" not in DNS_RESOLVER_POOL
    assert len(DNS_RESOLVER_POOL) >= 10


def test_resolver_pool_rotation_is_anonymous() -> None:
    resolver = AnonymousResolver(servers=["9.9.9.10", "185.228.168.168"], verbose_queries=False)
    rotation = {resolver.next_server() for _ in range(8)}
    assert rotation == {"9.9.9.10", "185.228.168.168"}


def test_anonymous_resolver_rejects_forbidden_pool() -> None:
    with pytest.raises(RuntimeError):
        AnonymousResolver(servers=["8.8.8.8"], verbose_queries=False)


def test_aiodns_backend_matches_the_wire_resolver() -> None:
    """The optional aiodns backend must resolve through the injected pool.

    Regression: aiodns >= 4 takes the record type as a string, so passing the
    c-ares integer constant raised ``ValueError: invalid query type``.

    The query goes to the loopback mock rather than the public pool: this suite
    must not send packets to third parties (``main.py selftest`` covers the real
    pool), and pycares' shutdown thread has been observed to wedge the
    interpreter when a live channel is torn down mid-run.
    """
    from subsonar.core.dns import AiodnsResolver
    from subsonar.core.selftest import MOCK_IP, TEST_DOMAIN, MockDNSServer

    async def check() -> None:
        server = MockDNSServer()
        port = await server.start()
        resolver = AiodnsResolver(servers=[f"{MOCK_IP}:{port}"], timeout=2.0)
        try:
            resolver._load()
            if not resolver.available:
                pytest.skip("aiodns is not installed")
            result = await resolver.resolve(TEST_DOMAIN, "A")
            assert result.error is None, result.error
            assert MOCK_IP in result.addresses, result.addresses
        finally:
            await resolver.aclose()
            server.stop()

    asyncio.run(check())


def test_encode_name_round_trip() -> None:
    encoded = encode_name("www.example.com")
    assert encoded == b"\x03www\x07example\x03com\x00"


def test_encode_name_rejects_overlong_label() -> None:
    with pytest.raises(DNSFormatError):
        encode_name("a" * 64 + ".com")


def test_build_query_and_parse_response() -> None:
    packet, qid = build_query("api.example.com", TYPE_A)
    assert len(packet) > 12
    # CNAME answer whose RDATA is a compression pointer to the question name.
    response = (
        struct.pack("!HHHHHH", qid, 0x8180, 1, 2, 0, 0)
        + packet[12:]
        + b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 3600, 2) + b"\xc0\x0c"
        + b"\xc0\x0c" + struct.pack("!HHIH", TYPE_A, 1, 300, 4) + socket.inet_aton("192.0.2.10")
    )
    records, rcode = parse_response(response, qid)
    assert rcode == 0
    types = {record.type_name for record in records}
    assert "A" in types and "CNAME" in types
    assert any(record.value == "192.0.2.10" for record in records)
    assert any(record.value == "api.example.com" for record in records)


def test_parse_response_detects_txid_mismatch() -> None:
    packet, qid = build_query("example.com", TYPE_A)
    with pytest.raises(DNSFormatError):
        parse_response(packet, (qid + 1) % 0xFFFF)


def test_nxdomain_rcode_is_three() -> None:
    packet, qid = build_query("nope.example.com", TYPE_A)
    _, rcode = parse_response(struct.pack("!HHHHHH", qid, 0x8183, 1, 0, 0, 0) + packet[12:], qid)
    assert rcode == 3


@pytest.mark.asyncio
async def test_resolver_timeout_is_graceful() -> None:
    """A silent UDP endpoint must yield an error result, never an exception."""
    loop = asyncio.get_running_loop()

    class _Silent(asyncio.DatagramProtocol):
        pass

    transport, _ = await loop.create_datagram_endpoint(_Silent, local_addr=("127.0.0.1", 0))
    transport.close()  # nothing listens on the port now
    resolver = AnonymousResolver(
        servers=["127.0.0.1"],
        timeout=0.2,
        retries=1,
        verbose_queries=False,
        # The durable cache is shared across runs, so a previously cached answer
        # for example.com would make this test non-hermetic.
        disk_cache_enabled=False,
    )
    result = await resolver.query_raw("example.com", TYPE_A, log=False)
    assert not result.ok
    assert result.error  # timeout recorded, no exception escaped
    resolver.close()


@pytest.mark.asyncio
async def test_wildcard_report_false_positive_logic() -> None:
    from subsonar.core.dns import WildcardReport

    report = WildcardReport(domain="example.com", wildcard=True, ips={"203.0.113.5"})
    assert report.is_false_positive(["203.0.113.5"])
    assert not report.is_false_positive(["203.0.113.5", "198.51.100.9"])
    assert not report.is_false_positive([])
    inactive = WildcardReport(domain="example.com")
    assert not inactive.is_false_positive(["203.0.113.5"])


# --------------------------------------------------------------------------- #
# Ports
# --------------------------------------------------------------------------- #


def test_port_matrix_has_exactly_fifty_ports() -> None:
    assert PORT_MATRIX_SIZE == 50
    assert len(PORT_MATRIX) == 50
    validate_matrix()


def test_port_matrix_contains_required_ports() -> None:
    for port in (80, 443, 3000, 5000, 8080, 8443, 9000, 9443, 10000):
        assert port in PORT_MATRIX


def test_tls_first_detection() -> None:
    assert prefers_tls(8443) and prefers_tls(443)
    assert not prefers_tls(80)
    assert scheme_order(8443) == ("https", "http")
    assert scheme_order(8080) == ("http", "https")


def test_infrastructure_matrix_subset() -> None:
    audit = audit_matrix()
    assert set(audit).issubset(PORT_MATRIX)
    assert set(INFRASTRUCTURE_PORTS).issubset(PORT_MATRIX)
    assert describe(10000) == "Webmin / Usermin"


# --------------------------------------------------------------------------- #
# Profiles
# --------------------------------------------------------------------------- #


def test_exactly_eight_profiles() -> None:
    assert len(PROFILES) == 8
    assert [profile.id for profile in PROFILES] == list(range(1, 9))


def test_profile_lookup_by_id_and_key() -> None:
    assert get_profile(3).name == "Medium Brute"
    assert get_profile("stealth").id == 8
    with pytest.raises(KeyError):
        get_profile(99)


def test_profile_wordlist_sizes() -> None:
    sizes = {profile.id: profile.wordlist_size for profile in PROFILES}
    assert sizes[1] == 0
    assert sizes[2] == 1_000
    assert sizes[3] == 5_000
    assert sizes[4] == 20_000
    assert sizes[6] == 500
    assert sizes[8] == 5_000


def test_passive_profile_sends_no_brute_force() -> None:
    passive = get_profile(1)
    assert passive.passive and not passive.brute
    assert "0 packets" in passive.packet_profile


def test_stealth_profile_has_random_delays() -> None:
    from subsonar.core.profiles import PROFILE_DELAY

    delay = PROFILE_DELAY[8]
    assert delay[1] > delay[0] > 0


def test_infrastructure_profile_uses_audit_ports() -> None:
    profile = get_profile(7)
    assert profile.port_mode == "audit"
    assert 10000 in profile.port_numbers()
    assert 80 not in profile.port_numbers()


def test_profile_table_renders_all_profiles() -> None:
    table = render_profile_table()
    for profile in PROFILES:
        assert profile.name in table


# --------------------------------------------------------------------------- #
# Config / domain handling
# --------------------------------------------------------------------------- #


def test_scan_config_normalises_domain() -> None:
    config = ScanConfig(domain="HTTPS://Example.COM/path?x=1")
    assert config.domain == "example.com"


def test_scan_config_rejects_bare_hostname() -> None:
    with pytest.raises(ValueError):
        ScanConfig(domain="localhost")


def test_scan_config_strips_port() -> None:
    assert ScanConfig(domain="example.com:8443").domain == "example.com"


# --------------------------------------------------------------------------- #
# OSINT / wordlist parsing
# --------------------------------------------------------------------------- #


def test_hostname_scope_validation() -> None:
    assert is_valid_hostname("www.example.com", "example.com")
    assert is_valid_hostname("*.api.example.com", "example.com")
    assert is_valid_hostname("example.com", "example.com")
    assert not is_valid_hostname("evil.com", "example.com")
    assert not is_valid_hostname("10.0.0.1", "example.com")
    assert not is_valid_hostname("-bad.example.com", "example.com")


def test_wordlist_parsing_is_normalised_and_deduped() -> None:
    text = "# comment\nwww\nWWW\napi\nmail.example.com\n\nbad..host\nns1\n"
    words = parse_wordlist(text, domain="example.com")
    assert words == ["www", "api", "mail", "ns1"]


def test_wordlist_limit_respected() -> None:
    text = "\n".join(f"host{i}" for i in range(100))
    assert len(parse_wordlist(text, limit=10)) == 10


def test_embedded_seed_is_available() -> None:
    assert len(EMBEDDED_SEED) > 100
    assert "www" in EMBEDDED_SEED


# --------------------------------------------------------------------------- #
# Web probe extraction + strict filter
# --------------------------------------------------------------------------- #


def test_extract_title_handles_entities_and_whitespace() -> None:
    body = b"<html><head><title>\n  Admin &amp; Portal \n</title></head></html>"
    assert extract_title(body, "text/html") == "Admin &amp; Portal"


def test_extract_title_ignores_non_html() -> None:
    assert extract_title(b"binary", "image/png") is None
    assert extract_title(b"<html></html>", "text/html") is None


def test_strict_filter_requires_content() -> None:
    empty = WebProbeResult(host="h", ip="1.1.1.1", port=80, scheme="http", url="http://h")
    empty.status = 200
    empty.content_length = 0
    empty.title = None
    assert not _is_web_interface(empty)
    populated = WebProbeResult(host="h", ip="1.1.1.1", port=80, scheme="http", url="http://h")
    populated.status = 200
    populated.content_length = 512
    assert _is_web_interface(populated)


# --------------------------------------------------------------------------- #
# False-positive classes reported from a live scan
# --------------------------------------------------------------------------- #


def test_plain_http_to_tls_port_is_rejected() -> None:
    """Reproduces ``400 The plain HTTP request was sent to HTTPS port``.

    Apache answers a plain HTTP probe on a TLS-only port with a 400 and a real
    body, which used to be reported as a web interface on ports such as 2083,
    2087, 2096 and 8443.
    """
    body = (
        b"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
        b"<html><head><title>400 The plain HTTP request was sent to HTTPS port</title>"
        b"</head><body><h1>Bad Request</h1>"
        b"<p>Your browser sent a request that this server could not understand."
        b"<br />The plain HTTP request was sent to HTTPS port</p></body></html>\n"
    )
    result = WebProbeResult(host="support.example.com", ip="1.1.1.1", port=8443, scheme="http",
                            url="http://support.example.com:8443")
    result.status = 400
    result.title = "400 The plain HTTP request was sent to HTTPS port"
    result.content_type = "text/html"
    result.content_length = len(body)
    result.server = "Apache"
    assert is_protocol_error(result, body)
    assert not _is_web_interface(result, body)


def test_cpanel_tls_ports_are_probed_with_https_first() -> None:
    """2082/2086/2095 are the cleartext twins; 2083/2087/2096 are TLS-only."""
    for port in (2083, 2087, 2096, 8443, 9443, 10000):
        assert prefers_tls(port), f"port {port} must be probed with https first"
        assert scheme_order(port)[0] == "https"
    for port in (2082, 2086, 2095, 8080):
        assert not prefers_tls(port), f"port {port} is a cleartext web port"


def test_generic_4xx_error_pages_are_rejected() -> None:
    for status in (400, 405, 501, 505):
        result = WebProbeResult(host="h", ip="1.1.1.1", port=80, scheme="http", url="http://h")
        result.status = status
        result.title = "Error"
        result.content_length = 800
        assert not _is_web_interface(result, b"<h1>error</h1>"), status


def test_auth_gated_panels_are_kept_but_labelled_restricted() -> None:
    for status in (401, 403):
        result = WebProbeResult(host="h", ip="1.1.1.1", port=8443, scheme="https", url="https://h:8443")
        result.status = status
        result.title = "Login required"
        result.content_length = 900
        assert _is_web_interface(result, b"<html><body>login</body></html>")
        assert classify_finding(result) == "restricted"


def test_bare_404_without_an_application_is_rejected() -> None:
    result = WebProbeResult(host="h", ip="1.1.1.1", port=8080, scheme="http", url="http://h:8080")
    result.status = 404
    result.title = None
    result.content_length = 200
    assert not _is_web_interface(result, b"")
    # ...but a 404 with a real application shell (title + body) survives.
    result.title = "Not found — Admin Console"
    result.content_length = 4096
    assert _is_web_interface(result, b"<html><title>x</title></html>")


# --------------------------------------------------------------------------- #
# Redirect attribution (reported live: support.example.com:2082)
# --------------------------------------------------------------------------- #


def _redirect_result(url: str, final_url: str, *, status: int = 200, initial: int = 301):
    result = WebProbeResult(
        host="support.example.com", ip="172.66.0.145", port=2082, scheme="http", url=url
    )
    result.status = status
    result.initial_status = initial
    result.redirected = True
    result.final_url = final_url
    result.redirect_chain = [url, final_url]
    result.title = "Support : Example Inc"
    result.content_type = "text/html"
    result.content_length = 22104
    result.server = "cloudflare"
    return result


def test_redirect_only_port_is_rejected() -> None:
    """``http://support.example.com:2082`` → ``https://support.example.com/`` (port 443).

    Nothing is served on 2082 — the 200 belonged to 443. This must be filtered.
    """
    result = _redirect_result(
        "http://support.example.com:2082", "https://support.example.com/support/home"
    )
    assert is_redirect_only(result)
    assert not _is_web_interface(result, b"<html><title>x</title></html>")


def test_same_port_redirect_keeps_the_finding() -> None:
    """A redirect that does *not* change the port keeps its finding.

    ``https://host:8443/x`` → ``https://host:8443/y``: the service really is on
    8443, so it must be reported.
    """
    result = _redirect_result(
        "https://host.example.com:8443", "https://host.example.com:8443/login"
    )
    result.port = 8443
    result.scheme = "https"
    assert not is_redirect_only(result)
    assert _is_web_interface(result, b"<html><title>x</title></html>")


def test_http_to_https_upgrade_is_a_redirect_only_port() -> None:
    """``http://host:80`` → ``https://host`` is a bounce to 443 and is dropped.

    The TLS service on 443 is itself scanned and reported, so counting the
    cleartext bounce as a second finding would double-report one site.
    """
    result = _redirect_result(
        "http://support.example.com", "https://support.example.com/support/home"
    )
    result.port = 80
    assert is_redirect_only(result)


def test_cross_port_redirect_to_alt_port_is_rejected() -> None:
    result = _redirect_result(
        "http://host.example.com:2082", "https://host.example.com:8443/admin"
    )
    assert is_redirect_only(result)


def test_effective_port_parsing() -> None:
    from subsonar.core.web_probe import _effective_port

    assert _effective_port("http://x.test") == 80
    assert _effective_port("https://x.test") == 443
    assert _effective_port("https://x.test:8443/a/b") == 8443
    assert _effective_port("http://x.test:2082") == 2082


def test_classify_finding_labels_redirect() -> None:
    result = _redirect_result(
        "http://support.example.com:2082", "https://support.example.com/support/home"
    )
    assert classify_finding(result) == "redirect"


def test_redirect_only_is_promoted_when_nothing_else_answers() -> None:
    """A bounce is still reported (labelled ``redirect``) if the host is otherwise dark."""
    from subsonar.core.engine import Finding, ScanEngine

    bus = EventBus()
    engine = ScanEngine(ScanConfig(domain="dark.example.com", profile_id=3), profile=3, bus=bus)
    engine.result.redirects.append(
        Finding(
            subdomain="dark.example.com",
            ip="203.0.113.77",
            port=2082,
            scheme="http",
            url="http://dark.example.com:2082",
            status=200,
            initial_status=301,
            title="Support",
            kind="redirect",
            redirect_chain=["http://dark.example.com:2082", "https://dark.example.com/"],
        )
    )
    engine._promote_redirects()
    assert len(engine.result.findings) == 1
    assert engine.result.findings[0].kind == "redirect"


def test_redirect_only_is_not_promoted_when_an_interface_exists() -> None:
    from subsonar.core.engine import Finding, ScanEngine

    bus = EventBus()
    engine = ScanEngine(ScanConfig(domain="dark.example.com", profile_id=3), profile=3, bus=bus)
    engine.result.findings.append(
        Finding(
            subdomain="dark.example.com",
            ip="203.0.113.77",
            port=443,
            scheme="https",
            url="https://dark.example.com",
            status=200,
            title="Real",
            kind="interface",
        )
    )
    engine.result.redirects.append(
        Finding(
            subdomain="dark.example.com",
            ip="203.0.113.77",
            port=2082,
            scheme="http",
            url="http://dark.example.com:2082",
            status=200,
            initial_status=301,
            title="Support",
            kind="redirect",
        )
    )
    engine._promote_redirects()
    assert len(engine.result.findings) == 1
    assert engine.result.findings[0].port == 443


def test_cloudflare_alt_port_bounce_is_dropped_end_to_end() -> None:
    """The full reported case: 2082 bounces, 443 serves, only 443 is reported."""
    bounce = _redirect_result(
        "http://support.example.com:2082", "https://support.example.com/support/home"
    )
    real = WebProbeResult(
        host="support.example.com", ip="172.66.0.145", port=443,
        scheme="https", url="https://support.example.com",
    )
    real.status = 200
    real.initial_status = 302
    real.redirected = True
    real.final_url = "https://support.example.com/support/home"
    real.title = "Support : Example Inc"
    real.content_length = 22104
    assert not _is_web_interface(bounce, b"<html><title>x</title></html>")
    assert _is_web_interface(real, b"<html><title>x</title></html>")


def test_duplicate_ports_collapse_to_one_interface() -> None:
    """One vhost on many ports must yield one finding, with the rest as aliases."""
    from subsonar.core.engine import Finding, ScanEngine, ScanResult
    from subsonar.core.events import EventBus

    bus = EventBus()
    config = ScanConfig(domain="support.example.com", profile_id=2)
    engine = ScanEngine(config, profile=2, bus=bus)
    result = engine.result
    fingerprint = "deadbeefdeadbeef"
    for port in (8080, 2095, 2086, 2082):
        result.findings.append(
            Finding(
                subdomain="support.example.com",
                ip="162.159.140.14",
                port=port,
                scheme="http",
                url=f"http://support.example.com:{port}",
                status=200,
                title="Support : Example Inc",
                fingerprint=fingerprint,
            )
        )
    # A genuinely different interface on 443 must survive independently.
    result.findings.append(
        Finding(
            subdomain="support.example.com",
            ip="162.159.140.14",
            port=443,
            scheme="https",
            url="https://support.example.com",
            status=200,
            title="Support : Example Inc",
            fingerprint="0123456789abcdef",
            tls=True,
        )
    )
    engine._dedupe_findings()
    assert len(result.findings) == 2
    http_finding = next(f for f in result.findings if f.scheme == "http")
    # 8080 is the most canonical cleartext port of the group; the rest become aliases.
    assert http_finding.port == 8080
    assert set(http_finding.aliases) == {2082, 2086, 2095}
    assert any(f.port == 443 for f in result.findings)
    assert len([k for k in result.filtered if k.startswith("support.example.com:")]) == 3


# --------------------------------------------------------------------------- #
# Event bus
# --------------------------------------------------------------------------- #


def test_event_bus_drain_and_history() -> None:
    bus = EventBus()
    for index in range(10):
        bus.emit(f"event {index}", "info", "dns", host="a.example.com")
    drained = bus.drain(limit=5)
    assert len(drained) == 5
    assert drained[0].message == "event 0"
    assert len(bus.history()) == 10
    assert bus.drain(limit=100)[0].message == "event 5"


def test_event_bus_thread_safety() -> None:
    bus = EventBus()
    import threading

    def writer(worker: int) -> None:
        for index in range(100):
            bus.emit(f"w{worker}-{index}", "info", "stat")

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(bus.history()) == 800
    assert len(bus.drain(limit=10_000)) == 800


def test_event_stats_snapshot() -> None:
    bus = EventBus()
    bus.bump("dns_resolved", 4)
    bus.bump_source("crt.sh", 3)
    bus.set_field("candidates", 10)
    snapshot = bus.snapshot()
    assert snapshot["dns_resolved"] == 4
    assert snapshot["sources"]["crt.sh"] == 3
    assert snapshot["progress"] == 0.4


def test_event_render_contains_clock_and_category() -> None:
    from subsonar.core.events import ScanEvent

    event = ScanEvent(seq=1, ts=time.time(), severity="info", category="dns", message="hello")
    rendered = event.render()
    assert "dns" in rendered and "hello" in rendered
    assert len(event.clock.split(".")[1]) == 3


# --------------------------------------------------------------------------- #
# Theme
# --------------------------------------------------------------------------- #


def test_palette_matches_monokai_pro_spec() -> None:
    assert Palette.BACKGROUND == "#2d2a2e"
    assert Palette.TEXT == "#fcfcfa"
    assert Palette.MUTED == "#727072"
    assert Palette.PINK == "#ff61ef"
    assert Palette.GREEN == "#a9dc76"
    assert Palette.ORANGE == "#fc9867"
    assert Palette.YELLOW == "#ffd866"
    assert Palette.CYAN == "#78dce8"


def test_logo_and_banner_render() -> None:
    assert "subsonar" not in logo_block()  # styled wordmark, not plain text
    assert len(logo_block().splitlines()) == 6
    assert any("anonymous" in line for line in banner_lines())
    assert logo_block(width=40) != logo_block(width=120)


# --------------------------------------------------------------------------- #
# Report writers
# --------------------------------------------------------------------------- #


class _FakeFinding:
    pass


def _synthetic_result():
    from subsonar.core.engine import Finding, ScanResult
    from subsonar.core.events import Stats

    config = ScanConfig(domain="example.com")
    result = ScanResult(config, get_profile(3))
    result.findings = [
        Finding(
            subdomain="portal.example.com",
            ip="203.0.113.9",
            port=8443,
            scheme="https",
            url="https://portal.example.com:8443",
            status=200,
            title="Admin Portal",
            server="nginx",
            tls=True,
        )
    ]
    result.resolutions = {}
    result.finished_at = time.time()
    return result


def test_report_writers(tmp_path: Path) -> None:
    from subsonar.reporters import write_reports

    result = _synthetic_result()
    written = write_reports(result, tmp_path, formats=("json", "csv", "md", "html", "txt"))
    assert set(written) == {"json", "csv", "md", "html", "txt"}
    payload = json.loads(Path(written["json"]).read_text(encoding="utf-8"))
    assert payload["target"] == "example.com"
    assert payload["findings"][0]["url"] == "https://portal.example.com:8443"
    csv_text = Path(written["csv"]).read_text(encoding="utf-8")
    assert "https://portal.example.com:8443" in csv_text
    markdown = Path(written["md"]).read_text(encoding="utf-8")
    assert "[https://portal.example.com:8443](https://portal.example.com:8443)" in markdown
    html_text = Path(written["html"]).read_text(encoding="utf-8")
    assert "href='https://portal.example.com:8443'" in html_text
    assert Palette.BACKGROUND in html_text


def test_report_writers_include_geo_dns_intel_and_mining(tmp_path: Path) -> None:
    """The new OSINT enrichment must reach every report format."""
    from subsonar.core.dnsintel import DNSIntel
    from subsonar.reporters import CSV_COLUMNS, write_reports

    result = _synthetic_result()
    finding = result.findings[0]
    finding.country_code = "DK"
    finding.country = "Denmark"
    finding.asn = 13335
    finding.as_org = "CLOUDFLARENET"
    finding.ptr = "portal.example.com"
    result.carried_over = 1
    result.mined_hosts = {"mined.example.com"}
    result.wave2_hosts = {"mined.example.com"}
    result.ptr = {"203.0.113.9": "portal.example.com"}
    result.geo = {"entries": 721_256, "ipv4": 538_468, "ipv6": 182_788, "age_days": 1.5}
    result.dns_intel = DNSIntel(
        domain="example.com",
        mx=[(10, "mx1.dandomain.dk")],
        ns=["ns1.dandomain.dk"],
        mail_providers=["DanDomain"],
        dns_providers=["DanDomain DNS"],
        spf=["v=spf1 -all"],
        spf_all="-",
        dmarc={"p": "reject"},
        dmarc_record="v=DMARC1; p=reject",
        dkim_selectors=["default"],
        caa=[("0", "issue", "letsencrypt.org")],
        dnssec=True,
        verifications={"Google Search Console": "token"},
        notes=["no CAA record — any CA may issue for this domain"],
    )
    written = write_reports(result, tmp_path, formats=("json", "csv", "md", "html"))

    # CSV: the new columns exist and are populated.
    for column in ("country_code", "country", "asn", "as_org", "ptr", "carried_over"):
        assert column in CSV_COLUMNS
    csv_text = Path(written["csv"]).read_text(encoding="utf-8")
    assert "DK" in csv_text and "CLOUDFLARENET" in csv_text
    assert "portal.example.com" in csv_text.splitlines()[1]

    # JSON: enrichment is structured, not stringly-typed.
    payload = json.loads(Path(written["json"]).read_text(encoding="utf-8"))
    assert payload["findings"][0]["country_code"] == "DK"
    assert payload["findings"][0]["asn"] == 13335
    assert payload["dns_intel"]["dmarc"]["p"] == "reject"
    assert payload["dns_intel"]["dnssec"] is True
    assert payload["mined_hosts"] == ["mined.example.com"]
    assert payload["wave2_hosts"] == ["mined.example.com"]
    assert payload["ptr"]["203.0.113.9"] == "portal.example.com"
    assert payload["carried_over"] == 1
    assert payload["geo"]["entries"] == 721_256

    # Markdown: a Geo column plus the intelligence sections.
    markdown = Path(written["md"]).read_text(encoding="utf-8")
    assert "| Geo |" in markdown
    assert "🇩🇰 DK AS13335" in markdown
    assert "## DNS intelligence (free, DNS only)" in markdown
    assert "**Posture**" in markdown
    assert "Google Search Console" in markdown
    assert "## Mined hostnames" in markdown
    assert "## Reverse DNS (PTR)" in markdown
    assert "mail platform" in markdown

    # HTML: flag image with a hover tooltip plus the same sections.
    html_text = Path(written["html"]).read_text(encoding="utf-8")
    assert "flagcdn.com/20x15/dk.png" in html_text
    assert (
        "title='Denmark · AS13335 CLOUDFLARENET · portal.example.com'" in html_text
    )
    assert "DNS intelligence (free, DNS only)" in html_text
    assert "Mined hostnames (1)" in html_text
    assert "<th>AS organisation</th>" in html_text


def test_markdown_reports_carry_over_provenance(tmp_path: Path) -> None:
    from subsonar.reporters import write_markdown

    result = _synthetic_result()
    result.carried_over = 1
    result.findings[0].from_previous_scan = True
    path = write_markdown(result, tmp_path / "r.md")
    text = path.read_text(encoding="utf-8")
    assert "| from prev. scan |" in text
    assert "nothing was cleared" in text
    assert "_(prev)_" in text


# --------------------------------------------------------------------------- #
# End-to-end self-test
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_engine_selftest_passes(tmp_path: Path) -> None:
    from subsonar.core.selftest import run_selftest

    report = await run_selftest(report_dir=tmp_path)
    failures = [check for check in report["checks"] if not check["ok"]]
    assert report["passed"] == report["total"], failures
    assert report["total"] >= 10


# --------------------------------------------------------------------------- #
# Regressions: hostile DNS packets, record scoping, event-bus reset
# --------------------------------------------------------------------------- #


def test_compression_pointer_loop_is_rejected_not_hung() -> None:
    """A self-referencing pointer must raise, never spin the event loop.

    Regression: ``_decode_name`` accepted a ``depth`` argument it never
    incremented, so a crafted/ mangled response looped forever in pure Python
    bytecode and froze the whole asyncio loop.
    """
    packet = (
        struct.pack("!HHHHHH", 0x2222, 0x8180, 1, 0, 0, 0)
        + b"\xc0\x0c"  # pointer at offset 12 → offset 12
        + struct.pack("!HH", TYPE_A, 1)
    )
    with pytest.raises(DNSFormatError):
        parse_response(packet, 0x2222)


def test_compression_pointer_out_of_range_is_rejected() -> None:
    packet = (
        struct.pack("!HHHHHH", 0x3333, 0x8180, 1, 0, 0, 0)
        + b"\xc0\xff"  # pointer to offset 255, past the end of the packet
        + struct.pack("!HH", TYPE_A, 1)
    )
    with pytest.raises(DNSFormatError):
        parse_response(packet, 0x3333)


def _rr(name: str, rtype: int, value: bytes, ttl: int = 300) -> bytes:
    return (
        encode_name(name)
        + struct.pack("!HHIH", rtype, 1, ttl, len(value))
        + value
    )


def test_glue_records_are_not_attributed_to_the_queried_host() -> None:
    """Authority/additional records for other names must never become addresses."""
    from subsonar.core.dns import DNSResult

    packet, qid = build_query("nope.example.com", TYPE_A)
    authority = _rr("example.com", 2, encode_name("ns1.example.com"))
    additional = _rr("ns1.example.com", TYPE_A, socket.inet_aton("203.0.113.53"))
    response = (
        struct.pack("!HHHHHH", qid, 0x8180, 1, 0, 1, 1) + packet[12:] + authority + additional
    )
    records, rcode = parse_response(response, qid)
    assert rcode == 0 and len(records) == 2  # the wire parser still reports them

    result = DNSResult(name="nope.example.com")
    AnonymousResolver._apply_records(result, records, TYPE_A)
    assert result.addresses == []
    assert result.records == []
    assert result.error == "no records"


def test_cname_chain_addresses_are_kept() -> None:
    from subsonar.core.dns import DNSResult

    packet, qid = build_query("api.example.com", TYPE_A)
    answer = _rr("api.example.com", 5, encode_name("edge.cdn.net")) + _rr(
        "edge.cdn.net", TYPE_A, socket.inet_aton("198.51.100.7"), ttl=60
    )
    response = struct.pack("!HHHHHH", qid, 0x8180, 1, 2, 0, 0) + packet[12:] + answer
    records, _ = parse_response(response, qid)

    result = DNSResult(name="api.example.com")
    AnonymousResolver._apply_records(result, records, TYPE_A)
    assert result.addresses == ["198.51.100.7"]
    assert result.cnames == ["edge.cdn.net"]


def test_event_bus_clear_resets_statistics() -> None:
    """A second scan in one process must not inherit the first run's counters."""
    bus = EventBus()
    bus.bump("dns_resolved", 7)
    bus.set_field("phase", "done")
    bus.emit("x")
    bus.clear()
    snapshot = bus.snapshot()
    assert snapshot["dns_resolved"] == 0
    assert snapshot["phase"] == "init"
    assert bus.drain() == []
    assert bus.history() == []


@pytest.mark.asyncio
async def test_stream_queue_overflow_drops_instead_of_raising() -> None:
    bus = EventBus()
    queue: asyncio.Queue = asyncio.Queue(maxsize=1)
    bus._offer(queue, bus.emit("first"))
    bus._offer(queue, bus.emit("second"))
    assert bus.dropped == 1
    assert queue.qsize() == 1




def test_redirect_classification_without_a_final_url_does_not_raise() -> None:
    """Regression: ``urljoin`` was used in ``is_redirect_only`` but never imported."""
    result = WebProbeResult(
        host="h.example.com",
        ip="192.0.2.1",
        port=80,
        scheme="http",
        url="http://h.example.com:80",
        status=301,
        initial_status=301,
    )
    # A bounce that stays on the scanned port is not "redirect only".
    assert is_redirect_only(result) is False
    assert classify_finding(result) == "interface"


def test_declared_length_helper_rejects_junk() -> None:
    from subsonar.core.web_probe import _int_or_none

    assert _int_or_none("1234") == 1234
    assert _int_or_none(None) is None
    assert _int_or_none("not a number") is None
    assert _int_or_none("-5") is None


class _ChunkedContent:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def _iterate(self):  # noqa: ANN202
        for chunk in self._chunks:
            yield chunk

    def iter_chunked(self, size: int):  # noqa: ANN201, ARG002
        return self._iterate()


class _FakeResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self.content = _ChunkedContent(chunks)


@pytest.mark.asyncio
async def test_body_read_honours_the_hard_size_budget() -> None:
    """The cap is a budget: the returned body can never exceed ``max_body``."""
    from subsonar.core.web_probe import WebProbe

    probe = WebProbe(resolver=object(), max_body=10)
    body, truncated = await probe._read_body(_FakeResponse([b"x" * 8, b"y" * 8]))
    assert len(body) == 10
    assert truncated is True


@pytest.mark.asyncio
async def test_body_read_stops_at_head_end_without_marking_truncated() -> None:
    from subsonar.core.web_probe import WebProbe

    probe = WebProbe(resolver=object(), max_body=4096)
    body, truncated = await probe._read_body(
        _FakeResponse([b"<html><head><title>t</title></head>", b"z" * 500])
    )
    assert body == b"<html><head><title>t</title></head>"
    assert truncated is False


def test_promoted_redirect_is_removed_from_the_filtered_map() -> None:
    """The promoted host must not stay listed as filtered at the same time."""
    from subsonar.core.engine import Finding, ScanEngine

    engine = ScanEngine(
        ScanConfig(domain="dark.example.com", profile_id=2), profile=2, bus=EventBus()
    )
    engine.result.filtered["dark.example.com"] = "redirect only"
    engine.result.redirects.append(
        Finding(
            subdomain="dark.example.com",
            ip="203.0.113.1",
            port=2082,
            scheme="http",
            url="http://dark.example.com:2082",
            status=301,
            initial_status=301,
            title="bounce",
            kind="redirect",
        )
    )
    engine._promote_redirects()
    assert engine.result.filtered == {}
    assert [finding.port for finding in engine.result.findings] == [2082]


def test_tui_command_works_without_a_profile_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: ``main.py tui`` used to raise KeyError('unknown profile None')."""
    import main
    import subsonar.ui.tui as tui_module

    captured: dict[str, object] = {}

    def fake_run_tui(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(tui_module, "run_tui", fake_run_tui)

    args = main.build_parser().parse_args(["tui", "example.com"])
    assert main.cmd_tui(args) == main.EXIT_OK
    assert captured["profile_id"] == 3
    assert captured["domain"] == "example.com"

    captured.clear()
    args = main.build_parser().parse_args(["tui", "example.com", "-p", "8"])
    assert main.cmd_tui(args) == main.EXIT_OK
    assert captured["profile_id"] == 8
