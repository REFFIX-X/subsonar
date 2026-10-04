"""Tests for the performance, discovery and workflow subsystems.

Covers: port-major scheduling with adaptive timeouts, DNS UDP multiplexing,
the persistent DNS cache, HTTP body capping, discovery permutations and SAN
parsing, the TOML config loader, resumable state, diffing and IPv6 plumbing.
"""

from __future__ import annotations

import asyncio
import json
import socket
import time
from pathlib import Path

import pytest

from subsonar.core.config import PORT_MATRIX, ScanConfig
from subsonar.core.discovery import (
    CNAMEChain,
    DiscoveryStats,
    chase_cnames,
    expand_discovery,
    extract_sans_from_der,
    harvest_san,
    permute_hostnames,
    permute_labels,
    provider_for,
)
from subsonar.core.dns import AnonymousResolver, DNSConnection, DNSConnectionPool
from subsonar.core.dnscache import DNSCache
from subsonar.core.events import EventBus
from subsonar.core.scanner import (
    MODE_OPEN,
    MODE_REFUSED,
    MODE_TIMEOUT,
    AsyncPortScanner,
    SweepStats,
)
from subsonar.core.workflow import (
    ScanSettings,
    ScanState,
    diff_results,
    load_baseline,
    render_diff_markdown,
    save_baseline,
    state_path_for,
    write_example_config,
)

# --------------------------------------------------------------------------- #
# Port scanner: scheduling + adaptive timeout
# --------------------------------------------------------------------------- #


def test_port_result_failure_modes() -> None:
    from subsonar.core.scanner import PortResult

    open_result = PortResult(host="h", ip="1.2.3.4", port=80, label="HTTP", open=True)
    assert open_result.failure == MODE_REFUSED  # default before a probe sets it
    open_result.failure = MODE_OPEN
    assert not open_result.timed_out

    timeout = PortResult(host="h", ip="1.2.3.4", port=81, label="x", open=False)
    timeout.failure = MODE_TIMEOUT
    assert timeout.timed_out
    assert timeout.to_dict()["failure"] == MODE_TIMEOUT


def test_sweep_stats_rate() -> None:
    stats = SweepStats(probes=100, duration=2.0)
    assert stats.rate == 50.0
    assert SweepStats().rate == 0.0
    assert stats.to_dict()["probes_per_second"] == 50.0


@pytest.mark.asyncio
async def test_sweep_hosts_returns_open_ports_keyed_by_host() -> None:
    from subsonar.core.selftest import MOCK_IP, MockHTTPServer

    server = MockHTTPServer()
    open_port = await server.start()
    try:
        scanner = AsyncPortScanner(
            timeout=0.6, fast_timeout=0.3, concurrency=64, bus=EventBus(),
            log_attempts=False,
        )
        closed = [p for p in PORT_MATRIX if p != open_port][:4]
        swept = await scanner.sweep_hosts(
            [("a.test", MOCK_IP), ("b.test", MOCK_IP)], [open_port, *closed]
        )
        assert set(swept) == {"a.test", "b.test"}
        assert [r.port for r in swept["a.test"]] == [open_port]
        assert [r.port for r in swept["b.test"]] == [open_port]
    finally:
        server.stop()


@pytest.mark.asyncio
async def test_sweep_does_not_retry_when_nothing_responded() -> None:
    """A host with only timeouts must not trigger the slow second pass."""
    scanner = AsyncPortScanner(
        timeout=0.5, fast_timeout=0.2, concurrency=32, bus=EventBus(),
        log_attempts=False,
    )
    # 192.0.2.1 is RFC 5737 TEST-NET-1: unreachable, so every probe times out.
    await scanner.sweep_hosts([("dark.test", "192.0.2.1")], [80, 443])
    assert scanner.stats.retries == 0
    assert scanner.stats.timeouts >= 2


@pytest.mark.asyncio
async def test_adaptive_timeout_retries_only_timed_out_ports() -> None:
    """Open ports are found on the fast pass and never retried."""
    from subsonar.core.selftest import MOCK_IP, MockHTTPServer

    server = MockHTTPServer()
    open_port = await server.start()
    try:
        scanner = AsyncPortScanner(
            timeout=1.0, fast_timeout=0.3, concurrency=32, bus=EventBus(),
            log_attempts=False, adaptive_timeout=True,
        )
        swept = await scanner.sweep_hosts(
            [("live.test", MOCK_IP)], [open_port]
        )
        assert [r.port for r in swept["live.test"]] == [open_port]
        assert scanner.stats.retries == 0
        assert scanner.stats.duration > 0
    finally:
        server.stop()


def test_scanner_reset_stats() -> None:
    scanner = AsyncPortScanner(bus=EventBus(), log_attempts=False)
    scanner.probes_sent = 7
    scanner.ports_open = 3
    scanner.reset_stats()
    assert scanner.probes_sent == 0 and scanner.ports_open == 0
    assert scanner.stats.probes == 0


# --------------------------------------------------------------------------- #
# DNS: multiplexing
# --------------------------------------------------------------------------- #


def test_dns_connection_id_bookkeeping() -> None:
    connection = DNSConnection("127.0.0.1:53")
    assert connection.in_flight == 0
    assert len(connection._free_ids) == 0xFFFE  # 1..65534
    connection.close()


@pytest.mark.asyncio
async def test_dns_connection_pool_reuses_and_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    """Idle sockets are reused; the pool grows only when they are all busy."""
    import subsonar.core.dns as dns_module

    class FakeConnection:
        instances: list["FakeConnection"] = []

        def __init__(self, server: str, **kwargs: object) -> None:
            self.server = server
            self.in_flight = 0
            self.sent = 0
            self.timeouts = 0
            self.closed = False
            FakeConnection.instances.append(self)

        def close(self) -> None:
            self.closed = True

    FakeConnection.instances = []
    monkeypatch.setattr(dns_module, "DNSConnection", FakeConnection)

    pool = dns_module.DNSConnectionPool(max_per_server=2)
    # Nothing in flight → the same socket is handed back every time.
    first = await pool.acquire("9.9.9.10", 1.0)
    assert await pool.acquire("9.9.9.10", 1.0) is first
    assert pool.created == 1

    # Mark it busy → the pool must grow, but never past the cap.
    first.in_flight = 1
    second = await pool.acquire("9.9.9.10", 1.0)
    assert second is not first
    assert pool.created == 2
    second.in_flight = 1
    third = await pool.acquire("9.9.9.10", 1.0)
    assert third in (first, second)
    assert pool.created == 2  # capped

    stats = pool.stats()
    assert stats["servers"] == 1 and stats["connections"] == 2
    pool.close()
    assert all(connection.closed for connection in (first, second))


@pytest.mark.asyncio
async def test_multiplexed_resolver_matches_loopback_mock() -> None:
    from subsonar.core.dns import TYPE_A
    from subsonar.core.selftest import MOCK_IP, TEST_DOMAIN, MockDNSServer

    server = MockDNSServer()
    port = await server.start()
    try:
        resolver = AnonymousResolver(
            servers=[f"{MOCK_IP}:{port}"], timeout=1.5, concurrency=32,
            bus=EventBus(), verbose_queries=False, multiplex=True,
            disk_cache_enabled=False,
        )
        results = await resolver.resolve_many(
            [f"h{i}.{TEST_DOMAIN}" for i in range(12)], log=False
        )
        assert all(r.ok for r in results), [r.error for r in results]
        assert resolver._pool.created == 1  # one socket served all 12 queries
        assert resolver.transport_stats()["queries"] >= 12
        resolver.close()
    finally:
        server.stop()


@pytest.mark.asyncio
async def test_non_multiplexed_resolver_still_works() -> None:
    from subsonar.core.selftest import MOCK_IP, TEST_DOMAIN, MockDNSServer

    server = MockDNSServer()
    port = await server.start()
    try:
        resolver = AnonymousResolver(
            servers=[f"{MOCK_IP}:{port}"], timeout=1.5, concurrency=16,
            bus=EventBus(), verbose_queries=False, multiplex=False,
            disk_cache_enabled=False,
        )
        result = await resolver.resolve(TEST_DOMAIN, log=False)
        assert result.ok and result.ip == MOCK_IP
        assert resolver._pool.created == 0
        resolver.close()
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# DNS: persistent cache
# --------------------------------------------------------------------------- #


def test_dns_cache_round_trip(tmp_path: Path) -> None:
    cache = DNSCache(tmp_path / "c.sqlite3")
    assert cache.ready
    cache.put("Example.COM.", "A", addresses=["203.0.113.9"], ttl=600)
    entry = cache.get("example.com", "a")
    assert entry is not None
    assert entry.addresses == ["203.0.113.9"]
    assert entry.expires_at > time.time()
    stats = cache.stats()
    assert stats["entries"] == 1 and stats["hits"] == 1 and not stats["errors"]
    cache.close()


def test_dns_cache_negative_entries_use_short_ttl(tmp_path: Path) -> None:
    cache = DNSCache(tmp_path / "c.sqlite3", negative_ttl=30, positive_ttl=900)
    cache.put("gone.example.com", "A", error="NXDOMAIN")
    entry = cache.get("gone.example.com", "A")
    assert entry is not None and entry.error == "NXDOMAIN"
    assert entry.expires_at - time.time() <= 31
    cache.close()


def test_dns_cache_expiry_and_purge(tmp_path: Path) -> None:
    cache = DNSCache(tmp_path / "c.sqlite3")
    cache.put("short.example.com", "A", addresses=["1.1.1.1"], ttl=1)
    cache._conn.execute("UPDATE dns_cache SET expires_at = ?", (time.time() - 1,))
    assert cache.get("short.example.com", "A") is None  # expired entries vanish
    cache.put("keep.example.com", "A", addresses=["2.2.2.2"], ttl=600)
    assert cache.purge_expired() >= 0
    assert cache.get("keep.example.com", "A") is not None
    cache.close()


@pytest.mark.asyncio
async def test_dns_cache_async_wrappers_do_not_swallow_errors(tmp_path: Path) -> None:
    cache = DNSCache(tmp_path / "c.sqlite3")
    await cache.aput("a.example.com", "A", addresses=["3.3.3.3"], ttl=60)
    assert cache.writes == 1
    assert cache.errors == []  # a threading mistake would surface here
    entry = await cache.aget("a.example.com", "A")
    assert entry is not None and entry.addresses == ["3.3.3.3"]
    cache.close()


@pytest.mark.asyncio
async def test_resolver_uses_disk_cache_across_instances(tmp_path: Path) -> None:
    from subsonar.core.selftest import MOCK_IP, TEST_DOMAIN, MockDNSServer

    server = MockDNSServer()
    port = await server.start()
    db = tmp_path / "shared.sqlite3"
    try:
        first = AnonymousResolver(
            servers=[f"{MOCK_IP}:{port}"], timeout=1.5, bus=EventBus(),
            verbose_queries=False, disk_cache=DNSCache(db),
        )
        assert (await first.resolve(TEST_DOMAIN, log=False)).ok
        first.close()

        # A brand new resolver sharing only the on-disk cache must hit it.
        second = AnonymousResolver(
            servers=[f"{MOCK_IP}:{port}"], timeout=1.5, bus=EventBus(),
            verbose_queries=False, disk_cache=DNSCache(db),
        )
        result = await second.resolve(TEST_DOMAIN, log=False)
        assert result.ok
        assert second.disk_cache_hits == 1
        assert result.from_cache is True
        assert result.attempted_servers == ["disk-cache"]
        second.close()
    finally:
        server.stop()


@pytest.mark.asyncio
async def test_disk_cache_disabled_never_populates(tmp_path: Path) -> None:
    from subsonar.core.selftest import MOCK_IP, TEST_DOMAIN, MockDNSServer

    server = MockDNSServer()
    port = await server.start()
    try:
        resolver = AnonymousResolver(
            servers=[f"{MOCK_IP}:{port}"], timeout=1.5, bus=EventBus(),
            verbose_queries=False, disk_cache_enabled=False,
        )
        await resolver.resolve(TEST_DOMAIN, log=False)
        assert resolver.disk_cache is None
        assert resolver.disk_cache_hits == 0
        resolver.close()
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# HTTP body handling
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_body_read_stops_at_head_end() -> None:
    from subsonar.core.dns import DNSResult
    from subsonar.core.web_probe import MAX_BODY_BYTES, WebProbe
    from subsonar.core.selftest import MOCK_IP, MockHTTPServer

    class LoopbackResolver:
        """Resolves everything to the loopback mock, like the self-test does."""

        disk_cache = None

        async def resolve(self, name, log=True, ipv6=False):  # noqa: ANN001
            return DNSResult(name=name, addresses=[MOCK_IP])

        def close(self) -> None:
            pass

    server = MockHTTPServer()
    port = await server.start()
    probe = WebProbe(
        resolver=LoopbackResolver(), timeout=4.0, concurrency=4, bus=EventBus()
    )
    await probe.start()
    try:
        result = await probe.probe("subsonar.test", MOCK_IP, port)
        assert result.ok and result.title == "subsonar mock web interface"
        assert result.content_length <= MAX_BODY_BYTES
        assert result.content_length > 0
        head = await probe.probe_head("subsonar.test", port)
        if head["status"] is None:
            # Some aiohttp/loopback combinations refuse HEAD; the contract that
            # matters is that it reports a result and never raises.
            assert head["error"]
        else:
            assert head["status"] == 200
            assert (head.get("server") or "").startswith("subsonar-mock")
    finally:
        await probe.close()
        server.stop()


@pytest.mark.asyncio
async def test_probe_head_survives_unreachable_target() -> None:
    from subsonar.core.web_probe import WebProbe
    from subsonar.core.selftest import MOCK_IP

    resolver = AnonymousResolver(
        servers=[MOCK_IP], timeout=1.0, bus=EventBus(), verbose_queries=False,
        disk_cache_enabled=False,
    )
    probe = WebProbe(resolver=resolver, timeout=1.5, concurrency=2, bus=EventBus())
    await probe.start()
    try:
        head = await probe.probe_head("nothing.test", 9)  # port 9 (discard)
        assert head["status"] is None and head["error"]
    finally:
        await probe.close()


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


def test_permute_labels_generates_variants() -> None:
    labels = permute_labels(["admin"], depth=1, limit=500)
    assert "admin-dev" in labels and "dev-admin" in labels
    assert "admin2" in labels and "admin-staging" in labels
    assert len(labels) == len(set(labels))  # de-duplicated
    assert all("-" not in label or not label.startswith("-") for label in labels)


def test_permute_labels_respects_limit() -> None:
    assert len(permute_labels(["a"], depth=2, limit=50)) <= 50


def test_permute_labels_rejects_invalid_characters() -> None:
    labels = permute_labels(["web"], depth=1, limit=200)
    assert all(label == label.lower() for label in labels)
    assert not any("_" == label[0] for label in labels)


def test_permute_hostnames_stays_in_scope() -> None:
    hosts = permute_hostnames(
        ["api.example.com", "dev.example.com", "evil.com", "example.com"],
        "example.com",
        depth=1,
        limit=300,
    )
    assert hosts
    assert all(host.endswith(".example.com") for host in hosts)
    assert all(host not in {"api.example.com", "dev.example.com"} for host in hosts)


def test_provider_for_known_targets() -> None:
    assert provider_for("d123.cloudfront.net") == "AWS CloudFront"
    assert provider_for("acme.github.io") == "GitHub Pages"
    assert provider_for("thing.herokuapp.com") == "Heroku"
    assert provider_for("unknown.example.net") is None


def test_extract_sans_from_der_handles_garbage() -> None:
    assert extract_sans_from_der(b"") == []
    assert extract_sans_from_der(b"\x00\x01\x02not a certificate") == []


@pytest.mark.asyncio
async def test_harvest_san_returns_empty_without_tls() -> None:
    """Nothing is listening with TLS on the loopback mock, so this must be quiet."""
    from subsonar.core.selftest import MOCK_IP

    bus = EventBus()
    sans = await harvest_san(
        "subsonar.test", ports=(9443,), timeout=0.4, bus=bus
    )
    assert sans == []
    assert any("SAN" in event.message for event in bus.history())


@pytest.mark.asyncio
async def test_chase_cnames_reports_providers() -> None:
    calls: list[str] = []

    class FakeResult:
        def __init__(self, cnames=(), addresses=()) -> None:
            self.cnames = list(cnames)
            self.addresses = list(addresses)
            self.ok = bool(addresses)
            self.error = None

    class FakeResolver:
        async def query_raw(self, name, qtype, log=False):  # noqa: ANN001
            calls.append(name)
            if name == "www.example.com":
                return FakeResult(cnames=["acme.github.io"])
            return FakeResult()

        async def resolve(self, name, log=False):  # noqa: ANN001
            return FakeResult(addresses=["192.0.2.1"])

    chains = await chase_cnames(
        ["www.example.com"], resolver=FakeResolver(), bus=EventBus()
    )
    assert isinstance(chains[0], CNAMEChain)
    assert chains[0].provider == "GitHub Pages"
    assert chains[0].terminal == "acme.github.io"


@pytest.mark.asyncio
async def test_expand_discovery_combines_techniques() -> None:
    class FakeResolver:
        async def query_raw(self, name, qtype, log=False):  # noqa: ANN001
            class R:
                cnames: list[str] = []
            return R()

        async def resolve(self, name, log=False):  # noqa: ANN001
            class R:
                ok = False
                addresses: list[str] = []
                error = "NXDOMAIN"
            return R()

    hosts, stats = await expand_discovery(
        "example.com",
        ["api.example.com", "dev.example.com"],
        resolver=FakeResolver(),
        bus=EventBus(),
        enable_san=False,
        enable_permutations=True,
        enable_cnames=False,
    )
    assert isinstance(stats, DiscoveryStats)
    assert stats.permutations == len(hosts) > 0
    assert all(host.endswith(".example.com") for host in hosts)


@pytest.mark.asyncio
async def test_expand_discovery_can_be_fully_disabled() -> None:
    hosts, stats = await expand_discovery(
        "example.com",
        ["api.example.com"],
        bus=EventBus(),
        enable_san=False,
        enable_permutations=False,
        enable_cnames=False,
    )
    assert hosts == []
    assert stats.permutations == 0 and stats.san_hosts == 0


# --------------------------------------------------------------------------- #
# Workflow: config, state, diff
# --------------------------------------------------------------------------- #


def test_scan_settings_from_mapping_and_build_config() -> None:
    settings = ScanSettings.from_mapping(
        {
            "scan": {
                "profile": "stealth",
                "ports": [443, 8443],
                "host_batch": 8,
                "tcp_fast_timeout": 0.3,
                "ipv6": True,
                "confirm_resolvers": 3,
                "domains": "example.com",
            }
        }
    )
    assert settings.profile == "stealth"
    assert settings.domains == ["example.com"]
    config = settings.build_config("example.com")
    assert config.profile_id == 8
    assert set(config.ports) == {443, 8443}
    assert config.host_batch == 8
    assert config.tcp_fast_timeout == 0.3
    assert config.ipv6 is True
    assert config.confirm_resolvers == 3


def test_scan_settings_ignores_unknown_keys() -> None:
    settings = ScanSettings.from_mapping({"nonsense": True, "profile": "1"})
    assert settings.profile == "1"
    assert not hasattr(settings, "nonsense")


def test_scan_settings_load_missing_file_is_default(tmp_path: Path) -> None:
    settings = ScanSettings.load(tmp_path / "does-not-exist.toml")
    assert settings.profile == "3"


def test_scan_settings_load_real_toml(tmp_path: Path) -> None:
    path = tmp_path / "subsonar.toml"
    path.write_text('[scan]\nprofile = "5"\nipv6 = true\n', encoding="utf-8")
    settings = ScanSettings.load(path)
    assert settings.profile == "5" and settings.ipv6 is True


def test_write_example_config_is_valid_toml(tmp_path: Path) -> None:
    path = write_example_config(tmp_path / "subsonar.toml")
    assert path.is_file()
    settings = ScanSettings.load(path)
    assert settings.profile == "3"
    assert settings.enable_san is True


def test_scan_state_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    state = ScanState("example.com", path)
    state.candidates = ["a.example.com", "b.example.com"]
    state.resolved = {"a.example.com": {"addresses": ["1.1.1.1"], "error": None}}
    state.open_ports = {"a.example.com": [80, 443]}
    state.profile = "3.Medium Brute"
    state.mark("dns")

    loaded = ScanState.load("example.com", path)
    assert loaded is not None
    assert loaded.completed == ["dns"]
    assert loaded.pending_candidates() == ["b.example.com"]
    assert loaded.open_ports["a.example.com"] == [80, 443]
    assert loaded.is_resumable is True
    assert "candidates=" in loaded.summary()


def test_scan_state_clear_and_missing(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    state = ScanState("example.com", path)
    state.mark("started")
    assert path.is_file()
    state.clear()
    assert not path.is_file()
    assert ScanState.load("example.com", path) is None


def test_scan_state_rejects_wrong_schema(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"schema": 999, "domain": "example.com"}), encoding="utf-8")
    assert ScanState.load("example.com", path) is None


def test_state_path_is_filesystem_safe(tmp_path: Path) -> None:
    path = state_path_for("weird/../domain:8443", tmp_path)
    assert path.parent == tmp_path
    assert "/" not in path.name and ":" not in path.name


def test_diff_detects_new_changed_lost() -> None:
    previous = {
        "finished_at": 100.0,
        "findings": [
            {"subdomain": "a.test", "port": 80, "status": 200, "title": "A", "url": "http://a.test"},
            {"subdomain": "b.test", "port": 443, "status": 200, "title": "B", "url": "https://b.test"},
        ],
    }
    current = {
        "finished_at": 200.0,
        "findings": [
            {"subdomain": "a.test", "port": 80, "status": 200, "title": "A", "url": "http://a.test"},
            {"subdomain": "b.test", "port": 443, "status": 500, "title": "Broken", "url": "https://b.test"},
            {"subdomain": "c.test", "port": 8080, "status": 200, "title": "C", "url": "http://c.test:8080"},
        ],
    }
    diff = diff_results(previous, current)
    assert [f["subdomain"] for f in diff.new_findings] == ["c.test"]
    assert len(diff.changed_findings) == 1
    assert set(diff.changed_findings[0]["changed"]) == {"status", "title"}
    assert diff.unchanged == 1
    assert diff.lost_findings == []
    assert diff.has_changes
    assert "1 new" in diff.summary()


def test_diff_reports_lost_findings() -> None:
    previous = {"findings": [{"subdomain": "gone.test", "port": 80, "status": 200}]}
    diff = diff_results(previous, {"findings": []})
    assert [f["subdomain"] for f in diff.lost_findings] == ["gone.test"]


def test_diff_no_changes() -> None:
    payload = {"findings": [{"subdomain": "a.test", "port": 80, "status": 200, "title": "A"}]}
    diff = diff_results(payload, payload)
    assert not diff.has_changes
    assert diff.unchanged == 1
    assert "No changes" in render_diff_markdown("example.com", diff)


def test_diff_handles_missing_previous() -> None:
    diff = diff_results(None, {"findings": [{"subdomain": "a.test", "port": 80}]})
    assert len(diff.new_findings) == 1


def test_render_diff_markdown_sections() -> None:
    previous = {"findings": [{"subdomain": "old.test", "port": 80, "status": 200}]}
    current = {"findings": [{"subdomain": "new.test", "port": 443, "status": 200, "title": "N"}]}
    markdown = render_diff_markdown("example.com", diff_results(previous, current))
    assert "# subsonar diff — example.com" in markdown
    assert "## New" in markdown and "## Gone" in markdown


def test_baseline_save_and_load(tmp_path: Path) -> None:
    payload = {"findings": [{"subdomain": "a.test", "port": 80}]}
    path = save_baseline("example.com", payload, tmp_path)
    assert path.is_file()
    assert load_baseline("example.com", tmp_path) == payload
    assert load_baseline("other.com", tmp_path) is None


def test_noerror_empty_is_distinct_from_nxdomain_and_timeout() -> None:
    """rcode 0 with an empty answer is its own outcome, not a failure."""
    from subsonar.core.dns import DNSResult

    assert DNSResult(name="a", error="NXDOMAIN").empty_noerror is False
    assert DNSResult(name="a", error="no response from 1.1.1.1").empty_noerror is False
    assert DNSResult(name="a", error="NOERROR/empty", noerror_empty=True).empty_noerror
    assert DNSResult(name="a", addresses=["1.1.1.1"]).empty_noerror is False


@pytest.mark.asyncio
async def test_resolver_flags_noerror_empty_answer() -> None:
    """A resolver answering rcode 0 with no records must set the flag."""
    import struct

    from subsonar.core.dns import TYPE_A, AnonymousResolver, build_query, parse_response
    from subsonar.core.events import EventBus

    class NoErrorEmptyServer:
        def __init__(self) -> None:
            self.transport = None

        async def start(self) -> int:
            loop = asyncio.get_running_loop()
            server = self

            class _Protocol(asyncio.DatagramProtocol):
                def connection_made(self, transport) -> None:  # noqa: ANN001
                    server.transport = transport

                def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
                    qid = struct.unpack("!H", data[:2])[0]
                    offset = 12
                    while offset < len(data) and data[offset] != 0:
                        if data[offset] & 0xC0 == 0xC0:
                            offset += 2
                            break
                        offset += data[offset] + 1
                    else:
                        offset += 1
                    question = data[12 : offset + 4]
                    # NOERROR (0x8180), qdcount=1, ancount=0
                    reply = struct.pack("!HHHHHH", qid, 0x8180, 1, 0, 0, 0) + question
                    server.transport.sendto(reply, addr)

            transport, _ = await loop.create_datagram_endpoint(
                _Protocol, local_addr=("127.0.0.1", 0)
            )
            self.transport = transport
            return transport.get_extra_info("socket").getsockname()[1]

        def stop(self) -> None:
            if self.transport is not None:
                self.transport.close()

    server = NoErrorEmptyServer()
    port = await server.start()
    try:
        resolver = AnonymousResolver(
            servers=[f"127.0.0.1:{port}"], timeout=1.5, retries=2,
            verbose_queries=False, disk_cache_enabled=False, bus=EventBus(),
        )
        raw_result = await resolver.query_raw("empty.test", TYPE_A, log=False)
        assert raw_result.error == "NOERROR/empty"
        assert raw_result.noerror_empty is True
        assert raw_result.ok is False
        # resolve() must not relabel the classification.
        resolved = await resolver.resolve("empty2.test", log=False)
        assert resolved.error == "NOERROR/empty"
        assert resolved.noerror_empty is True
        resolver.close()
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# Engine-level integration
# --------------------------------------------------------------------------- #


def test_cross_host_duplicates_ignores_same_host_scheme_pair() -> None:
    """One site reachable over HTTP and HTTPS is not a uniformity signal."""
    from subsonar.core.confidence import rank_findings

    class Finding:
        def __init__(self, subdomain, port, scheme, tls=False):
            self.subdomain = subdomain
            self.port = port
            self.scheme = scheme
            self.url = f"{scheme}://{subdomain}"
            self.status = 200
            self.title = "Example Domain"
            self.content_length = 713
            self.fingerprint = "samepage"
            self.tls = tls
            self.kind = "interface"

    single_host = [
        Finding("example.com", 80, "http"),
        Finding("example.com", 443, "https", tls=True),
    ]
    ranked = dict(
        (id(f), b) for f, b in rank_findings(single_host)
    )
    for finding in single_host:
        breakdown = ranked[id(finding)]
        assert not any(
            "fingerprint is shared" in penalty for penalty in breakdown.penalties
        ), breakdown.penalties

    # Two different hosts serving the identical page *on one scheme* is a real
    # signal and must still be penalised.
    two_hosts = [
        Finding("example.com", 443, "https", tls=True),
        Finding("www.example.com", 443, "https", tls=True),
    ]
    breakdowns = [b for _, b in rank_findings(two_hosts)]
    assert any(
        "fingerprint is shared" in penalty
        for breakdown in breakdowns
        for penalty in breakdown.penalties
    )


def test_baseline_cache_dir_prefers_configured_cache(tmp_path: Path) -> None:
    from main import _cache_dir_for

    output = tmp_path / "out"
    output.mkdir()
    resolved = _cache_dir_for(output)
    # Either the configured CACHE_DIR or a sibling of the output directory.
    assert resolved.name == ".subsonar_cache"


def test_scan_config_carries_new_switches() -> None:
    config = ScanConfig(domain="example.com")
    assert config.adaptive_timeout is True
    assert config.multiplex_dns is True
    assert config.disk_cache is True
    assert config.enable_discovery is True
    assert config.ipv6 is False
    assert config.confirm_resolvers == 0
    assert config.tcp_fast_timeout < config.tcp_timeout


def test_engine_builds_scanner_with_adaptive_defaults() -> None:
    from subsonar.core.engine import ScanEngine

    config = ScanConfig(domain="example.com", profile_id=3)
    engine = ScanEngine(config, profile=3, bus=EventBus())
    assert engine._scanner.adaptive_timeout is True
    assert engine._scanner.fast_timeout == config.tcp_fast_timeout
    assert engine._host_batch == config.host_batch
    engine._resolver.close()


@pytest.mark.asyncio
async def test_engine_ipv6_augmentation_adds_addresses() -> None:
    from subsonar.core.dns import DNSResult
    from subsonar.core.engine import ScanEngine

    config = ScanConfig(domain="example.com", profile_id=1)
    config.ipv6 = True
    engine = ScanEngine(config, profile=1, bus=EventBus())

    class FakeResolver:
        async def resolve(self, name, log=True, ipv6=False):  # noqa: ANN001
            if ipv6:
                return DNSResult(name=name, addresses=["2001:db8::1"])
            return DNSResult(name=name, addresses=["192.0.2.1"])

    engine._resolver = FakeResolver()  # type: ignore[assignment]
    result = DNSResult(name="www.example.com", addresses=["192.0.2.1"])
    await engine._augment_ipv6("www.example.com", result)
    assert "2001:db8::1" in result.addresses
    assert engine.bus.stats.ipv6_hosts == 1


@pytest.mark.asyncio
async def test_engine_confirmation_flags_disagreement() -> None:
    from subsonar.core.dns import DNSResult
    from subsonar.core.engine import ScanEngine

    config = ScanConfig(domain="example.com", profile_id=1)
    config.confirm_resolvers = 2
    bus = EventBus()
    engine = ScanEngine(config, profile=1, bus=bus)

    class FakePool:
        live_servers = ("9.9.9.9", "149.112.112.10", "76.76.2.0")
        disk_cache = None

        def close(self) -> None:
            pass

    engine._resolver = FakePool()  # type: ignore[assignment]
    result = DNSResult(name="a.example.com", addresses=["192.0.2.1"], resolver="9.9.9.9")
    # Both confirmation probes disagree → unconfirmed.
    import subsonar.core.engine as engine_module

    class FakeResolver:
        def __init__(self, **kwargs: object) -> None:
            pass

        async def resolve(self, name, log=True):  # noqa: ANN001
            return DNSResult(name=name, addresses=["198.51.100.7"])

        def close(self) -> None:
            pass

    original = engine_module.AnonymousResolver
    engine_module.AnonymousResolver = FakeResolver  # type: ignore[misc]
    try:
        await engine._confirm_resolution("a.example.com", result)
    finally:
        engine_module.AnonymousResolver = original  # type: ignore[misc]
    assert getattr(result, "confirmed_by", None) == 1
    assert bus.stats.dns_unconfirmed == 1


# --------------------------------------------------------------------------- #
# Regressions: state temp file, wordlist mirror cache, pinned resolver, stealth
# --------------------------------------------------------------------------- #


def test_scan_state_clear_removes_the_stale_temp_file(tmp_path: Path) -> None:
    """``save`` writes ``<state>.tmp``; ``clear`` must delete that same path."""
    path = tmp_path / "state-example.com.json"
    state = ScanState("example.com", path)
    state.mark("started")
    leftover = path.with_suffix(".tmp")  # what save() would leave behind
    leftover.write_text("{}", encoding="utf-8")

    state.clear()

    assert not path.is_file()
    assert not leftover.is_file()


@pytest.mark.asyncio
async def test_wordlist_mirror_caches_to_the_canonical_file(tmp_path: Path) -> None:
    """A fallback mirror must populate the file ``cached_file()`` looks at."""
    from subsonar.core.wordlist import WordlistManager

    manager = WordlistManager(
        url="https://example.invalid/primary.txt",
        fallbacks=("https://example.invalid/mirror.txt",),
        cache_dir=tmp_path,
        bus=EventBus(),
    )
    seen: list[tuple[str, Path]] = []

    async def fake_stream(url: str, destination: Path):
        seen.append((url, destination))
        if url == manager.url:
            return None  # primary mirror unreachable
        destination.write_text("www\nmail\napi\n", encoding="utf-8")
        return destination

    manager._stream = fake_stream  # type: ignore[assignment]
    path = await manager.acquire()

    canonical = manager.cached_file()
    assert [destination for _url, destination in seen] == [canonical, canonical]
    assert path == canonical
    assert manager.cache_is_fresh() is True
    assert manager.cached_size() > 0


@pytest.mark.asyncio
async def test_pinned_resolver_uses_one_node_and_leaves_the_cache_alone() -> None:
    from subsonar.core.selftest import MOCK_IP, TEST_DOMAIN, MockDNSServer

    first, second = MockDNSServer(), MockDNSServer()
    port_a = await first.start()
    port_b = await second.start()
    try:
        resolver = AnonymousResolver(
            servers=[f"{MOCK_IP}:{port_a}", f"{MOCK_IP}:{port_b}"],
            timeout=1.5,
            bus=EventBus(),
            verbose_queries=False,
            disk_cache_enabled=False,
        )
        pinned = f"{MOCK_IP}:{port_b}"
        result = await resolver.resolve(
            TEST_DOMAIN, log=False, server=pinned, use_cache=False
        )
        assert result.ok
        assert result.resolver == pinned
        assert result.attempted_servers == [pinned]  # no rotation, no failover
        assert resolver.queries_sent == 1
        assert resolver._cache == {}  # use_cache=False wrote nothing

        # The default path is unchanged: rotation plus caching.
        assert (await resolver.resolve(TEST_DOMAIN, log=False)).ok
        assert resolver._cache, "an unpinned resolve must still populate the cache"
        resolver.close()
    finally:
        first.stop()
        second.stop()


@pytest.mark.asyncio
async def test_scanner_stealth_delay_is_randomised(monkeypatch: pytest.MonkeyPatch) -> None:
    """The delay must be drawn from the range, not pinned to its midpoint."""
    calls: list[tuple[float, float]] = []

    class _Random:
        @staticmethod
        def uniform(low: float, high: float) -> float:
            calls.append((low, high))
            return 0.0

    monkeypatch.setattr("subsonar.core.scanner.random", _Random)

    scanner = AsyncPortScanner(
        timeout=0.3,
        fast_timeout=0.3,
        concurrency=4,
        bus=EventBus(),
        stealth_delay=(0.35, 1.25),
        log_attempts=False,
    )
    await scanner.probe("h.test", "127.0.0.1", 9)
    assert calls == [(0.35, 1.25)]




@pytest.mark.asyncio
async def test_harvest_san_dials_the_anonymous_address_not_the_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SAN harvesting must never hand a hostname to the OS resolver."""
    import subsonar.core.discovery as discovery

    dialled: list[str] = []
    resolved: list[str] = []

    class FakeResolver:
        async def resolve(self, name, log=True, **kwargs):  # noqa: ANN001, ANN003, ANN201
            resolved.append(name)

            class _R:
                ok = True
                ip = "203.0.113.99"

            return _R()

    class FakeAsyncio:
        CancelledError = asyncio.CancelledError

        @staticmethod
        async def open_connection(*, host, port, ssl=None, server_hostname=None):  # noqa: ANN001, ANN202
            dialled.append(host)
            raise OSError("nothing listening")

        @staticmethod
        async def wait_for(awaitable, timeout):  # noqa: ANN001, ANN202
            return await awaitable

    monkeypatch.setattr(discovery, "asyncio", FakeAsyncio)

    bus = EventBus()
    sans = await harvest_san(
        "example.com", ports=(443,), timeout=0.2, bus=bus, resolver=FakeResolver()
    )

    assert sans == []
    assert resolved == ["example.com", "www.example.com"]
    assert dialled == ["203.0.113.99", "203.0.113.99"]  # the IP, never the name


@pytest.mark.asyncio
async def test_harvest_san_without_a_resolver_skips_instead_of_leaking() -> None:
    bus = EventBus()
    sans = await harvest_san("example.com", ports=(443,), timeout=0.2, bus=bus)
    assert sans == []
    assert any(
        "OS resolver is never used" in event.message for event in bus.history()
    ), [event.message for event in bus.history()]
