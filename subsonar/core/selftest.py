"""End-to-end engine self-test using loopback mock servers only.

``python main.py selftest`` exercises the *entire* pipeline — DNS wire
encoding/decoding against a mock authoritative server, the anonymous resolver,
wildcard detection and false-positive filtering, the async TCP port matrix, the
HTTP verifier, the live event bus under concurrency, the strict output filter
and every report writer — without sending a single packet to a third party.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .config import (
    DNS_RESOLVER_POOL,
    FORBIDDEN_DNS_SERVERS,
    PORT_MATRIX,
    ScanConfig,
)
from .dns import (
    TYPE_A,
    AnonymousResolver,
    build_query,
    encode_name,
    parse_response,
)
from .events import EventBus
from .profiles import PROFILES, get_profile
from .scanner import AsyncPortScanner
from .web_probe import WebProbe

TEST_DOMAIN = "subsonar.test"
MOCK_IP = "127.0.0.1"
PAGE_TITLE = "subsonar mock web interface"
CANDIDATE_PORTS = (8000, 8888, 8080, 9000, 5000, 3000)


# --------------------------------------------------------------------------- #
# Mock servers
# --------------------------------------------------------------------------- #


class MockDNSServer:
    """Authoritative mock: known labels resolve to 127.0.0.1, everything else NXDOMAIN.

    ``wildcard=True`` makes it answer *every* name with 127.0.0.1, which is used
    to verify wildcard detection and false-positive filtering.
    """

    def __init__(self, *, wildcard: bool = False) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.queries = 0
        self.wildcard = wildcard
        self._protocol: asyncio.DatagramProtocol | None = None

    async def start(self) -> int:
        loop = asyncio.get_running_loop()
        server = self

        class _Protocol(asyncio.DatagramProtocol):
            def connection_made(self, transport: asyncio.BaseTransport) -> None:  # noqa: D401
                server.transport = transport  # type: ignore[assignment]

            def datagram_received(self, data: bytes, addr: Any) -> None:
                server.queries += 1
                response = server._respond(data)
                if response and server.transport is not None:
                    server.transport.sendto(response, addr)

        transport, protocol = await loop.create_datagram_endpoint(
            _Protocol, local_addr=(MOCK_IP, 0)
        )
        self.transport = transport  # type: ignore[assignment]
        self._protocol = protocol
        return transport.get_extra_info("socket").getsockname()[1]

    def _is_wildcard_probe(self, name: str) -> bool:
        """Randomised labels look like ``<12 random letters>-<digit>.domain``."""
        label = name.split(".")[0]
        if "-" not in label:
            return False
        token, _, index = label.rpartition("-")
        return len(token) == 12 and token.isalpha() and index.isdigit()

    def _respond(self, data: bytes) -> bytes | None:
        parsed = _parse_question(data)
        if parsed is None:
            return None
        qid, question, name = parsed
        if not self.wildcard and self._is_wildcard_probe(name):
            return struct.pack("!HHHHHH", qid, 0x8183, 1, 0, 0, 0) + question
        header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
        answer = (
            b"\xc0\x0c"
            + struct.pack("!HHIH", TYPE_A, 1, 60, 4)
            + socket.inet_aton(MOCK_IP)
        )
        return header + question + answer

    def stop(self) -> None:
        if self.transport is not None:
            self.transport.close()


def _parse_question(data: bytes) -> tuple[int, bytes, str] | None:
    """Return ``(query_id, question_bytes, qname)`` for a DNS query packet."""
    if len(data) < 12:
        return None
    qid, _flags, qdcount = struct.unpack("!HHH", data[:6])
    if qdcount < 1:
        return None
    offset = 12
    labels: list[str] = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            label, _ = _decode_label(data, pointer)
            labels.append(label)
            offset += 2
            break
        label, offset = _decode_label(data, offset)
        labels.append(label)
    return qid, data[12 : offset + 4], ".".join(filter(None, labels))


def _decode_label(data: bytes, offset: int) -> tuple[str, int]:
    length = data[offset]
    start = offset + 1
    return data[start : start + length].decode("ascii", "replace"), start + length


class MockHTTPServer:
    """Serves a titled HTML page on 127.0.0.1 for every request."""

    def __init__(self) -> None:
        self.server: asyncio.Server | None = None
        self.port = 0
        self.requests = 0

    async def start(self, candidate_ports: tuple[int, ...] = CANDIDATE_PORTS) -> int:
        server = self

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            server.requests += 1
            try:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
                body = (
                    "<!DOCTYPE html><html><head>"
                    f"<title>{PAGE_TITLE}</title></head>"
                    "<body><h1>subsonar mock</h1>"
                    "<p>anonymous DNS + async port matrix verified</p>"
                    "</body></html>"
                ).encode()
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/html; charset=utf-8\r\n"
                    b"Server: subsonar-mock/1.0\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                    + body
                )
                writer.write(response)
                await writer.drain()
            except Exception:
                pass
            finally:
                with contextlib.suppress(Exception):
                    writer.close()

        last_error: Exception | None = None
        for port in candidate_ports:
            try:
                self.server = await asyncio.start_server(handle, MOCK_IP, port)
                self.port = port
                return port
            except OSError as exc:  # port busy — try the next matrix port
                last_error = exc
                continue
        raise RuntimeError(f"no free matrix port available ({last_error})")

    def stop(self) -> None:
        if self.server is not None:
            self.server.close()


class TLSOnlyPortServer:
    """Mimics Apache on a TLS-only port: plain HTTP gets ``400 Bad Request``.

    This is exactly what real cPanel/WHM (2083/2087/2096) and alt-HTTPS (8443)
    ports do, and it is what produced the "no web interface here" false
    positives on ports like 2082/2086/2095/8080.
    """

    def __init__(self) -> None:
        self.server: asyncio.Server | None = None
        self.port = 0
        self.requests = 0

    async def start(self, candidate_ports: tuple[int, ...] = (9123, 9443, 19443)) -> int:
        server = self

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            server.requests += 1
            try:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
                body = (
                    b"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                    b"<html><head><title>400 The plain HTTP request was sent to "
                    b"HTTPS port</title></head><body><h1>Bad Request</h1>"
                    b"<p>Your browser sent a request that this server could not "
                    b"understand.<br />The plain HTTP request was sent to HTTPS "
                    b"port</p></body></html>\n"
                )
                writer.write(
                    b"HTTP/1.1 400 Bad Request\r\n"
                    b"Content-Type: text/html; charset=iso-8859-1\r\n"
                    b"Server: Apache\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                    + body
                )
                await writer.drain()
            except Exception:
                pass
            finally:
                with contextlib.suppress(Exception):
                    writer.close()

        for port in candidate_ports:
            try:
                self.server = await asyncio.start_server(handle, MOCK_IP, port)
                self.port = port
                return port
            except OSError:
                continue
        return 0

    def stop(self) -> None:
        if self.server is not None:
            self.server.close()


class RedirectOnlyServer:
    """Mimics a Cloudflare alt-port bounce: ``301 Location: https://host/``.

    This is the ``support.example.com:2082`` behaviour — the port answers, but with
    a redirect to the canonical host on 443, where the real interface lives.
    """

    def __init__(self, target: str) -> None:
        self.target = target
        self.server: asyncio.Server | None = None
        self.port = 0

    async def start(self, candidate_ports: tuple[int, ...] = (9500, 9501, 9502)) -> int:
        server = self

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
                body = (
                    f'<html><head><title>301 Moved Permanently</title></head>'
                    f'<body><a href="{server.target}">Moved</a></body></html>'
                ).encode()
                writer.write(
                    b"HTTP/1.1 301 Moved Permanently\r\n"
                    b"Content-Type: text/html; charset=UTF-8\r\n"
                    b"Server: cloudflare\r\n"
                    + f"Location: {server.target}\r\n".encode()
                    + f"Content-Length: {len(body)}\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                    + body
                )
                await writer.drain()
            except Exception:
                pass
            finally:
                with contextlib.suppress(Exception):
                    writer.close()

        for port in candidate_ports:
            try:
                self.server = await asyncio.start_server(handle, MOCK_IP, port)
                self.port = port
                return port
            except OSError:
                continue
        return 0

    def stop(self) -> None:
        if self.server is not None:
            self.server.close()


# --------------------------------------------------------------------------- #
# Check harness
# --------------------------------------------------------------------------- #


@dataclass
class Check:
    name: str
    ok: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail}


async def run_selftest(
    *,
    report_dir: Path | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Run every self-test check and return a JSON-serialisable report."""
    started = time.perf_counter()
    checks: list[Check] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        checks.append(Check(name=name, ok=ok, detail=detail))
        if progress is not None:
            progress(f"{'✔' if ok else '✖'} {name} — {detail}")

    # -- static guarantees ------------------------------------------------- #
    leaked = sorted(FORBIDDEN_DNS_SERVERS.intersection(DNS_RESOLVER_POOL))
    record(
        "dns privacy contract",
        not leaked and len(DNS_RESOLVER_POOL) >= 10,
        f"{len(DNS_RESOLVER_POOL)} anonymous resolvers, no Google/Cloudflare "
        f"({'clean' if not leaked else 'LEAK: ' + ','.join(leaked)})",
    )
    record(
        "top-50 port matrix",
        len(PORT_MATRIX) == 50,
        f"{len(PORT_MATRIX)} ports embedded",
    )
    record(
        "8 scan profiles",
        len(PROFILES) == 8 and [p.id for p in PROFILES] == list(range(1, 9)),
        ", ".join(f"{p.id}:{p.key}" for p in PROFILES),
    )

    # -- DNS wire protocol -------------------------------------------------- #
    try:
        packet, qid = build_query("www.example.com", TYPE_A)
        records, rcode = parse_response(
            struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
            + packet[12:]
            + b"\xc0\x0c"
            + struct.pack("!HHIH", TYPE_A, 1, 300, 4)
            + socket.inet_aton("93.184.216.34"),
            qid,
        )
        record(
            "dns wire round-trip",
            rcode == 0 and [r.value for r in records] == ["93.184.216.34"],
            f"encode+decode OK ({[r.value for r in records]})",
        )
    except Exception as exc:
        record("dns wire round-trip", False, f"{exc.__class__.__name__}: {exc}")

    try:
        encoded = encode_name(TEST_DOMAIN)
        record(
            "dns name encoding",
            encoded.endswith(b"\x00") and len(encoded) == len(TEST_DOMAIN) + 2,
            f"{encoded!r}",
        )
    except Exception as exc:
        record("dns name encoding", False, f"{exc}")

    # -- mock servers ------------------------------------------------------- #
    dns = MockDNSServer()
    http = MockHTTPServer()
    dns_port = 0
    http_port = 0
    resolver: AnonymousResolver | None = None
    probe: WebProbe | None = None
    try:
        dns_port = await dns.start()
        record("mock authoritative DNS", True, f"udp/127.0.0.1:{dns_port}")
    except Exception as exc:
        record("mock authoritative DNS", False, f"{exc}")
    try:
        http_port = await http.start()
        record("mock web interface", True, f"http://127.0.0.1:{http_port}")
    except Exception as exc:
        record("mock web interface", False, f"{exc}")

    if dns_port and http_port:
        mock_server = f"{MOCK_IP}:{dns_port}"
        resolver = AnonymousResolver(
            servers=[mock_server],
            timeout=1.5,
            retries=2,
            concurrency=64,
            bus=EventBus(),
            verbose_queries=False,
        )
        # -- anonymous resolution against the mock server ------------------ #
        result = await resolver.resolve(TEST_DOMAIN, log=False)
        record(
            "async dns resolution",
            result.ok and result.ip == MOCK_IP,
            f"{TEST_DOMAIN} → {result.addresses} via [{result.resolver}] "
            f"in {result.rtt_ms:.1f} ms",
        )

        # -- wildcard detection + false-positive filtering ----------------- #
        try:
            report = await resolver.detect_wildcard(TEST_DOMAIN, samples=2)
            record(
                "wildcard check (non-wildcard zone)",
                not report.wildcard,
                f"wildcard={report.wildcard} — non-wildcard zone correctly cleared",
            )
        except Exception as exc:
            record("wildcard check (non-wildcard zone)", False, f"{exc.__class__.__name__}: {exc}")

        try:
            wildcard_dns = MockDNSServer(wildcard=True)
            wildcard_port = await wildcard_dns.start()
            wildcard_resolver = AnonymousResolver(
                servers=[f"{MOCK_IP}:{wildcard_port}"],
                timeout=1.5,
                concurrency=16,
                bus=EventBus(),
                verbose_queries=False,
            )
            report = await wildcard_resolver.detect_wildcard(TEST_DOMAIN, samples=2)
            fp = report.is_false_positive([MOCK_IP])
            record(
                "wildcard detection + filtering",
                report.wildcard and fp and report.is_false_positive(["127.0.0.1"]),
                f"wildcard={report.wildcard} ips={sorted(report.ips)} "
                f"false-positive filter={'active' if fp else 'INACTIVE'}",
            )
            wildcard_dns.stop()
        except Exception as exc:
            record("wildcard detection + filtering", False, f"{exc.__class__.__name__}: {exc}")

        # -- async TCP port scanner ---------------------------------------- #
        scanner = AsyncPortScanner(timeout=1.0, concurrency=32, bus=EventBus(), log_attempts=False)
        open_ports = await scanner.scan_host(TEST_DOMAIN, MOCK_IP, (http_port, 9001))
        record(
            "async port matrix probe",
            [p.port for p in open_ports] == [http_port],
            f"open={[p.port for p in open_ports]} probes={scanner.probes_sent}",
        )

        # -- HTTP verification + title extraction -------------------------- #
        probe = WebProbe(resolver=resolver, timeout=4.0, concurrency=8, bus=EventBus())
        await probe.start()
        web = await probe.probe(TEST_DOMAIN, MOCK_IP, http_port)
        record(
            "http verification + title",
            web.ok and web.status == 200 and web.title == PAGE_TITLE,
            f"status={web.status} title={web.title!r} url={web.url}",
        )
        # 9001 is closed → the strict filter must drop it.
        closed = await probe.probe(TEST_DOMAIN, MOCK_IP, 9001)
        record(
            "strict web-interface filter",
            not closed.ok,
            f"closed port rejected ({closed.error or 'unreachable'})",
        )

        # -- protocol-error rejection (the 20xx/8443 false positive) -------- #
        try:
            tls_only = TLSOnlyPortServer()
            tls_only_port = await tls_only.start()
            if not tls_only_port:
                record(
                    "protocol-error rejection",
                    False,
                    "could not bind any candidate port for the mock",
                )
            else:
                rejected = await probe.probe(TEST_DOMAIN, MOCK_IP, tls_only_port)
                # The TLS-only mock answers a plain HTTP probe with Apache's
                # "400 The plain HTTP request was sent to HTTPS port".  subsonar
                # must either reject that outright or upgrade to https and fail
                # to negotiate — in both cases no interface is reported.
                accepted_interface = rejected.ok
                upgraded = "https" in rejected.attempted_schemes
                record(
                    "protocol-error rejection",
                    not accepted_interface and upgraded,
                    f"plain HTTP on a TLS-only port rejected "
                    f"(status={rejected.status}, kind={rejected.kind!r}, "
                    f"schemes={rejected.attempted_schemes}) — this is the "
                    f"2082/2086/2095/8443 false-positive class",
                )
                accepted = await probe.probe(TEST_DOMAIN, MOCK_IP, http_port)
                record(
                    "genuine interface still accepted",
                    accepted.ok and accepted.kind == "interface",
                    f"status={accepted.status} kind={accepted.kind}",
                )
            tls_only.stop()
        except Exception as exc:
            record(
                "protocol-error rejection",
                False,
                f"{exc.__class__.__name__}: {exc}",
            )

        # -- redirect attribution (the 2082 bounce) -------------------------- #
        try:
            # Bounce to the live mock web server on a *different* port, which is
            # precisely the support.example.com:2082 → :443 situation.
            bounce_target = f"http://{TEST_DOMAIN}:{http_port}/support/home"
            bounce = RedirectOnlyServer(target=bounce_target)
            bounce_port = await bounce.start()
            if not bounce_port:
                record(
                    "redirect attribution",
                    False,
                    "could not bind any candidate port for the mock",
                )
            else:
                from .web_probe import is_redirect_only

                bounced = await probe.probe(TEST_DOMAIN, MOCK_IP, bounce_port)
                record(
                    "redirect attribution",
                    not bounced.ok
                    and is_redirect_only(bounced)
                    and bounced.initial_status == 301
                    and bounced.final_url == bounce_target,
                    f"{bounced.initial_status} bounce on port {bounce_port} → "
                    f"{bounced.final_url} is not reported as an interface "
                    f"(kind={bounced.kind!r}, status={bounced.status})",
                )
            bounce.stop()
        except Exception as exc:
            record("redirect attribution", False, f"{exc.__class__.__name__}: {exc}")

    # -- performance subsystems -------------------------------------------- #
    try:
        from .dnscache import DNSCache

        cache_path = (Path(report_dir) if report_dir else Path(".subsonar_cache") / "selftest")
        cache_path.mkdir(parents=True, exist_ok=True)
        db = cache_path / "selftest-dns-cache.sqlite3"
        for stale in cache_path.glob("selftest-dns-cache.sqlite3*"):
            stale.unlink(missing_ok=True)

        mux_dns = MockDNSServer(wildcard=True)
        mux_port = await mux_dns.start()
        mux_resolver = AnonymousResolver(
            servers=[f"{MOCK_IP}:{mux_port}"], timeout=1.5, concurrency=32,
            bus=EventBus(), verbose_queries=False, multiplex=True,
            disk_cache=DNSCache(db),
        )
        mux_results = await mux_resolver.resolve_many(
            [f"m{i}.{TEST_DOMAIN}" for i in range(12)], log=False
        )
        sockets = mux_resolver._pool.created
        record(
            "dns udp multiplexing",
            all(r.ok for r in mux_results) and sockets <= 2,
            f"{len(mux_results)} queries over {sockets} socket(s) "
            f"({mux_resolver.transport_stats()['queries']} sent)",
        )
        mux_resolver.close()

        # A fresh resolver sharing only the on-disk cache must hit it.
        warm_resolver = AnonymousResolver(
            servers=[f"{MOCK_IP}:{mux_port}"], timeout=1.5, bus=EventBus(),
            verbose_queries=False, disk_cache=DNSCache(db),
        )
        warm = await warm_resolver.resolve(f"m0.{TEST_DOMAIN}", log=False)
        record(
            "persistent dns cache",
            warm.ok and warm_resolver.disk_cache_hits == 1,
            f"second resolver answered from disk "
            f"({warm_resolver.disk_cache_hits} hit, attempted={warm.attempted_servers})",
        )
        warm_resolver.close()
        mux_dns.stop()
    except Exception as exc:
        record("dns udp multiplexing", False, f"{exc.__class__.__name__}: {exc}")
        record("persistent dns cache", False, f"{exc.__class__.__name__}: {exc}")

    try:
        from .discovery import permute_hostnames, provider_for

        hosts = permute_hostnames(
            ["api.example.com", "dev.example.com"], "example.com", depth=1, limit=400
        )
        in_scope = hosts and all(h.endswith(".example.com") for h in hosts)
        record(
            "hostname permutations",
            bool(in_scope) and "api-dev.example.com" in hosts,
            f"{len(hosts)} in-scope variants generated locally (no API), "
            f"e.g. {', '.join(hosts[:3])}",
        )
    except Exception as exc:
        record("hostname permutations", False, f"{exc.__class__.__name__}: {exc}")

    try:
        record(
            "cname provider inference",
            provider_for("d1.cloudfront.net") == "AWS CloudFront"
            and provider_for("x.github.io") == "GitHub Pages"
            and provider_for("nothing.example.net") is None,
            "cloudfront.net→AWS CloudFront, github.io→GitHub Pages, "
            "unknown→None",
        )
    except Exception as exc:
        record("cname provider inference", False, f"{exc.__class__.__name__}: {exc}")

    try:
        from .workflow import ScanState, diff_results

        state_dir = (Path(report_dir) if report_dir else Path(".subsonar_cache") / "selftest")
        state_dir.mkdir(parents=True, exist_ok=True)
        state = ScanState(TEST_DOMAIN, state_dir / "selftest-state.json")
        state.candidates = ["a.test", "b.test"]
        state.resolved = {"a.test": {"addresses": ["127.0.0.1"], "error": None}}
        state.mark("dns")
        reloaded = ScanState.load(TEST_DOMAIN, state_dir / "selftest-state.json")
        diff = diff_results(
            {"findings": [{"subdomain": "a.test", "port": 80, "status": 200, "title": "A"}]},
            {
                "findings": [
                    {"subdomain": "a.test", "port": 80, "status": 200, "title": "A"},
                    {"subdomain": "b.test", "port": 443, "status": 200, "title": "B"},
                ]
            },
        )
        record(
            "resumable state + diff",
            reloaded is not None
            and reloaded.pending_candidates() == ["b.test"]
            and len(diff.new_findings) == 1
            and diff.unchanged == 1,
            f"state resumed with {len(reloaded.pending_candidates()) if reloaded else 0} "
            f"pending candidate(s); diff found {len(diff.new_findings)} new / "
            f"{diff.unchanged} unchanged",
        )
        state.clear()
        (state_dir / "selftest-state.json").unlink(missing_ok=True)
    except Exception as exc:
        record("resumable state + diff", False, f"{exc.__class__.__name__}: {exc}")

    try:
        from .workflow import ScanSettings

        settings = ScanSettings.from_mapping(
            {"scan": {"profile": "stealth", "ports": [443, 8443], "ipv6": True}}
        )
        config = settings.build_config(TEST_DOMAIN)
        record(
            "toml config loading",
            config.profile_id == 8 and set(config.ports) == {443, 8443} and config.ipv6,
            f"profile→{config.profile_id}, ports→{sorted(config.ports)}, ipv6→{config.ipv6}",
        )
    except Exception as exc:
        record("toml config loading", False, f"{exc.__class__.__name__}: {exc}")

    try:
        from .scanner import AsyncPortScanner as _Scanner

        # Deterministic: every connect raises TimeoutError, so the scheduling
        # invariants are checked without touching the network or waiting.
        scanner = _Scanner(
            timeout=0.5, fast_timeout=0.2, concurrency=32, bus=EventBus(),
            log_attempts=False,
        )

        async def always_timeout(ip: str, port: int, timeout: float):  # noqa: ANN001
            raise asyncio.TimeoutError()

        scanner._connect = always_timeout  # type: ignore[assignment]
        await scanner.sweep_hosts([("dark.selftest", "192.0.2.1")], [80, 443])
        no_retry = scanner.stats.retries == 0 and scanner.stats.timeouts >= 2

        # Now make one port answer instantly: that host becomes "responsive",
        # so its other timed-out port must be retried once at the slow timeout.
        scanner2 = _Scanner(
            timeout=0.5, fast_timeout=0.2, concurrency=32, bus=EventBus(),
            log_attempts=False,
        )

        class _Writer:
            def close(self) -> None:
                pass

            async def wait_closed(self) -> None:
                return None

        class _Reader:
            async def read(self, n: int) -> bytes:
                return b""

        async def open_on_443(ip: str, port: int, timeout: float):  # noqa: ANN001
            if port == 443:
                return _Reader(), _Writer()
            raise asyncio.TimeoutError()

        scanner2._connect = open_on_443  # type: ignore[assignment]
        swept = await scanner2.sweep_hosts([("mixed.selftest", "192.0.2.1")], [80, 443])
        retried = scanner2.stats.retries >= 1
        found = [r.port for r in swept.get("mixed.selftest", [])]
        record(
            "adaptive timeout scheduling",
            no_retry and retried and found == [443],
            f"unresponsive host: {scanner.stats.timeouts} timeouts / "
            f"{scanner.stats.retries} retries (not retried); responsive host: "
            f"{scanner2.stats.retries} adaptive retry, open ports {found}",
        )
    except Exception as exc:
        record("adaptive timeout scheduling", False, f"{exc.__class__.__name__}: {exc}")

    # -- concurrency / live event bus --------------------------------------- #
    try:
        bus = EventBus()
        # Exercise genuine cross-thread concurrency with a small worker pool
        # rather than 500 OS threads: that many simultaneous threads saturate
        # the machine's ephemeral port pool on Windows, which then made later
        # checks fail for entirely unrelated reasons.
        import threading

        workers = 8
        per_worker = 75

        def writer(worker: int) -> None:
            for index in range(per_worker):
                bus.emit(
                    f"concurrent event {worker}-{index}",
                    "info",
                    "stat",
                    host=f"h{index}.test",
                )

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        expected = workers * per_worker
        drained = bus.drain(limit=expected + 10)
        record(
            "live event bus concurrency",
            len(drained) == expected and len(bus.history()) == expected,
            f"{len(drained)} events captured from {workers} concurrent writer "
            f"threads ({expected} total)",
        )
    except Exception as exc:
        record("live event bus concurrency", False, f"{exc.__class__.__name__}: {exc}")

    # -- full engine run against the mock environment ---------------------- #
    result = None
    try:
        result = await _run_engine_check(dns_port, http_port)
        record(
            "full engine pipeline",
            result is not None
            and len(result.findings) >= 8
            and any(f.subdomain == TEST_DOMAIN and f.status == 200 for f in result.findings),
            (
                f"{len(result.findings)} finding(s), "
                f"{len(result.filtered)} filtered: "
                + ", ".join(f.url for f in result.findings[:4])
                + (" …" if len(result.findings) > 4 else "")
            )
            if result
            else "engine returned no result",
        )
    except Exception as exc:
        record("full engine pipeline", False, f"{exc.__class__.__name__}: {exc}")

    # -- report writers ----------------------------------------------------- #
    if result is not None:
        try:
            from ..reporters import write_reports

            target = Path(report_dir) if report_dir else Path(".subsonar_cache") / "selftest"
            written = write_reports(
                result, target, formats=("json", "csv", "md", "html", "txt")
            )
            sizes = {fmt: path.stat().st_size for fmt, path in written.items()}
            record(
                "report writers (json/csv/md/html/txt)",
                len(written) == 5 and all(size > 0 for size in sizes.values()),
                ", ".join(f"{fmt}:{size}B" for fmt, size in sizes.items()),
            )
        except Exception as exc:
            record(
                "report writers (json/csv/md/html/txt)",
                False,
                f"{exc.__class__.__name__}: {exc}",
            )

    if probe is not None:
        await probe.close()
    dns.stop()
    http.stop()

    passed = sum(1 for check in checks if check.ok)
    return {
        "tool": "subsonar",
        "selftest": True,
        "domain": TEST_DOMAIN,
        "mock_dns_port": dns_port,
        "mock_http_port": http_port,
        "total": len(checks),
        "passed": passed,
        "failed": len(checks) - passed,
        "duration": round(time.perf_counter() - started, 2),
        "checks": [check.to_dict() for check in checks],
    }


async def _run_engine_check(dns_port: int, http_port: int):
    """Run the real engine end-to-end against the loopback mocks."""
    import dataclasses

    from .engine import ScanEngine
    from .wordlist import WordlistManager, WordlistResult, parse_wordlist

    class _LocalWordlist(WordlistManager):
        """Uses the real parsing path but never touches the network."""

        async def acquire(self, **kwargs: Any):  # type: ignore[override]
            return None

        async def load(self, limit: int, **kwargs: Any):  # type: ignore[override]
            text = "\n".join(
                ["www", "api", "admin", "mail", "dev", "test", "portal", "vpn"]
            )
            words = parse_wordlist(text, limit=limit)
            return WordlistResult(
                words=words, source="selftest", from_cache=True, truncated_from=len(words)
            )

    config = ScanConfig(
        domain=TEST_DOMAIN,
        profile_id=2,
        resolver_pool=(f"{MOCK_IP}:{dns_port}",),
        dns_timeout=1.5,
        tcp_timeout=1.0,
        http_timeout=4.0,
        dns_concurrency=64,
        port_concurrency=64,
        http_concurrency=16,
        wildcard_filter=True,
    )
    config.ports = {http_port: "selftest-mock", 9001: "selftest-closed"}
    # Never mutate the shared profile registry — build a local copy instead.
    profile = dataclasses.replace(get_profile(2), wordlist_size=8)
    engine = ScanEngine(config, profile=profile, bus=EventBus())
    local_resolver = AnonymousResolver(
        servers=[f"{MOCK_IP}:{dns_port}"],
        timeout=1.5,
        concurrency=32,
        bus=engine.bus,
        verbose_queries=False,
    )
    engine._resolver = local_resolver
    engine._probe.resolver = local_resolver
    engine._wordlists = _LocalWordlist(cache_dir=Path(".subsonar_cache"), bus=engine.bus)
    engine._phase_osint = _null_osint(engine)  # type: ignore[assignment]
    # Real SAN harvesting and CNAME chasing need live TLS/DNS; disable just those
    # two so the pipeline check stays loopback-only.  Permutations stay enabled
    # (they are pure computation) with a small cap.
    config.permutation_limit = 40
    config.enable_san = False
    config.enable_cnames = False
    # Keep the self-test strictly loopback: no BGP dump download, no robots.txt
    # mining against the mock, no PTR lookups for mock addresses.
    config.geoip = False
    config.geoip_download = False
    config.reverse_dns = False
    config.web_mining = False
    return await engine.run()


def _null_osint(engine: Any) -> Any:
    async def _noop(add: Any) -> None:
        engine.bus.emit(
            "selftest — OSINT sources stubbed (no external traffic)",
            "debug",
            "osint",
        )

    return _noop


def main() -> int:
    report = asyncio.run(run_selftest(progress=print))
    print()
    print(f"{report['passed']}/{report['total']} checks passed in {report['duration']}s")
    return 0 if report["passed"] == report["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
