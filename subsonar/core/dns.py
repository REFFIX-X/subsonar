"""Anonymous asynchronous DNS engine.

Design notes
------------
``aiodns`` is used when available, but the primary path is a *self-contained*
asyncio UDP resolver implemented directly on top of the DNS wire protocol.  This
guarantees the privacy contract that ``aiodns``/``dnspython`` cannot always
give on Windows (libc/registry resolvers leak to the OS-configured servers):
every single packet is sent to a rotating member of
:data:`~subsonar.core.config.DNS_RESOLVER_POOL`, and Google/Cloudflare
addresses are hard-blocked at runtime.

Features
--------
* Round-robin over 18 privacy-focused resolvers, retry + fail-over per query.
* A / AAAA / CNAME / NS / MX / TXT query support with a full wire parser.
* TTL-aware LRU answer cache.
* Optional integration with the ``aiodns`` backend (kept behind a flag).
* Concurrency gated by an :class:`asyncio.Semaphore`.
* Wildcard-DNS detection with dynamic false-positive filtering.
* Reverse lookups (PTR) for IP attribution in the live log.
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import struct
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from .config import DNS_RESOLVER_POOL, FORBIDDEN_DNS_SERVERS
from .dnscache import CacheEntry, DNSCache
from .events import BUS, EventBus
from .ratelimit import RateLimiter

#: Name used to prove a resolver still answers recursive queries.
HEALTHCHECK_NAME = "example.com"

# --------------------------------------------------------------------------- #
# Wire constants
# --------------------------------------------------------------------------- #

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_DS = 43
TYPE_DNSKEY = 48
TYPE_CAA = 257

TYPE_NAMES = {
    TYPE_A: "A",
    TYPE_NS: "NS",
    TYPE_CNAME: "CNAME",
    TYPE_SOA: "SOA",
    TYPE_PTR: "PTR",
    TYPE_MX: "MX",
    TYPE_TXT: "TXT",
    TYPE_AAAA: "AAAA",
    TYPE_DS: "DS",
    TYPE_DNSKEY: "DNSKEY",
    TYPE_CAA: "CAA",
}

CLASS_IN = 1
FLAG_RD = 0x0100  # recursion desired
MAX_UDP_PAYLOAD = 4096


class DNSError(Exception):
    """Base class for DNS failures."""


class DNSTimeout(DNSError):
    """All resolvers in the rotation failed to answer in time."""


class DNSFormatError(DNSError):
    """The response could not be parsed."""


class DNSNxDomain(DNSError):
    """NXDOMAIN — the name definitively does not exist."""


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class DNSRecord:
    name: str
    rtype: int
    ttl: int
    value: str

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.rtype, str(self.rtype))


@dataclass(slots=True)
class DNSResult:
    """Aggregated answer for one hostname."""

    name: str
    addresses: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    records: list[DNSRecord] = field(default_factory=list)
    resolver: str | None = None
    rtt_ms: float = 0.0
    from_cache: bool = False
    error: str | None = None
    #: True when the resolver answered rcode 0 with an empty answer section:
    #: the name exists but has no address.  Distinct from NXDOMAIN and from a
    #: transport failure.  Set explicitly by the resolver, never inferred.
    noerror_empty: bool = False
    attempted_servers: list[str] = field(default_factory=list)
    #: How many independent resolvers agreed on this answer (confirmation mode).
    confirmed_by: int = 0
    #: Resolvers that returned a *different* address set.
    disagreements: list[str] = field(default_factory=list)
    #: True when the per-name time budget ran out before the failover attempts
    #: did — the answer is "unresolved", but for a time reason, not a DNS one.
    deadline_hit: bool = False

    @property
    def ok(self) -> bool:
        return bool(self.addresses) and self.error is None

    @property
    def empty_noerror(self) -> bool:
        """rcode 0 with an empty answer — the name exists but has no address."""
        return self.noerror_empty

    @property
    def ip(self) -> str | None:
        """Primary address (IPv4 preferred)."""
        for addr in self.addresses:
            if ":" not in addr:
                return addr
        return self.addresses[0] if self.addresses else None

    @property
    def canonical(self) -> str:
        return self.cnames[-1] if self.cnames else self.name


# --------------------------------------------------------------------------- #
# Wire encoding / decoding
# --------------------------------------------------------------------------- #


def _queued_note(queued_ms: float) -> str:
    """Suffix for a query log line when it waited on our own rate limiter.

    Kept separate from ``rtt_ms`` so the reported round-trip time stays an honest
    measure of the resolver: a 20 ms answer queued for 13 s is still a 20 ms
    resolver, and the log now says so explicitly.
    """
    return f", queued {queued_ms / 1000:.1f}s (rate limit)" if queued_ms >= 250 else ""


def encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if len(raw) > 63:
            raise DNSFormatError(f"label too long: {label!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def build_query(name: str, qtype: int, *, qid: int | None = None) -> tuple[bytes, int]:
    """Build a recursive DNS query packet.  Returns ``(packet, query_id)``."""
    query_id = qid if qid is not None else random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", query_id, FLAG_RD, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)
    return header + question, query_id


def _decode_name(packet: bytes, offset: int, *, depth: int = 0) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name starting at *offset*.

    Compression pointers may point *anywhere* in the packet, including back at
    themselves, so every pointer target is remembered: a loop (or a pointer that
    walks backwards forever) raises :class:`DNSFormatError` instead of spinning.
    A hostile or mangled response must never be able to hang the event loop.
    """
    if depth > 16:
        raise DNSFormatError("compression pointer loop")
    labels: list[str] = []
    cursor = offset
    jumped = False
    end = offset
    seen: set[int] = set()
    while True:
        if cursor >= len(packet):
            raise DNSFormatError("truncated name")
        if cursor in seen:
            raise DNSFormatError("compression pointer loop")
        seen.add(cursor)
        length = packet[cursor]
        if length == 0:
            cursor += 1
            if not jumped:
                end = cursor
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise DNSFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if not jumped:
                end = cursor + 2
            if pointer >= len(packet):
                raise DNSFormatError("compression pointer out of range")
            cursor = pointer
            jumped = True
            continue
        cursor += 1
        labels.append(packet[cursor : cursor + length].decode("latin-1"))
        cursor += length
        if not jumped:
            end = cursor
        if len(labels) > 128:
            raise DNSFormatError("too many labels in a single name")
    return ".".join(labels), end


def parse_response(packet: bytes, expected_id: int) -> tuple[list[DNSRecord], int]:
    """Parse a DNS response into records.  Returns ``(records, rcode)``."""
    if len(packet) < 12:
        raise DNSFormatError("response shorter than header")
    (qid, flags, qdcount, ancount, nscount, arcount) = struct.unpack("!HHHHHH", packet[:12])
    if qid != expected_id:
        raise DNSFormatError(f"transaction id mismatch ({qid} != {expected_id})")
    rcode = flags & 0x000F
    offset = 12
    for _ in range(qdcount):
        _, offset = _decode_name(packet, offset)
        offset += 4
    records: list[DNSRecord] = []
    for _ in range(ancount + nscount + arcount):
        name, offset = _decode_name(packet, offset)
        if offset + 10 > len(packet):
            raise DNSFormatError("truncated resource record")
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        rdata = packet[offset : offset + rdlength]
        if len(rdata) != rdlength:
            raise DNSFormatError("truncated rdata")
        offset += rdlength
        value = _decode_rdata(packet, offset - rdlength, rdlength, rtype, rdata)
        if value is not None:
            records.append(DNSRecord(name=name, rtype=rtype, ttl=ttl, value=value))
    return records, rcode


def _decode_rdata(
    packet: bytes, rdata_offset: int, rdlength: int, rtype: int, rdata: bytes
) -> str | None:
    if rtype == TYPE_A and rdlength == 4:
        return str(ipaddress.IPv4Address(rdata))
    if rtype == TYPE_AAAA and rdlength == 16:
        return str(ipaddress.IPv6Address(rdata))
    if rtype in (TYPE_CNAME, TYPE_NS, TYPE_PTR):
        try:
            value, _ = _decode_name(packet, rdata_offset)
            return value
        except DNSFormatError:
            return None
    if rtype == TYPE_MX:
        if rdlength < 3:
            return None
        preference = struct.unpack("!H", rdata[:2])[0]
        try:
            exchange, _ = _decode_name(packet, rdata_offset + 2)
        except DNSFormatError:
            return None
        return f"{preference} {exchange}"
    if rtype == TYPE_TXT:
        parts: list[str] = []
        cursor = 0
        while cursor < len(rdata):
            length = rdata[cursor]
            cursor += 1
            parts.append(rdata[cursor : cursor + length].decode("latin-1", "replace"))
            cursor += length
        return "".join(parts)
    if rtype == TYPE_SOA:
        try:
            primary, after = _decode_name(packet, rdata_offset)
            mailbox, after = _decode_name(packet, after)
        except DNSFormatError:
            return None
        relative = after - rdata_offset
        if rdlength >= relative + 20:
            serial = struct.unpack("!I", rdata[relative : relative + 4])[0]
            return f"{primary} {mailbox} {serial}"
        return f"{primary} {mailbox}"
    if rtype == TYPE_DS and rdlength >= 5:
        key_tag, algorithm, digest_type = struct.unpack("!HBB", rdata[:4])
        return f"{key_tag} {algorithm} {digest_type} {rdata[4:].hex()}"
    if rtype == TYPE_DNSKEY and rdlength >= 5:
        flags, protocol, algorithm = struct.unpack("!HBB", rdata[:4])
        return f"{flags} {protocol} {algorithm} {rdata[4:].hex()[:64]}"
    if rtype == TYPE_CAA and rdlength >= 2:
        tag_length = rdata[1]
        if rdlength < 2 + tag_length:
            return None
        tag = rdata[2 : 2 + tag_length].decode("latin-1", "replace")
        value = rdata[2 + tag_length :].decode("latin-1", "replace")
        return f"{rdata[0]} {tag} {value}"
    return None


# --------------------------------------------------------------------------- #
# Multiplexed UDP transport
# --------------------------------------------------------------------------- #


class DNSConnection:
    """One long-lived UDP socket per resolver, multiplexing many queries.

    Creating a socket per query measured ~215 µs p50 (373 µs p95) of pure setup
    and teardown.  This class keeps the socket open and matches responses to
    requests by DNS transaction ID, so the per-query cost collapses to a
    dictionary insert plus a future.

    Transaction IDs are allocated uniquely per connection; if the 16-bit space
    is ever exhausted the caller simply gets a fresh connection, so a collision
    can never mis-attribute an answer.
    """

    def __init__(
        self,
        server: str,
        *,
        timeout: float = 2.5,
        on_unhealthy: Any = None,
    ) -> None:
        self.server = server
        self.timeout = timeout
        self.on_unhealthy = on_unhealthy
        self._transport: asyncio.DatagramTransport | None = None
        self._pending: dict[int, asyncio.Future[bytes]] = {}
        #: Free transaction IDs.  A ``set`` keeps ``in``/discard O(1) — a list
        #: made every query scan ~65 k entries, twice.
        self._free_ids: set[int] = set(range(1, 0xFFFF))
        self._connecting: asyncio.Future[None] | None = None
        self._lock = asyncio.Lock()
        self.sent = 0
        self.received = 0
        self.mismatched = 0
        self.timeouts = 0
        self.osprev = 0

    # -- lifecycle --------------------------------------------------------- #
    async def _ensure_transport(self) -> asyncio.DatagramTransport:
        if self._transport is not None and not self._transport.is_closing():
            return self._transport
        async with self._lock:
            if self._transport is not None and not self._transport.is_closing():
                return self._transport
            loop = asyncio.get_running_loop()
            host, port = AnonymousResolver._split_server(self.server)
            connection = self

            class _Protocol(asyncio.DatagramProtocol):
                def datagram_received(self, data: bytes, addr: Any) -> None:
                    connection._dispatch(data)

                def error_received(self, exc: Exception) -> None:
                    connection._fail_all(exc)

                def connection_lost(self, exc: Exception | None) -> None:
                    connection._transport = None

            transport, _ = await loop.create_datagram_endpoint(
                _Protocol, remote_addr=(host, port)
            )
            self._transport = transport  # type: ignore[assignment]
            return self._transport

    def _dispatch(self, data: bytes) -> None:
        self.received += 1
        if len(data) < 2:
            return
        qid = int.from_bytes(data[:2], "big")
        future = self._pending.pop(qid, None)
        if future is None or future.done():
            self.mismatched += 1
            return
        self._free_ids.add(qid)
        future.set_result(data)

    def _fail_all(self, exc: Exception) -> None:
        for future in list(self._pending.values()):
            if not future.done():
                future.set_exception(exc)
        self._pending.clear()

    def close(self) -> None:
        self._fail_all(ConnectionError("resolver connection closed"))
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception:
                pass
        self._transport = None

    # -- query ------------------------------------------------------------- #
    async def query(self, packet: bytes, qid: int, *, timeout: float | None = None) -> bytes:
        """Send *packet* and await the response carrying *qid*."""
        transport = await self._ensure_transport()
        if qid not in self._free_ids:
            raise DNSError(f"transaction id {qid} is already in flight")
        self._free_ids.discard(qid)

        loop = asyncio.get_running_loop()
        future: asyncio.Future[bytes] = loop.create_future()
        self._pending[qid] = future
        self.sent += 1
        try:
            transport.sendto(packet)
            return await asyncio.wait_for(
                future, timeout=timeout or self.timeout
            )
        except asyncio.TimeoutError:
            self.timeouts += 1
            if self.on_unhealthy is not None:
                try:
                    self.on_unhealthy(self.server)
                except Exception:
                    pass
            raise DNSTimeout(
                f"no response from {self.server} within "
                f"{timeout or self.timeout:.1f}s"
            )
        finally:
            self._pending.pop(qid, None)
            self._free_ids.add(qid)

    @property
    def in_flight(self) -> int:
        return len(self._pending)


class DNSConnectionPool:
    """Keeps a small set of multiplexed connections per resolver."""

    def __init__(
        self,
        *,
        max_per_server: int = 4,
        on_unhealthy: Any = None,
    ) -> None:
        self.max_per_server = max(1, max_per_server)
        self.on_unhealthy = on_unhealthy
        self._pool: dict[str, list[DNSConnection]] = {}
        self._rr: dict[str, int] = {}
        self._lock = asyncio.Lock()
        self.created = 0

    async def acquire(self, server: str, timeout: float) -> DNSConnection:
        """Hand out a connection for *server*.

        An idle connection is reused; the pool only grows (up to
        ``max_per_server``) when every existing connection is already busy.  That
        keeps a small serial scan on a single socket while still allowing large
        concurrent fan-out.
        """
        async with self._lock:
            connections = self._pool.setdefault(server, [])
            start = self._rr.get(server, 0)
            for offset in range(len(connections)):
                index = (start + offset) % len(connections)
                candidate = connections[index]
                if candidate.in_flight == 0:
                    self._rr[server] = (index + 1) % len(connections)
                    return candidate
            if len(connections) < self.max_per_server:
                connection = DNSConnection(
                    server, timeout=timeout, on_unhealthy=self.on_unhealthy
                )
                connections.append(connection)
                self.created += 1
                self._rr[server] = 0
                return connection
            # All busy and the pool is full: use the least loaded one.
            best_index = start % len(connections)
            best_in_flight = connections[best_index].in_flight
            for offset in range(1, len(connections)):
                index = (start + offset) % len(connections)
                if connections[index].in_flight < best_in_flight:
                    best_index, best_in_flight = index, connections[index].in_flight
            self._rr[server] = (best_index + 1) % len(connections)
            return connections[best_index]

    def close(self) -> None:
        for connections in self._pool.values():
            for connection in connections:
                connection.close()
        self._pool.clear()

    def stats(self) -> dict[str, Any]:
        total_sent = sum(
            c.sent for connections in self._pool.values() for c in connections
        )
        total_timeouts = sum(
            c.timeouts for connections in self._pool.values() for c in connections
        )
        return {
            "servers": len(self._pool),
            "connections": self.created,
            "queries": total_sent,
            "timeouts": total_timeouts,
        }


# --------------------------------------------------------------------------- #
# Resolver
# --------------------------------------------------------------------------- #


#: Fraction of the per-attempt timeout used for *failover* attempts (the first
#: attempt always gets the full timeout).  A healthy privacy resolver answers in
#: tens of milliseconds, so a node that has been silent for 0.75 s is not going to
#: answer this name either: handing the remaining budget to *more* nodes catches
#: far more hosts than waiting out one slow node six times.
RETRY_TIMEOUT_FACTOR = 0.3


class AnonymousResolver:
    """Async DNS resolver pinned to an anonymous, rotating resolver pool."""

    def __init__(
        self,
        *,
        servers: Sequence[str] = DNS_RESOLVER_POOL,
        timeout: float = 2.5,
        retries: int = 2,
        concurrency: int = 400,
        cache_size: int = 4096,
        default_ttl: int = 300,
        bus: EventBus | None = None,
        verbose_queries: bool = True,
        multiplex: bool = True,
        disk_cache: "DNSCache | None" = None,
        disk_cache_enabled: bool = True,
        rate_limit: float = 0.0,
        rate_burst: float | None = None,
        rate_per_server: float = 0.0,
        name_deadline: float = 6.0,
    ) -> None:
        servers = tuple(s for s in servers if s not in FORBIDDEN_DNS_SERVERS)
        if not servers:
            raise RuntimeError(
                "AnonymousResolver requires at least one privacy resolver "
                "(Google/Cloudflare are hard-blocked)"
            )
        self.servers = servers
        self.timeout = timeout
        self.retries = max(1, retries)
        self.bus = bus or BUS
        self.verbose_queries = verbose_queries
        self._semaphore = asyncio.Semaphore(concurrency)
        #: Query pacing — concurrency bounds in-flight queries, this bounds the
        #: rate (queries/second) that actually leaves the machine.
        self.rate_limit = max(0.0, float(rate_limit))
        self.limiter = RateLimiter(
            self.rate_limit,
            burst=rate_burst,
            per_server_rate=rate_per_server,
        )
        self.rate_waits = 0
        self.rate_wait_seconds = 0.0
        #: Wall-clock budget for one hostname across all its failover attempts.
        #: The attempt budget alone allowed ``attempts × timeout`` (6 × 2.5 s =
        #: 15 s) for a single dead name — with a 5 000-label wordlist made of
        #: mostly-NXDOMAIN names that, not the rate limit, becomes the bottleneck.
        #: ``0`` restores the old "as many attempts as it takes" behaviour.
        self.name_deadline = max(0.0, float(name_deadline))
        self.deadline_aborts = 0
        self._cache: OrderedDict[tuple[str, int], tuple[float, DNSResult]] = OrderedDict()
        self._cache_size = cache_size
        self._default_ttl = default_ttl
        self._cursor = random.randrange(len(self.servers))
        self._lock = asyncio.Lock()
        self.queries_sent = 0
        self.answers_received = 0
        #: Servers observed to answer; every candidate is tried until one does.
        self._healthy: set[str] | None = None
        self._health_task: asyncio.Task[None] | None = None
        self.health_report: dict[str, str | None] = {}
        self.health_checked_at: float = 0.0
        #: Multiplexed UDP transport (one socket per resolver, many queries).
        self.multiplex = multiplex
        self._pool: DNSConnectionPool = DNSConnectionPool(
            on_unhealthy=self._mark_unhealthy
        )
        #: Durable answer cache so repeat scans do not re-query the same names.
        if disk_cache is None and disk_cache_enabled:
            disk_cache = DNSCache()
        self.disk_cache = disk_cache
        self.disk_cache_hits = 0

    def _mark_unhealthy(self, server: str) -> None:
        if self._healthy is not None:
            self._healthy.discard(server)

    # -- health ----------------------------------------------------------- #
    @property
    def live_servers(self) -> tuple[str, ...]:
        """Servers currently believed to be answering (falls back to all)."""
        if not self._healthy:
            return self.servers
        live = tuple(s for s in self.servers if s in self._healthy)
        return live or self.servers

    async def health_check(
        self,
        *,
        timeout: float = 2.0,
        concurrency: int = 32,
        log: bool = True,
    ) -> dict[str, str | None]:
        """Probe every resolver in the pool and record who actually answers.

        Public resolver pools drift: nodes get retired, move to DoT/DoH, or block
        plain UDP/53 from a given network.  Probing up-front keeps the rotation
        fast and keeps the live log honest about which nodes were used.
        """
        semaphore = asyncio.Semaphore(concurrency)
        original_timeout = self.timeout

        async def probe(server: str) -> tuple[str, str | None]:
            async with semaphore:
                try:
                    packet, qid = build_query(HEALTHCHECK_NAME, TYPE_A)
                    raw = await asyncio.wait_for(
                        self._exchange(packet, server, qid), timeout=timeout
                    )
                    records, rcode = parse_response(raw, qid)
                    if rcode in (0, 3):
                        return server, None
                    return server, f"rcode={rcode}"
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    return server, f"{exc.__class__.__name__}"

        try:
            pairs = await asyncio.gather(*(probe(server) for server in self.servers))
        finally:
            self.timeout = original_timeout

        self.health_report = {server: error for server, error in pairs}
        self._healthy = {server for server, error in pairs if error is None}
        self.health_checked_at = time.time()
        if log and self.bus is not None:
            live = sorted(self._healthy)
            dead = sorted(set(self.servers) - self._healthy)
            self.bus.emit(
                f"Resolver health check — {len(live)}/{len(self.servers)} anonymous "
                f"nodes answering UDP/53",
                "success" if live else "warn",
                "dns",
                live=len(live),
                dead=len(dead),
            )
            if dead:
                self.bus.emit(
                    "Unreachable nodes skipped this session: "
                    + ", ".join(f"{node} ({self.health_report.get(node)})" for node in dead),
                    "debug",
                    "dns",
                )
            if live:
                self.bus.emit(
                    "Active rotation: " + ", ".join(live),
                    "debug",
                    "dns",
                )
        return self.health_report

    async def start_health_loop(self, *, interval: float = 600.0, timeout: float = 2.0) -> None:
        """Re-probe the pool periodically for long scans."""

        async def loop() -> None:
            while True:
                await asyncio.sleep(interval)
                await self.health_check(timeout=timeout, log=False)

        if self._health_task is None or self._health_task.done():
            self._health_task = asyncio.create_task(loop())

    def stop_health_loop(self) -> None:
        if self._health_task is not None and not self._health_task.done():
            self._health_task.cancel()
        self._health_task = None

    # -- pool management -------------------------------------------------- #
    def next_server(self) -> str:
        """Round-robin the resolver pool, skipping known-dead nodes."""
        candidates = self.live_servers
        self._cursor = (self._cursor + 1) % len(candidates)
        return candidates[self._cursor]

    def server_attempt_order(self, count: int | None = None) -> list[str]:
        """Distinct resolvers to try for a single query, healthiest first."""
        pool = list(self.live_servers)
        random.shuffle(pool)
        if count is not None:
            pool = pool[:count]
        return pool

    def rotation(self, count: int | None = None) -> list[str]:
        """The exact resolver rotation this scan will use (for display)."""
        count = count or len(self.servers)
        return [self.servers[(self._cursor + 1 + i) % len(self.servers)] for i in range(count)]

    # -- cache ------------------------------------------------------------ #
    def _cache_get(self, key: tuple[str, int]) -> DNSResult | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        expires, result = entry
        if expires < time.time():
            self._cache.pop(key, None)
            return None
        self._cache.move_to_end(key)
        cached = DNSResult(
            name=result.name,
            addresses=list(result.addresses),
            cnames=list(result.cnames),
            records=list(result.records),
            resolver=result.resolver,
            rtt_ms=result.rtt_ms,
            from_cache=True,
            error=result.error,
        )
        return cached

    def _cache_put(self, key: tuple[str, int], result: DNSResult, ttl: int | None = None) -> None:
        ttl = ttl if ttl and ttl > 0 else self._default_ttl
        self._cache[key] = (time.time() + min(ttl, 3600), result)
        self._cache.move_to_end(key)
        while len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)

    def cache_clear(self) -> None:
        self._cache.clear()

    # -- low level -------------------------------------------------------- #
    @staticmethod
    def _split_server(server: str) -> tuple[str, int]:
        """Split ``host[:port]`` resolver entries (default port 53)."""
        if ":" in server and not server.startswith("["):
            host, _, raw_port = server.partition(":")
            if raw_port.isdigit():
                return host, int(raw_port)
        return server, 53

    async def _exchange(
        self,
        packet: bytes,
        server: str,
        expected_id: int,
        *,
        timeout: float | None = None,
    ) -> bytes:
        """Send one UDP query and await its response.

        With :attr:`multiplex` enabled the packet goes out over a shared,
        long-lived socket (one per resolver) and responses are matched by
        transaction ID; otherwise a throwaway socket is used per query.

        *timeout* overrides :attr:`timeout` for this one exchange — used by the
        failover loop so a retry can never outlive the per-name budget.
        """
        budget = self.timeout if timeout is None else max(0.2, timeout)
        if self.multiplex:
            connection = await self._pool.acquire(server, budget)
            self.queries_sent += 1
            data = await connection.query(packet, expected_id)
            self.answers_received += 1
            return data

        loop = asyncio.get_running_loop()
        host, port = self._split_server(server)
        transport = None
        try:
            on_response: asyncio.Future[bytes] = loop.create_future()

            class _Protocol(asyncio.DatagramProtocol):
                def datagram_received(self, data: bytes, addr: Any) -> None:  # noqa: D401
                    if not on_response.done():
                        on_response.set_result(data)

                def error_received(self, exc: Exception) -> None:  # noqa: D401
                    if not on_response.done():
                        on_response.set_exception(exc)

            transport, _ = await loop.create_datagram_endpoint(
                _Protocol, remote_addr=(host, port)
            )
            self.queries_sent += 1
            transport.sendto(packet)
            try:
                data = await asyncio.wait_for(on_response, timeout=budget)
            except asyncio.TimeoutError as exc:
                raise DNSTimeout(
                    f"no response from {server} within {budget:.1f}s"
                ) from exc
            self.answers_received += 1
            return data
        finally:
            if transport is not None:
                transport.close()

    async def query_raw(
        self,
        name: str,
        qtype: int = TYPE_A,
        *,
        use_cache: bool = True,
        log: bool = True,
        server: str | None = None,
    ) -> DNSResult:
        """Resolve *name* for *qtype* through the anonymous pool.

        *server* pins the query to exactly that resolver (one attempt, no
        rotation) — used by the multi-resolver confirmation path, where asking
        the rotating pool would defeat the point.  Callers that pin a server
        should also pass ``use_cache=False`` so one node's answer is neither read
        from nor written to the shared cache.
        """
        name = name.strip().lower().rstrip(".")
        key = (name, qtype)
        if use_cache:
            cached = self._cache_get(key)
            if cached is not None:
                return cached
            # Durable cache: repeat scans of the same domain are almost entirely
            # redundant (the same NXDOMAINs over and over), so a disk hit removes
            # both the packet and the latency.
            disk = await self._disk_cache_get(name, qtype)
            if disk is not None:
                result = DNSResult(
                    name=name,
                    addresses=list(disk.addresses),
                    cnames=list(disk.cnames),
                    error=disk.error,
                    resolver=disk.resolver,
                    rtt_ms=disk.rtt_ms,
                    from_cache=True,
                )
                result.attempted_servers = ["disk-cache"]
                self.disk_cache_hits += 1
                self.bus.bump("dns_cache_hits")
                self._cache_put(key, result, ttl=60)
                if log and self.verbose_queries:
                    self.bus.emit(
                        f"Disk cache hit for ://{name} "
                        f"({' → '.join(disk.addresses) if disk.addresses else disk.error or 'empty'})",
                        "debug",
                        "dns",
                        host=name,
                    )
                return result

        result = DNSResult(name=name)
        attempted: list[str] = []
        # Never retry the same node twice in a row: build an ordered list of
        # distinct resolvers (degraded nodes are dropped by the health check).
        # The attempt budget scales with the live pool so a name that several
        # nodes refuse is still given every other node a chance.
        if server is not None:
            # Pinned node (the resolver-confirmation path): exactly one attempt,
            # no rotation — the answer must be that node's own answer.
            order = [server]
            attempts = 1
        else:
            live_count = len(self.live_servers)
            attempts = max(self.retries, min(6, max(2, live_count // 2)))
            order = self.server_attempt_order(live_count)
            while len(order) < attempts:
                order.extend(self.server_attempt_order(attempts))
        # Walk away from a name rather than spending the whole attempt budget on
        # it: dead names are the majority of any brute list, so a per-name budget
        # is what keeps the DNS phase near the rate limit instead of the timeout.
        deadline = (
            time.perf_counter() + self.name_deadline if self.name_deadline > 0 else None
        )
        deadline_hit = False
        async with self._semaphore:
            # Attempt budget: the configured retries, but never fewer than half
            # the live pool nor more than the whole pool twice over.  A name that
            # a few nodes refuse is therefore still offered to every other node.
            attempt_index = 0
            while attempt_index < attempts:
                if deadline is not None and time.perf_counter() >= deadline:
                    deadline_hit = True
                    self.deadline_aborts += 1
                    if log and self.verbose_queries:
                        self.bus.dns(
                            f"Giving up on ://{name} after "
                            f"{attempt_index - 1} failover attempt(s) — "
                            f"{self.name_deadline:.1f}s budget exhausted",
                            host=name,
                        )
                    break
                node = (
                    order[attempt_index]
                    if attempt_index < len(order)
                    else self.next_server()
                )
                attempt_index += 1
                if len(attempted) >= max(attempts, len(self.live_servers)) * 2:
                    break
                attempted.append(node)
                # Pace first, then time the exchange: ``rtt_ms`` must measure the
                # resolver, not the time a query spent queued behind our own rate
                # limiter (which made a 20 ms answer look like a 13 s one).
                queued_ms = 0.0
                if self.limiter.enabled:
                    waited = await self.limiter.acquire(node)
                    if waited > 0:
                        self.rate_waits += 1
                        self.rate_wait_seconds += waited
                        queued_ms = waited * 1000
                started = time.perf_counter()
                try:
                    packet, qid = build_query(name, qtype)
                    if log and self.verbose_queries:
                        self.bus.dns(
                            f"DNS Request ({TYPE_NAMES.get(qtype, qtype)}) sent to "
                            f"[{node}] for ://{name}",
                            host=name,
                            ip=node,
                            qtype=TYPE_NAMES.get(qtype, str(qtype)),
                            transport="udp/53",
                        )
                    # Failover attempts use a shorter timeout; the first attempt
                    # always gets the full one.  Never longer than the normal
                    # timeout, even for a tiny configured value.
                    retry_timeout = min(
                        self.timeout, max(0.15, self.timeout * RETRY_TIMEOUT_FACTOR)
                    )
                    tried = self.timeout if attempt_index == 1 else retry_timeout
                    if deadline is not None:
                        remaining = deadline - time.perf_counter()
                        if remaining <= 0:
                            deadline_hit = True
                            self.deadline_aborts += 1
                            break
                        tried = min(tried, remaining)
                    if tried == self.timeout:
                        raw = await self._exchange(packet, node, qid)
                    else:
                        raw = await self._exchange(packet, node, qid, timeout=tried)
                    records, rcode = parse_response(raw, qid)
                    result.rtt_ms = (time.perf_counter() - started) * 1000
                    result.resolver = node
                    if rcode == 3:  # NXDOMAIN
                        result.error = "NXDOMAIN"
                        if log and self.verbose_queries:
                            self.bus.dns(
                                f"NXDOMAIN from [{node}] for ://{name} "
                                f"({result.rtt_ms:.0f} ms)"
                                + self._queued_note(queued_ms),
                                host=name,
                                ip=node,
                            )
                        if use_cache:
                            self._cache_put(key, result, ttl=60)
                            await self._disk_cache_put(name, qtype, result)
                        return result
                    if rcode != 0:
                        raise DNSError(f"resolver returned rcode={rcode}")
                    self._apply_records(result, records, qtype)
                    if result.addresses or result.cnames:
                        # A working answer clears any error left behind by an
                        # earlier node that timed out or refused: trying the next
                        # resolver is failover, not failure.  Leaving the stale
                        # error set made ``result.ok`` False for a host that had
                        # just been resolved — the engine then dropped it as
                        # unresolved and never cached it.
                        result.error = None
                        result.noerror_empty = False
                    if not result.addresses and not result.cnames:
                        # rcode 0 with an empty answer section: the zone answered
                        # authoritatively and the name simply has no address.
                        # Recorded explicitly so the engine can report it
                        # distinctly from NXDOMAIN and from a transport failure.
                        result.noerror_empty = True
                        result.error = "NOERROR/empty"
                        if log and self.verbose_queries:
                            self.bus.dns(
                                f"NOERROR/empty from [{node}] for ://{name} — "
                                f"the name exists but has no A record",
                                host=name,
                                ip=node,
                            )
                        if use_cache:
                            self._cache_put(key, result, ttl=120)
                            await self._disk_cache_put(name, qtype, result)
                        return result
                    if self._healthy is not None and node not in self._healthy and result.ok:
                        self._healthy.add(node)
                    break
                except (DNSTimeout, DNSFormatError, DNSError, OSError) as exc:
                    result.error = str(exc)
                    if self._healthy is not None and exc.__class__ is DNSTimeout:
                        # Mark unresponsive nodes so later queries skip them.
                        self._healthy.discard(node)
                    if log and self.verbose_queries:
                        self.bus.dns(
                            f"Resolver [{node}] failed for ://{name} — {exc} "
                            f"(attempt {attempt_index}/{attempts})",
                            host=name,
                            ip=node,
                        )
                    await asyncio.sleep(0.05 * attempt_index)
                except asyncio.CancelledError:
                    raise
        result.attempted_servers = attempted
        result.deadline_hit = deadline_hit
        if use_cache and result.ok:
            ttl = min((r.ttl for r in result.records if r.ttl), default=self._default_ttl)
            self._cache_put(key, result, ttl=ttl)
            await self._disk_cache_put(name, qtype, result, ttl=ttl)
        return result

    # -- disk cache -------------------------------------------------------- #
    async def _disk_cache_get(self, name: str, qtype: int) -> "CacheEntry | None":
        if self.disk_cache is None or not self.disk_cache.ready:
            return None
        return await self.disk_cache.aget(name, TYPE_NAMES.get(qtype, str(qtype)))

    async def _disk_cache_put(
        self, name: str, qtype: int, result: DNSResult, *, ttl: int | None = None
    ) -> None:
        if self.disk_cache is None or not self.disk_cache.ready:
            return
        # Only cache definitive outcomes: a success, or an authoritative
        # NXDOMAIN/empty answer.  Transport failures are transient and must not
        # be memorised for long.
        if result.ok:
            await self.disk_cache.aput(
                name,
                TYPE_NAMES.get(qtype, str(qtype)),
                addresses=result.addresses,
                cnames=result.cnames,
                resolver=result.resolver,
                rtt_ms=result.rtt_ms,
                ttl=ttl or self.disk_cache.positive_ttl,
            )
        elif result.error in ("NXDOMAIN", "no records", "NOERROR/empty"):
            await self.disk_cache.aput(
                name,
                TYPE_NAMES.get(qtype, str(qtype)),
                error=result.error,
                resolver=result.resolver,
                ttl=self.disk_cache.negative_ttl,
            )

    @staticmethod
    def _owner(name: str) -> str:
        return name.strip().lower().rstrip(".")

    @classmethod
    def _apply_records(cls, result: DNSResult, records: list[DNSRecord], qtype: int) -> None:
        """Collect answers **for the queried name only**.

        A response may legally carry records for other names: the rest of the
        CNAME chain (wanted) but also authority/additional-section glue for
        unrelated names (not wanted).  Attributing glue to the queried host
        invents addresses that were never resolved, so a record is only accepted
        when its owner is the query name or a name reached through that name's
        CNAME chain.
        """
        wanted = {cls._owner(result.name)}
        for _ in range(8):  # follow CNAME indirection, in any record order
            grew = False
            for record in records:
                if record.rtype != TYPE_CNAME:
                    continue
                if cls._owner(record.name) in wanted:
                    target = cls._owner(record.value)
                    if target and target not in wanted:
                        wanted.add(target)
                        grew = True
            if not grew:
                break
        for record in records:
            if cls._owner(record.name) not in wanted:
                continue
            result.records.append(record)
            if record.rtype == TYPE_A or record.rtype == TYPE_AAAA:
                if record.value not in result.addresses:
                    result.addresses.append(record.value)
            elif record.rtype == TYPE_CNAME:
                target = cls._owner(record.value)
                if target and target not in result.cnames:
                    result.cnames.append(target)
        if not result.addresses and qtype in (TYPE_A, TYPE_AAAA):
            result.error = result.error or "no records"

    # -- high level ------------------------------------------------------- #
    async def resolve(
        self,
        name: str,
        *,
        log: bool = True,
        ipv6: bool = False,
        server: str | None = None,
        use_cache: bool = True,
    ) -> DNSResult:
        """Resolve A records (plus CNAME chain) for *name*.

        *server* pins every query of this resolution (including the CNAME
        follow-up) to one resolver — see :meth:`query_raw`.
        """
        result = await self.query_raw(
            name,
            TYPE_A if not ipv6 else TYPE_AAAA,
            log=log,
            server=server,
            use_cache=use_cache,
        )
        if not result.records:
            # Preserve the NOERROR/empty classification: an empty answer is a
            # definitive result, not a failure, and must not be relabelled here.
            if result.noerror_empty:
                result.error = "NOERROR/empty"
            return result
        # Follow the CNAME chain one hop when the answer is empty but aliased.
        hops = 0
        while result.cnames and not result.addresses and hops < 4:
            hops += 1
            target = result.cnames[-1]
            follow = await self.query_raw(
                target, TYPE_A, log=log, server=server, use_cache=use_cache
            )
            for addr in follow.addresses:
                if addr not in result.addresses:
                    result.addresses.append(addr)
            for cname in follow.cnames:
                if cname not in result.cnames:
                    result.cnames.append(cname)
            if follow.error and not result.error:
                result.error = follow.error
        return result

    async def resolve_many(
        self,
        names: Iterable[str],
        *,
        log: bool = False,
        on_result: Any = None,
        chunk: int = 200,
    ) -> list[DNSResult]:
        """Resolve many names concurrently, optionally streaming results."""
        names = list(names)
        results: list[DNSResult] = []
        pending: list[asyncio.Task[DNSResult]] = []
        for start in range(0, len(names), chunk):
            batch = names[start : start + chunk]
            pending = [asyncio.create_task(self.resolve(n, log=log)) for n in batch]
            for task in asyncio.as_completed(pending):
                try:
                    res = await task
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # pragma: no cover - defensive
                    res = DNSResult(name="?", error=str(exc))
                results.append(res)
                if on_result is not None:
                    await _maybe_await(on_result(res))
        return results

    async def reverse(self, ip: str, *, log: bool = False) -> str | None:
        """PTR lookup — used to attribute IPs in the live log."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version == 4:
            ptr = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        else:
            ptr = ".".join(reversed(addr.exploded.replace(":", ""))) + ".ip6.arpa"
        result = await self.query_raw(ptr, TYPE_PTR, log=log)
        for record in result.records:
            if record.rtype == TYPE_PTR:
                return record.value
        return None

    async def txt(self, name: str, *, log: bool = False) -> list[str]:
        result = await self.query_raw(name, TYPE_TXT, log=log)
        return [r.value for r in result.records if r.rtype == TYPE_TXT]

    # -- wildcard detection ---------------------------------------------- #
    async def detect_wildcard(
        self,
        domain: str,
        *,
        samples: int = 3,
        probe: Any = None,
    ) -> "WildcardReport":
        """Detect wildcard DNS for *domain* using randomised non-existent labels.

        When *probe* is supplied (an async callable ``(host) -> str | None``
        returning an HTTP fingerprint) the check is repeated at the HTTP layer
        so wildcard web servers are caught too.
        """
        tokens = "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(12))
        report = WildcardReport(domain=domain)
        names = [f"{tokens}-{i}.{domain}" for i in range(samples)]
        results = await self.resolve_many(names, log=False)
        for res in results:
            if res.ok:
                report.wildcard = True
                for addr in res.addresses:
                    report.ips.add(addr)
        if report.wildcard:
            self.bus.wildcard(
                f"Wildcard DNS detected for {domain} — "
                f"{len(report.ips)} rotating address(es): {', '.join(sorted(report.ips))}",
                host=domain,
            )
            if probe is not None:
                fingerprints = set()
                for name in names[:2]:
                    try:
                        fp = await probe(name)
                    except Exception:  # pragma: no cover - defensive
                        fp = None
                    if fp:
                        fingerprints.add(str(fp))
                report.http_fingerprints = fingerprints
                if fingerprints:
                    self.bus.wildcard(
                        f"Wildcard HTTP responder detected for {domain} — "
                        f"filtering signature(s): {', '.join(sorted(fingerprints))}",
                        host=domain,
                    )
        return report

    def close(self) -> None:
        self._cache.clear()
        self._pool.close()
        if self.disk_cache is not None:
            self.disk_cache.close()

    async def flush_disk_cache(self) -> None:
        """Drain the write-behind disk-cache buffer (called at scan end)."""
        cache = self.disk_cache
        if cache is None:
            return
        flush = getattr(cache, "flush", None)
        if flush is not None:
            try:
                await flush()
            except Exception:  # pragma: no cover - best effort
                pass

    def transport_stats(self) -> dict[str, Any]:
        stats = self._pool.stats()
        stats["multiplexed"] = self.multiplex
        stats["disk_cache_hits"] = self.disk_cache_hits
        stats["rate_limit"] = self.limiter.stats()
        stats["rate_waits"] = self.rate_waits
        stats["rate_wait_seconds"] = round(self.rate_wait_seconds, 3)
        if self.disk_cache is not None:
            stats["disk_cache"] = self.disk_cache.stats()
        return stats


@dataclass
class WildcardReport:
    """Outcome of a wildcard-DNS probe."""

    domain: str
    wildcard: bool = False
    ips: set[str] = field(default_factory=set)
    http_fingerprints: set[str] = field(default_factory=set)

    def is_false_positive(self, addresses: Iterable[str]) -> bool:
        """True when every resolved address matches the wildcard answer."""
        addresses = list(addresses)
        if not self.wildcard or not addresses or not self.ips:
            return False
        return all(addr in self.ips for addr in addresses)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "wildcard": self.wildcard,
            "ips": sorted(self.ips),
            "http_fingerprints": sorted(self.http_fingerprints),
        }


async def _maybe_await(value: Any) -> Any:
    if asyncio.iscoroutine(value) or isinstance(value, asyncio.Future):
        return await value
    return value
