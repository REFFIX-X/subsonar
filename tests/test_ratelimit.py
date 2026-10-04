"""DNS rate limiting: token bucketing, per-resolver caps, resolver integration.

The clock is injected everywhere so the tests are deterministic and instant.
"""

from __future__ import annotations

import time

import pytest

from subsonar.core.config import ScanConfig
from subsonar.core.dns import AnonymousResolver, DNSTimeout, build_query
from subsonar.core.profiles import PROFILES, apply_profile, get_profile
from subsonar.core.ratelimit import RateLimiter, RateLimiterGroup, TokenBucket


class FakeClock:
    """Monotonic clock that only moves when the test says so."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# --------------------------------------------------------------------------- #
# TokenBucket
# --------------------------------------------------------------------------- #


def test_disabled_bucket_never_waits() -> None:
    bucket = TokenBucket(0, clock=FakeClock())
    assert bucket.enabled is False
    for _ in range(1000):
        assert bucket.try_acquire() is True
    assert bucket.acquired == 1000
    assert bucket.waits == 0


def test_burst_is_allowed_then_tokens_refill() -> None:
    clock = FakeClock()
    bucket = TokenBucket(10, 5, clock=clock)
    assert bucket.burst == 5
    # The first burst comes straight out of the initial full bucket.
    assert [bucket.try_acquire() for _ in range(5)] == [True] * 5
    assert bucket.try_acquire() is False
    assert bucket.tokens == pytest.approx(0.0)
    # 100 ms at 10 tokens/s = 1 token.
    clock.advance(0.1)
    assert bucket.tokens == pytest.approx(1.0)
    assert bucket.try_acquire() is True
    # Refill never exceeds the burst capacity.
    clock.advance(60)
    assert bucket.tokens == pytest.approx(5.0)


async def test_acquire_waits_exactly_as_long_as_the_rate_requires() -> None:
    clock = FakeClock()
    bucket = TokenBucket(4, 1, clock=clock)
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        clock.advance(seconds)

    assert await bucket.acquire(sleep=fake_sleep) == 0.0
    first = await bucket.acquire(sleep=fake_sleep)
    second = await bucket.acquire(sleep=fake_sleep)
    assert first == pytest.approx(0.25)
    assert second == pytest.approx(0.25)
    assert bucket.acquired == 3
    assert bucket.waits == 2
    assert bucket.wait_seconds == pytest.approx(0.5)
    assert bucket.blocked_seconds == pytest.approx(0.5)
    assert slept == pytest.approx([0.25, 0.25])


async def test_concurrent_workers_are_serialised_by_one_bucket() -> None:
    """Two tasks sharing a bucket must not both fire on the same token."""
    import asyncio

    clock = FakeClock()
    bucket = TokenBucket(2, 1, clock=clock)
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock.advance(seconds)
        await asyncio.sleep(0)

    async def worker() -> float:
        return await bucket.acquire(sleep=fake_sleep)

    waited = await asyncio.gather(worker(), worker(), worker())
    assert sum(1 for item in waited if item == 0.0) == 1
    assert sorted(waited)[1:] == pytest.approx([0.5, 0.5])
    assert bucket.acquired == 3


def test_bucket_stats_report_the_counters() -> None:
    clock = FakeClock()
    bucket = TokenBucket(5, 2, clock=clock)
    bucket.try_acquire()
    stats = bucket.stats()
    assert stats["rate"] == 5 and stats["burst"] == 2
    assert stats["acquired"] == 1
    assert stats["waits"] == 0


# --------------------------------------------------------------------------- #
# RateLimiter (global + per server)
# --------------------------------------------------------------------------- #


async def test_per_server_buckets_are_independent() -> None:
    clock = FakeClock()
    limiter = RateLimiter(0, per_server_rate=1, per_server_burst=1, clock=clock)
    assert limiter.enabled is True
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        clock.advance(seconds)

    # Per-server buckets are created lazily on first use, on the same clock.
    assert limiter.bucket_for("9.9.9.10") is not None
    assert limiter.bucket_for("1.1.1.1") is not None
    assert await limiter.acquire("9.9.9.10") == 0.0
    assert await limiter.acquire("1.1.1.1") == 0.0  # a different server: no wait
    assert limiter.bucket_for("9.9.9.10").try_acquire() is False
    assert limiter.bucket_for(None) is None
    bucket = limiter.bucket_for("9.9.9.10")
    assert bucket is limiter.bucket_for("9.9.9.10")  # cached, not recreated


def test_limiter_summary_and_stats() -> None:
    limiter = RateLimiter(0)
    assert limiter.summary() == "DNS rate limit: off (unlimited)"
    assert limiter.stats()["enabled"] is False

    limiter = RateLimiter(25, burst=5, per_server_rate=8)
    summary = limiter.summary()
    assert "25 q/s global" in summary and "burst 5" in summary
    assert "8 q/s per key" in summary
    stats = limiter.stats()
    assert stats["enabled"] is True and stats["per_server_rate"] == 8
    # The port sweep reuses the same class, so the prefix is configurable.
    assert limiter.summary(prefix="connect limit: ").startswith("connect limit: 25 q/s")
    assert RateLimiter(0).summary(prefix="connect limit: ") == "connect limit: off (unlimited)"


async def test_group_exposes_named_limiters() -> None:
    limiter = RateLimiter(0)
    group = RateLimiterGroup(dns=limiter)
    assert group["dns"] is limiter
    assert group.get("missing") is None
    assert await group.acquire("dns") == 0.0
    assert await group.acquire("missing") == 0.0
    assert set(group.stats()) == {"dns"}


# --------------------------------------------------------------------------- #
# Resolver integration
# --------------------------------------------------------------------------- #


def _resolver(**kwargs) -> AnonymousResolver:
    return AnonymousResolver(
        servers=("9.9.9.10", "149.112.112.10"),
        timeout=0.2,
        retries=1,
        concurrency=8,
        bus=None,
        disk_cache_enabled=False,
        **kwargs,
    )


def _answer_for(packet: bytes, address: str) -> bytes:
    """Build a minimal A answer for the query in *packet* (id preserved)."""
    import struct

    qid = struct.unpack("!H", packet[:2])[0]
    # Header: id, flags=0x8180 (response + RD + RA), qd=1, an=1
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    question = packet[12:]
    ip = bytes(int(part) for part in address.split("."))
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip
    return header + question + answer


def test_resolver_has_no_limiter_by_default() -> None:
    resolver = _resolver()
    assert resolver.limiter.enabled is False
    assert resolver.rate_limit == 0.0
    stats = resolver.transport_stats()
    assert stats["rate_limit"]["enabled"] is False
    assert stats["rate_waits"] == 0


def test_resolver_accepts_a_rate_limit() -> None:
    resolver = _resolver(rate_limit=30, rate_burst=10, rate_per_server=5)
    assert resolver.limiter.enabled is True
    assert resolver.limiter.global_bucket.rate == 30
    assert resolver.limiter.global_bucket.burst == 10
    assert resolver.limiter.per_server_rate == 5
    assert "30 q/s global" in resolver.limiter.summary()
    resolver.close()


def test_default_burst_is_one_second_of_tokens() -> None:
    resolver = _resolver(rate_limit=12)
    assert resolver.limiter.global_bucket.burst == 12
    resolver.close()


async def test_every_query_attempt_takes_a_token(monkeypatch) -> None:
    """Retries are paced too — a failing query must not hammer the resolver."""
    import asyncio

    resolver = _resolver(rate_limit=1000, rate_burst=1)
    taken: list[str] = []

    async def fake_acquire(server=None):
        taken.append(str(server))
        return 0.0

    monkeypatch.setattr(resolver.limiter, "acquire", fake_acquire)

    async def fake_exchange(packet, server, qid, timeout=None):
        raise TimeoutError("nope")

    monkeypatch.setattr(resolver, "_exchange", fake_exchange)
    real_sleep = asyncio.sleep
    monkeypatch.setattr(
        "subsonar.core.dns.asyncio.sleep", lambda *a, **k: real_sleep(0)
    )
    result = await resolver.query_raw("nope.example.com", use_cache=False, log=False)
    assert result.ok is False
    assert taken  # at least one attempt was paced
    resolver.close()


async def test_cached_queries_bypass_the_limiter(monkeypatch) -> None:
    """A cache hit costs no packet, so it must cost no token either."""
    resolver = _resolver(rate_limit=1, rate_burst=1)
    calls = {"n": 0}

    async def fake_exchange(packet, server, qid, timeout=None):
        calls["n"] += 1
        return _answer_for(packet, "10.0.0.1")

    monkeypatch.setattr(resolver, "_exchange", fake_exchange)
    first = await resolver.query_raw("hit.example.com", use_cache=True, log=False)
    assert first.ok is True
    taken_before = resolver.limiter.global_bucket.acquired
    second = await resolver.query_raw("hit.example.com", use_cache=True, log=False)
    assert second.ok is True and second.from_cache is True
    assert resolver.limiter.global_bucket.acquired == taken_before
    assert calls["n"] == 1
    resolver.close()


async def test_reported_rtt_excludes_the_rate_limiter_queue_wait(monkeypatch) -> None:
    """Regression: ``rtt_ms`` used to include the token-bucket wait.

    The live log showed ``NXDOMAIN from [94.140.15.15] (13313 ms)`` for answers
    that took 20 ms: the timer started *before* the rate limiter handed out a
    token, so the queueing delay was reported as resolver latency.  The exchange
    is now timed on its own, and the wait is surfaced separately.
    """
    import asyncio

    from subsonar.core.dns import _queued_note

    resolver = _resolver(rate_limit=1, rate_burst=1)
    sent: list[float] = []

    async def slow_acquire(server=None):
        # Pretend the bucket made us wait 600 ms for a token.
        sent.append(1.0)
        await asyncio.sleep(0.6)
        return 0.6

    async def fake_exchange(packet, server, qid, timeout=None):
        return _answer_for(packet, "10.9.9.9")

    monkeypatch.setattr(resolver.limiter, "acquire", slow_acquire)
    monkeypatch.setattr(resolver, "_exchange", fake_exchange)

    result = await resolver.query_raw("slow.example.com", use_cache=False, log=False)
    assert result.addresses == ["10.9.9.9"]
    # The mock answers instantly: the reported RTT must be ~0, not ~600 ms.
    assert result.rtt_ms < 300, f"rtt_ms leaked the queue wait: {result.rtt_ms}"
    assert resolver.rate_wait_seconds >= 0.5
    assert resolver.rate_waits == 1
    # …and the log line says where the time really went.
    assert _queued_note(0.0) == ""
    assert _queued_note(120.0) == ""
    assert _queued_note(1250.0) == ", queued 1.2s (rate limit)"
    resolver.close()


async def test_per_name_deadline_caps_the_failover_budget(monkeypatch) -> None:
    """A dead name must not cost ``attempts × timeout`` (6 × 2.5 s = 15 s).

    Dead names are the majority of any brute list, so the DNS phase used to be
    paced by timeouts rather than by the rate limit.  ``name_deadline`` bounds the
    wall-clock time one name may spend; ``0`` restores the old behaviour.
    """
    import asyncio

    calls: list[float] = []

    async def always_timeout(packet, server, qid, timeout=None):
        calls.append(timeout if timeout is not None else 1.0)
        await asyncio.sleep(calls[-1])
        raise DNSTimeout(f"no response from {server}")

    bounded = AnonymousResolver(
        servers=("9.9.9.10", "149.112.112.10"),
        timeout=1.0,
        retries=6,
        concurrency=8,
        bus=None,
        disk_cache_enabled=False,
        name_deadline=5.0,
    )
    monkeypatch.setattr(bounded, "_exchange", always_timeout)
    result = await bounded.query_raw("dead.example.com", use_cache=False, log=False)
    assert result.ok is False and result.deadline_hit is False
    # Every node is still consulted — the time is simply spent on more nodes: the
    # first attempt gets the full 1 s, the five failovers 0.3 s each.
    assert len(calls) == 6, f"expected all failover attempts, got {len(calls)}"
    assert calls[0] == 1.0
    assert all(abs(value - 0.3) < 0.01 for value in calls[1:]), calls
    assert len(result.attempted_servers) == 6
    bounded.close()

    # A tight budget stops the retrying instead of letting it run to the end.
    calls.clear()
    tight = AnonymousResolver(
        servers=("9.9.9.10", "149.112.112.10"),
        timeout=1.0,
        retries=6,
        concurrency=8,
        bus=None,
        disk_cache_enabled=False,
        name_deadline=0.5,
    )
    monkeypatch.setattr(tight, "_exchange", always_timeout)
    result = await tight.query_raw("dead.example.com", use_cache=False, log=False)
    assert result.deadline_hit is True
    assert tight.deadline_aborts == 1
    assert len(calls) == 1, f"budget not enforced: {len(calls)} attempts"
    tight.close()

    # 0 = unlimited, exactly the old behaviour.
    calls.clear()
    unbounded = AnonymousResolver(
        servers=("9.9.9.10", "149.112.112.10"),
        timeout=0.05,
        retries=6,
        concurrency=8,
        bus=None,
        disk_cache_enabled=False,
        name_deadline=0.0,
    )
    monkeypatch.setattr(unbounded, "_exchange", always_timeout)
    result = await unbounded.query_raw("dead.example.com", use_cache=False, log=False)
    assert result.deadline_hit is False and unbounded.deadline_aborts == 0
    assert len(calls) == 6
    unbounded.close()


async def test_failover_success_is_not_poisoned_by_an_earlier_timeout(monkeypatch) -> None:
    """Regression: a failover answer kept the failed attempt's error.

    ``result.ok`` is ``bool(addresses) and error is None``, so a host that timed
    out on the first resolver and answered on the second came back with
    ``addresses=['1.2.3.4']`` **and** ``error='no response from …'`` → ``ok=False``.
    The engine then dropped a perfectly resolvable host as unresolved (and never
    cached it), which showed up as missing subdomains in real scans.
    """
    resolver = _resolver(rate_limit=0)
    seen: list[str] = []

    async def flaky_exchange(packet, server, qid, timeout=None):
        seen.append(server)
        if len(seen) == 1:
            raise DNSTimeout(f"no response from {server} within 0.2s")
        return _answer_for(packet, "10.2.2.2")

    monkeypatch.setattr(resolver, "_exchange", flaky_exchange)
    result = await resolver.query_raw("flaky.example.com", use_cache=False, log=False)
    assert result.addresses == ["10.2.2.2"]
    assert result.error is None, result.error
    assert result.ok is True
    assert len(seen) >= 2  # the first node really did fail first
    assert len(result.attempted_servers) >= 2
    resolver.close()


async def test_query_raw_answers_are_parsed_with_the_limiter_enabled(monkeypatch) -> None:
    resolver = _resolver(rate_limit=1000, rate_burst=100)

    async def fake_exchange(packet, server, qid, timeout=None):
        return _answer_for(packet, "10.1.2.3")

    monkeypatch.setattr(resolver, "_exchange", fake_exchange)
    result = await resolver.resolve("paced.example.com", log=False)
    assert result.addresses == ["10.1.2.3"]
    assert resolver.limiter.global_bucket.acquired >= 1
    resolver.close()



# --------------------------------------------------------------------------- #
# Configuration & profiles
# --------------------------------------------------------------------------- #


def test_scan_config_marks_an_explicit_rate_as_an_override() -> None:
    assert ScanConfig(domain="example.com").dns_rate_override is False
    assert ScanConfig(domain="example.com", dns_rate_limit=50).dns_rate_override is True
    assert (
        ScanConfig(domain="example.com", dns_rate_per_server=5).dns_rate_override is True
    )


def test_profile_supplies_a_default_rate_but_never_overrides_a_choice() -> None:
    default = ScanConfig(domain="example.com")
    apply_profile(get_profile(8), default)
    assert default.dns_rate_limit == 25.0
    assert default.dns_rate_per_server == 8.0
    assert default.port_rate_limit == 60.0
    assert default.port_rate_per_host == 10.0

    # Every profile is paced by default — no profile is unlimited any more, so a
    # scan cannot get the resolver pool or the target's IPS to ban it.
    for profile in PROFILES:
        config = ScanConfig(domain="example.com")
        apply_profile(profile, config)
        assert config.dns_rate_limit > 0, profile.name
        assert config.dns_rate_per_server > 0, profile.name
        if profile.port_scan:
            assert config.port_rate_limit > 0, profile.name
        # The bar must never be raised above a sane per-client ceiling.
        assert config.dns_rate_limit <= 500, profile.name
        assert config.port_rate_limit <= 1000, profile.name

    # An explicit --dns-rate/--port-rate survives the profile application.
    chosen = ScanConfig(domain="example.com", dns_rate_limit=7, port_rate_limit=99)
    apply_profile(get_profile(8), chosen)
    assert chosen.dns_rate_limit == 7
    assert chosen.port_rate_limit == 99
    assert chosen.port_rate_per_host == 0.0  # untouched: profile value skipped


def test_scan_config_marks_an_explicit_port_rate_as_an_override() -> None:
    assert ScanConfig(domain="example.com").port_rate_override is False
    assert (
        ScanConfig(domain="example.com", port_rate_limit=200).port_rate_override is True
    )
    assert (
        ScanConfig(domain="example.com", port_rate_per_host=20).port_rate_override
        is True
    )


def test_engine_passes_the_rate_limit_to_the_resolver() -> None:
    from subsonar.core.engine import ScanEngine

    config = ScanConfig(
        domain="example.com",
        dns_rate_limit=40,
        dns_rate_burst=4,
        dns_rate_per_server=9,
    )
    engine = ScanEngine(config, profile=3)
    assert engine._resolver.limiter.enabled is True
    assert engine._resolver.limiter.global_bucket.rate == 40
    assert engine._resolver.limiter.global_bucket.burst == 4
    assert engine._resolver.limiter.per_server_rate == 9
    engine._resolver.close()


def test_cli_flags_flow_into_the_settings() -> None:
    from main import _settings_from_args, build_parser

    args = build_parser().parse_args(
        [
            "scan",
            "example.com",
            "--dns-rate",
            "12.5",
            "--dns-rate-per-server",
            "3",
            "--dns-rate-burst",
            "20",
        ]
    )
    settings = _settings_from_args(args)
    assert settings.dns_rate == 12.5
    assert settings.dns_rate_per_server == 3.0
    assert settings.dns_rate_burst == 20.0
    config = settings.build_config("example.com")
    assert config.dns_rate_limit == 12.5
    assert config.dns_rate_override is True
    assert config.dns_rate_burst == 20.0


def test_build_query_still_works_with_the_new_rr_types() -> None:
    """Sanity check that the CAA/DS/SOA additions did not disturb the encoder."""
    packet, qid = build_query("example.com", 257)  # CAA
    assert len(packet) > 12 and 0 <= qid <= 0xFFFF


def test_real_timing_is_bounded_by_the_rate(monkeypatch) -> None:
    """End-to-end (real clock): 4 queries at 50 q/s cannot finish instantly."""
    import asyncio

    async def run() -> float:
        resolver = _resolver(rate_limit=50, rate_burst=1)

        async def fake_exchange(packet, server, qid, timeout=None):
            return _answer_for(packet, "10.0.0.9")

        monkeypatch.setattr(resolver, "_exchange", fake_exchange)
        started = time.monotonic()
        for index in range(4):
            await resolver.query_raw(
                f"h{index}.example.com", use_cache=False, log=False
            )
        elapsed = time.monotonic() - started
        resolver.close()
        return elapsed

    elapsed = asyncio.run(run())
    # Three waits of ~20 ms with a burst of one — a generous lower bound that
    # still proves the limiter actually paced the queries.
    assert elapsed >= 0.045

