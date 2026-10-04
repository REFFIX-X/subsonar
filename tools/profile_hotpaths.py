"""Profile the subsonar hot paths. Every stage is hard-bounded so it cannot hang.

Unlike a naive benchmark, each measurement runs under :func:`asyncio.wait_for`
with a wall-clock budget, and the whole run has a global deadline.  If a stage
blows its budget it is reported as TIMEOUT and skipped rather than blocking.

Usage::

    python tools/profile_hotpaths.py               # loopback, ~30s
    python tools/profile_hotpaths.py --seconds 60
    python tools/profile_hotpaths.py --live        # adds real DNS numbers
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import gc
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from subsonar.core.config import PORT_MATRIX
from subsonar.core.dns import AnonymousResolver, build_query, TYPE_A
from subsonar.core.events import EventBus
from subsonar.core.scanner import AsyncPortScanner
from subsonar.core.selftest import MOCK_IP, TEST_DOMAIN, MockDNSServer, MockHTTPServer

DEADLINE = 120.0


class Budget:
    """Global wall-clock budget guard."""

    def __init__(self, seconds: float) -> None:
        self.deadline = time.perf_counter() + seconds

    @property
    def expired(self) -> bool:
        return time.perf_counter() >= self.deadline

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.perf_counter())


async def guard(label: str, coro, budget: Budget, *, limit: float | None = None):
    """Await *coro* with a bounded timeout; report TIMEOUT instead of hanging."""
    timeout = min(limit or 20.0, budget.remaining())
    if timeout <= 0.5:
        print(f"  {label:<42} SKIPPED (budget exhausted)")
        return None
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        print(f"  {label:<42} TIMEOUT after {timeout:.1f}s — stage skipped")
        return None
    except Exception as exc:  # noqa: BLE001
        print(f"  {label:<42} ERROR {exc.__class__.__name__}: {exc}")
        return None


def section(title: str) -> None:
    print(f"\n{'=' * 74}\n  {title}\n{'=' * 74}")


def row(label: str, ops: int, seconds: float, extra: str = "") -> None:
    rate = ops / seconds if seconds > 0 else 0.0
    print(f"  {label:<42} {ops:>7,}  {seconds:>7.3f}s  {rate:>11,.0f}/s  {extra}")


# --------------------------------------------------------------------------- #


async def profile_dns(budget: Budget, hosts: int) -> None:
    section("DNS — loopback authoritative mock")
    dns = MockDNSServer(wildcard=True)
    port = await dns.start()
    try:
        resolver = AnonymousResolver(
            servers=[f"{MOCK_IP}:{port}"], timeout=2.0, concurrency=400,
            bus=EventBus(), verbose_queries=False,
        )
        names = [f"h{i}.{TEST_DOMAIN}" for i in range(hosts)]

        resolver.cache_clear()
        t0 = time.perf_counter()
        results = await guard("resolve_many (cold)", resolver.resolve_many(names, log=False), budget, limit=30)
        if results is not None:
            row("DNS resolve_many (cold)", len(results), time.perf_counter() - t0)

        t0 = time.perf_counter()
        await guard("resolve_many (warm cache)", resolver.resolve_many(names, log=False), budget, limit=10)
        row("DNS resolve_many (warm cache)", len(names), time.perf_counter() - t0)

        # Isolate one raw exchange: socket create + send + recv + close.
        packet, qid = build_query("probe.subsonar.test", TYPE_A)
        samples: list[float] = []
        started = time.perf_counter()
        while len(samples) < 200 and time.perf_counter() - started < 12:
            t = time.perf_counter()
            with contextlib.suppress(Exception):
                await resolver._exchange(packet, f"{MOCK_IP}:{port}", qid)
            samples.append((time.perf_counter() - t) * 1e6)
        if samples:
            samples.sort()
            print(
                f"  {'single UDP exchange (setup+tx+rx+close)':<42} "
                f"n={len(samples)}  p50={statistics.median(samples):>7.0f}us  "
                f"p95={samples[int(len(samples) * 0.95)]:>7.0f}us"
            )
    finally:
        dns.stop()


async def profile_dns_live(budget: Budget) -> None:
    section("DNS — real anonymous resolvers")
    resolver = AnonymousResolver(timeout=2.5, concurrency=400, verbose_queries=False)
    t0 = time.perf_counter()
    health = await guard("health_check (18 nodes)", resolver.health_check(timeout=2.0, log=False), budget, limit=20)
    if health is None:
        return
    print(
        f"  {'resolver health check':<42} {len([e for e in health.values() if e is None])}"
        f"/{len(health)} live  {time.perf_counter() - t0:.2f}s"
    )
    names = ["example.com", "www.example.com", "iana.org", "www.iana.org",
             "cloudflare.com", "www.cloudflare.com", "python.org", "pypi.org"]
    resolver.cache_clear()
    t0 = time.perf_counter()
    results = await guard("real resolve_many", resolver.resolve_many(names, log=False), budget, limit=30)
    if results is not None:
        ok = sum(1 for r in results if r.ok)
        row(f"real resolve_many (ok={ok})", len(results), time.perf_counter() - t0)
        rtts = sorted(r.rtt_ms for r in results if r.ok)
        if rtts:
            print(
                f"  {'median RTT':<42} p50={statistics.median(rtts):>7.0f}ms  "
                f"p95={rtts[int(len(rtts) * 0.95)]:>7.0f}ms"
            )


async def profile_ports(budget: Budget, hosts: int) -> None:
    section("Port scanning — closed ports on loopback (worst case)")
    sock_port = 9123  # unused on loopback
    ports = [p for p in sorted(PORT_MATRIX) if p != 8000]

    scanner = AsyncPortScanner(timeout=1.8, concurrency=300, bus=EventBus(), log_attempts=False)

    async def one_probe() -> tuple[int, float]:
        t = time.perf_counter()
        await scanner.probe("bench.test", "127.0.0.1", sock_port)
        return 1, time.perf_counter() - t

    # Sequential single probe cost.
    n_seq = 100
    t0 = time.perf_counter()
    for _ in range(n_seq):
        await one_probe()
    seq = time.perf_counter() - t0
    row("probe() sequential, 1 closed port", n_seq, seq, f"{seq / n_seq * 1000:.1f} ms/probe")

    # Host-major sweep: what the engine does today (50 ports, one host).
    reps = max(1, hosts // 100)
    t0 = time.perf_counter()
    total = 0
    for _ in range(reps):
        got = await guard("scan_host sweep", scanner.scan_host(TEST_DOMAIN, "127.0.0.1", ports), budget, limit=60)
        total += len(ports)
        if got is None:
            break
    if total:
        row("scan_host (host-major, 50 ports)", total, time.perf_counter() - t0)

    # Port-major sweep over a synthetic host batch: the proposed replacement.
    scanner2 = AsyncPortScanner(timeout=0.4, concurrency=300, bus=EventBus(), log_attempts=False)
    batch = 32
    t0 = time.perf_counter()
    swept = 0
    for _ in range(max(1, reps)):
        results = await guard(
            "port-major batch",
            scanner2.sweep_hosts([(f"h{i}.bench.test", "127.0.0.1") for i in range(batch)], ports),
            budget, limit=60,
        )
        swept += batch * len(ports)
        if results is None:
            break
    if swept:
        row(f"port-major sweep ({batch} hosts x {len(ports)} ports)", swept, time.perf_counter() - t0)


async def profile_http(budget: Budget, count: int) -> None:
    section("HTTP verification — loopback mock")
    dns = MockDNSServer()
    http = MockHTTPServer()
    dns_port = await dns.start()
    http_port = await http.start()
    try:
        from subsonar.core.web_probe import WebProbe

        resolver = AnonymousResolver(
            servers=[f"{MOCK_IP}:{dns_port}"], timeout=2.0, concurrency=400,
            bus=EventBus(), verbose_queries=False,
        )
        probe = WebProbe(resolver=resolver, timeout=4.0, concurrency=60, bus=EventBus())
        await probe.start()
        try:
            t0 = time.perf_counter()
            for _ in range(count):
                await probe.probe(TEST_DOMAIN, MOCK_IP, http_port)
            row("probe() GET + title", count, time.perf_counter() - t0)

            if hasattr(probe, "probe_head"):
                t0 = time.perf_counter()
                for _ in range(count):
                    await probe.probe_head(TEST_DOMAIN, http_port)
                row("probe_head() HEAD-only", count, time.perf_counter() - t0)
        finally:
            await probe.close()
    finally:
        dns.stop()
        http.stop()


def profile_pure(hosts: int) -> None:
    section("Pure-python hot paths")
    from subsonar.core.wordlist import parse_wordlist

    text = "\n".join(f"host{i}" for i in range(200_000))
    t0 = time.perf_counter()
    words = parse_wordlist(text, limit=hosts)
    row("parse_wordlist (200k line input)", len(words), time.perf_counter() - t0)

    gc.collect()
    base = sum(sys.getsizeof(o) for o in ())
    t0 = time.perf_counter()
    candidates = [f"{w}.example.com" for w in words[: min(20_000, len(words))]]
    row("candidate hostname build", len(candidates), time.perf_counter() - t0)
    del candidates, base
    gc.collect()

    try:
        import tracemalloc

        tracemalloc.start()
        sample = [f"{w}.example.com" for w in words[: min(20_000, len(words))]]
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        per = peak / max(1, len(sample))
        print(
            f"  {'candidate memory':<42} {per:>7.0f} B/host  "
            f"→ {per * 100_000 / 1024 / 1024:.1f} MiB at 100k hosts"
        )
    except Exception:
        pass


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hosts", type=int, default=1000)
    parser.add_argument("--seconds", type=float, default=DEADLINE,
                        help="global wall-clock budget (default 120s)")
    parser.add_argument("--live", action="store_true", help="include real DNS")
    parser.add_argument("--only", choices=("dns", "ports", "http", "pure"), default=None)
    args = parser.parse_args()

    budget = Budget(args.seconds)
    print(
        f"subsonar hot-path profile — hosts={args.hosts:,} budget={args.seconds:.0f}s "
        f"python={sys.version.split()[0]} matrix={len(PORT_MATRIX)}"
    )

    if args.only in (None, "dns"):
        await profile_dns(budget, args.hosts)
        if args.live and not budget.expired:
            await profile_dns_live(budget)
    if args.only in (None, "ports") and not budget.expired:
        await profile_ports(budget, args.hosts)
    if args.only in (None, "http") and not budget.expired:
        await profile_http(budget, min(300, args.hosts))
    if args.only in (None, "pure"):
        profile_pure(args.hosts)

    print(f"\n  elapsed {DEADLINE - budget.remaining():.1f}s of {args.seconds:.0f}s budget\n")


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
