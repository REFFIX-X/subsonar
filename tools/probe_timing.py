"""Measure the port phase against a realistic closed address.

Loopback lies: a closed 127.0.0.1 port takes ~2 s to fail on this machine (no
instant RST), which inflated earlier numbers.  192.0.2.0/24 is TEST-NET-1
(RFC 5737) and is neither routed nor reachable, so probes behave like a
firewalled host — exactly the case the adaptive timeout targets.
"""

from __future__ import annotations

import asyncio
import contextlib
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from subsonar.core.config import PORT_MATRIX
from subsonar.core.events import EventBus
from subsonar.core.scanner import AsyncPortScanner
from subsonar.core.selftest import MOCK_IP, MockHTTPServer

FILTERED = "192.0.2.1"   # RFC 5737 TEST-NET-1 (unroutable)
PORTS = sorted(PORT_MATRIX)


async def timed(label: str, coro) -> float:
    t0 = time.perf_counter()
    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(coro, timeout=180)
    dt = time.perf_counter() - t0
    print(f"  {label:<56} {dt:>8.2f}s")
    return dt


async def main() -> None:
    http = MockHTTPServer()
    open_port = await http.start()
    print(f"mock web server on {MOCK_IP}:{open_port}")
    print(f"filtered address    {FILTERED} (RFC 5737, unreachable)\n")

    # --- single probe cost against an unroutable address -------------------- #
    print("1. single probe cost")
    for timeout in (0.45, 1.8):
        scanner = AsyncPortScanner(
            timeout=timeout, fast_timeout=timeout, concurrency=50,
            bus=EventBus(), log_attempts=False,
        )
        samples = []
        for _ in range(3):
            t0 = time.perf_counter()
            await scanner.probe("f.test", FILTERED, 8080, verbose=False)
            samples.append((time.perf_counter() - t0) * 1000)
        print(
            f"  timeout={timeout:.2f}s → {statistics.median(samples):>7.0f} ms "
            f"(default loopback noise ~2000 ms)"
        )

    # --- whole 50-port matrix, one filtered host ---------------------------- #
    print("\n2. full 50-port matrix against one filtered host")
    old = AsyncPortScanner(
        timeout=1.8, fast_timeout=1.8, concurrency=300, bus=EventBus(), log_attempts=False
    )
    await timed("flat 1.8s timeout (old behaviour, 49 ports)", old.scan_host("f.test", FILTERED, PORTS))

    new = AsyncPortScanner(
        timeout=1.8, fast_timeout=0.45, concurrency=300, bus=EventBus(), log_attempts=False
    )
    await timed("adaptive 0.45s→1.8s (new), no responsive ports", new.scan_host("f.test", FILTERED, PORTS))
    print(f"     scanner stats: {new.stats.to_dict()}")

    # --- mixed batch: 1 live host + 31 filtered hosts, port-major ----------- #
    print("\n3. 32-host batch, 1 live + 31 filtered (port-major sweep)")
    hosts = [(f"h{i}.batch.test", FILTERED) for i in range(31)]
    hosts.insert(0, ("live.batch.test", MOCK_IP))
    sweep_ports = [open_port] + [p for p in PORTS if p != open_port][:9]

    new2 = AsyncPortScanner(
        timeout=1.8, fast_timeout=0.45, concurrency=300, bus=EventBus(), log_attempts=False
    )
    t0 = time.perf_counter()
    swept = await new2.sweep_hosts(hosts, sweep_ports)
    dt = time.perf_counter() - t0
    live = swept.get("live.batch.test", [])
    print(
        f"  {'sweep_hosts (port-major, adaptive)':<56} {dt:>8.2f}s\n"
        f"     live host open ports: {[r.port for r in live]}\n"
        f"     scanner stats: {new2.stats.to_dict()}"
    )

    http.stop()


if __name__ == "__main__":
    asyncio.run(main())
