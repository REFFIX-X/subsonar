"""Check whether probe cancellation is actually fast, or the timeout tail eats it."""

from __future__ import annotations

import asyncio
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from subsonar.core.config import PORT_MATRIX
from subsonar.core.events import EventBus
from subsonar.core.scanner import AsyncPortScanner

FILTERED = "192.0.2.1"
PORTS = sorted(PORT_MATRIX)


async def measure(label: str, n: int, timeout: float, concurrency: int) -> None:
    scanner = AsyncPortScanner(
        timeout=timeout, fast_timeout=timeout, concurrency=concurrency,
        bus=EventBus(), log_attempts=False,
    )
    probes = [("f.test", FILTERED, p) for p in PORTS[:n]]
    t0 = time.perf_counter()
    results = await scanner.probe_batch(probes, timeout=timeout, verbose=False)
    dt = time.perf_counter() - t0
    modes = {}
    for r in results:
        modes[r.failure] = modes.get(r.failure, 0) + 1
    print(
        f"  {label:<48} {dt:>7.2f}s  "
        f"({n / dt:>7.1f}/s) expected≥{n * timeout / min(concurrency, n):.2f}s  {modes}"
    )


async def main() -> None:
    print(f"filtered address {FILTERED}\n")
    for n in (10, 50):
        for c in (10, 50, 300):
            await measure(f"n={n} concurrency={c} timeout=0.45", n, 0.45, c)
    print()
    for n in (10, 50):
        await measure(f"n={n} concurrency=300 timeout=1.8", n, 1.8, 300)

    # How much of the wall time is the wait_for cancellation overhead?
    print("\n  cancellation overhead per probe:")
    for timeout in (0.2, 0.45, 1.8):
        scanner = AsyncPortScanner(
            timeout=timeout, fast_timeout=timeout, concurrency=50,
            bus=EventBus(), log_attempts=False,
        )
        samples = []
        for _ in range(5):
            t0 = time.perf_counter()
            await scanner.probe("f.test", FILTERED, 8080, timeout=timeout, verbose=False)
            samples.append((time.perf_counter() - t0) * 1000)
        print(f"    timeout={timeout:.2f}s → wall {statistics.median(samples):>7.0f} ms")


if __name__ == "__main__":
    asyncio.run(main())
