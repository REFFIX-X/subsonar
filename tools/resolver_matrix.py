"""Probe every resolver in the anonymous pool with a parallel nslookup-style run."""

from __future__ import annotations

import asyncio
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from subsonar.core.config import DNS_RESOLVER_POOL
from subsonar.core.dns import AnonymousResolver

NAMES = ("example.com", "www.example.com", "one.one.one.one", "dns.google")


async def main() -> None:
    print(f"probing {len(DNS_RESOLVER_POOL)} anonymous resolvers x {len(NAMES)} names\n")
    matrix: dict[str, list[str]] = {}
    for server in DNS_RESOLVER_POOL:
        resolver = AnonymousResolver(
            servers=[server], timeout=2.5, retries=1, verbose_queries=False
        )
        results = await resolver.resolve_many(NAMES, log=False)
        ok = sum(1 for r in results if r.ok)
        detail = []
        for name, res in zip(NAMES, results):
            if res.ok:
                detail.append(f"{name}={res.rtt_ms:.0f}ms")
            else:
                detail.append(f"{name}=FAIL({res.error})")
        matrix[server] = detail
        print(f"  {server:<18} {ok}/{len(NAMES)}  " + "  ".join(detail[:2]))

    responsive = [s for s, d in matrix.items() if any("FAIL" not in item for item in d)]
    print(f"\nresponsive: {len(responsive)}/{len(DNS_RESOLVER_POOL)}")
    print("dead:", [s for s in DNS_RESOLVER_POOL if s not in responsive])

    # Round-trip through the full rotation pool the way the engine does it.
    t0 = time.perf_counter()
    rotating = AnonymousResolver(timeout=2.5, retries=2, verbose_queries=False)
    results = await rotating.resolve_many(NAMES * 3, log=False)
    ok = sum(1 for r in results if r.ok)
    rtts = [r.rtt_ms for r in results if r.ok]
    print(
        f"\nrotation pool: {ok}/{len(results)} resolved in "
        f"{time.perf_counter() - t0:.2f}s"
        + (f" (median {statistics.median(rtts):.0f} ms)" if rtts else "")
    )


if __name__ == "__main__":
    asyncio.run(main())
