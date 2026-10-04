"""Measure the persistent DNS cache: cold vs warm across separate resolvers."""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from subsonar.core.dns import AnonymousResolver
from subsonar.core.dnscache import DNSCache

NAMES = [
    "example.com",
    "www.example.com",
    "iana.org",
    "cloudflare.com",
    "python.org",
    "nope-xyzzy-42.example.com",
    "nope-xyzzy-43.example.com",
    "nope-xyzzy-44.example.com",
]

CACHE_PATH = Path(".tmp/dns-cache-bench.sqlite3")


async def run(label: str) -> None:
    cache = DNSCache(CACHE_PATH)
    resolver = AnonymousResolver(
        timeout=2.5, retries=3, verbose_queries=False, disk_cache=cache
    )
    await resolver.health_check(timeout=2.0, log=False)
    started = time.perf_counter()
    results = await resolver.resolve_many(NAMES, log=False)
    elapsed = time.perf_counter() - started
    ok = sum(1 for r in results if r.ok)
    nx = sum(1 for r in results if r.error == "NXDOMAIN")
    stats = cache.stats()
    print(
        f"  {label:<32} {elapsed:>6.3f}s  ok={ok} nx={nx}  "
        f"disk_hits={resolver.disk_cache_hits:<3} "
        f"entries={stats['entries']:<3} hit_rate={stats['hit_rate']}"
    )
    if stats["errors"]:
        print(f"    cache errors: {stats['errors']}")
    resolver.close()


async def main() -> None:
    for path in CACHE_PATH.parent.glob(CACHE_PATH.name + "*"):
        path.unlink(missing_ok=True)
    print("persistent DNS cache — same 8 names, separate resolver instances\n")
    await run("cold (empty cache)")
    await run("warm (populated cache)")
    await run("warm again")


if __name__ == "__main__":
    asyncio.run(main())
