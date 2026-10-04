"""Async token-bucket rate limiting (DNS query pacing, per resolver and global).

A concurrency limit (:attr:`ScanConfig.dns_concurrency`) bounds how many queries
are *in flight*; it does not bound how many queries per second leave the machine,
which is what a resolver operator actually notices.  This module adds that
second, orthogonal control.

* one bucket for the whole resolver pool (``dns_rate_limit``),
* one bucket per nameserver (``dns_rate_per_server``), so a single resolver can
  never be hammered by a large pool,
* tokens are refilled continuously, so bursts up to ``burst`` are allowed while
  the long-run average equals ``rate``,
* the clock is injectable, which makes the behaviour testable without real waits.

Every bucket keeps counters (``acquired``, ``waits``, ``wait_seconds``) so the
live statistics can report what the limiter actually cost.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable

__all__ = ["RateLimiter", "RateLimiterGroup", "TokenBucket"]


class TokenBucket:
    """A monotonic token bucket.

    ``rate`` is tokens per second (``<= 0`` disables the bucket entirely),
    ``burst`` the bucket capacity (defaults to one second worth of tokens).
    """

    __slots__ = (
        "rate",
        "burst",
        "acquired",
        "waits",
        "wait_seconds",
        "blocked_seconds",
        "_tokens",
        "_updated",
        "_clock",
        "_lock",
    )

    def __init__(
        self,
        rate: float,
        burst: float | None = None,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.rate = max(0.0, float(rate))
        capacity = float(burst) if burst is not None else max(1.0, self.rate)
        self.burst = max(1.0, capacity) if self.rate > 0 else 0.0
        self._clock = clock or time.monotonic
        self._tokens = self.burst
        self._updated = self._clock()
        self._lock = asyncio.Lock()
        self.acquired = 0
        self.waits = 0
        self.wait_seconds = 0.0
        self.blocked_seconds = 0.0

    # -- introspection ------------------------------------------------------ #
    @property
    def enabled(self) -> bool:
        return self.rate > 0.0 and self.burst > 0.0

    @property
    def tokens(self) -> float:
        """Currently available tokens (after refilling for the elapsed time)."""
        if not self.enabled:
            return 0.0
        now = self._clock()
        elapsed = max(0.0, now - self._updated)
        return min(self.burst, self._tokens + elapsed * self.rate)

    # -- internals ---------------------------------------------------------- #
    def _refill(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._updated)
        if elapsed:
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._updated = now

    def _take(self) -> float:
        """Consume one token; returns how long the caller must wait first."""
        if not self.enabled:
            self.acquired += 1
            return 0.0
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            self.acquired += 1
            return 0.0
        missing = 1.0 - self._tokens
        wait = missing / self.rate
        self._tokens = 0.0
        self._updated += wait
        self.acquired += 1
        return wait

    # -- public API --------------------------------------------------------- #
    def try_acquire(self) -> bool:
        """Non-blocking take; ``False`` when the caller would have to wait."""
        if not self.enabled:
            self.acquired += 1
            return True
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            self.acquired += 1
            return True
        return False

    async def acquire(self, sleep: Callable[[float], Any] | None = None) -> float:
        """Wait for one token; returns the seconds spent waiting.

        ``_take`` reserves the token eagerly — it advances ``_updated`` to the
        slot this waiter owns *before* we sleep.  That reservation already
        prevents the burst a naive implementation would produce, so the lock can
        be released before the sleep: a concurrent caller simply reserves the
        next slot.  Not holding the lock across the sleep removes the single
        point of contention when hundreds of workers share one bucket.
        """
        waiter = sleep or asyncio.sleep
        async with self._lock:
            wait = self._take()
            if wait <= 0.0:
                return 0.0
            self.waits += 1
            self.wait_seconds += wait
        started = self._clock()
        await waiter(wait)
        self.blocked_seconds += max(0.0, self._clock() - started)
        return wait

    def stats(self) -> dict[str, Any]:
        return {
            "rate": self.rate,
            "burst": self.burst,
            "acquired": self.acquired,
            "waits": self.waits,
            "wait_seconds": round(self.wait_seconds, 3),
            "blocked_seconds": round(self.blocked_seconds, 3),
        }


class RateLimiter:
    """Facade: one global bucket plus one bucket per nameserver."""

    def __init__(
        self,
        rate: float = 0.0,
        *,
        burst: float | None = None,
        per_server_rate: float = 0.0,
        per_server_burst: float | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.global_bucket = TokenBucket(rate, burst, clock=clock)
        self.per_server_rate = max(0.0, float(per_server_rate))
        self.per_server_burst = per_server_burst
        self._clock = clock
        self._servers: dict[str, TokenBucket] = {}

    @property
    def enabled(self) -> bool:
        return self.global_bucket.enabled or self.per_server_rate > 0.0

    def bucket_for(self, server: str | None) -> TokenBucket | None:
        """The per-nameserver bucket, created on first use."""
        if self.per_server_rate <= 0.0 or not server:
            return None
        bucket = self._servers.get(server)
        if bucket is None:
            bucket = TokenBucket(
                self.per_server_rate, self.per_server_burst, clock=self._clock
            )
            self._servers[server] = bucket
        return bucket

    async def acquire(self, server: str | None = None) -> float:
        """Wait for both the global and the per-server token (``0.0`` = no wait)."""
        waited = await self.global_bucket.acquire()
        bucket = self.bucket_for(server)
        if bucket is not None:
            waited += await bucket.acquire()
        return waited

    @property
    def waits(self) -> int:
        return self.global_bucket.waits + sum(b.waits for b in self._servers.values())

    @property
    def wait_seconds(self) -> float:
        return self.global_bucket.wait_seconds + sum(
            bucket.wait_seconds for bucket in self._servers.values()
        )

    def stats(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "global": self.global_bucket.stats(),
            "per_server_rate": self.per_server_rate,
            "servers": {
                name: bucket.stats() for name, bucket in self._servers.items()
            },
            "waits": self.waits,
            "wait_seconds": round(self.wait_seconds, 3),
        }

    def summary(self, *, prefix: str = "DNS rate limit: ", unit: str = "q/s") -> str:
        """One-line description for the live log."""
        if not self.enabled:
            return f"{prefix}off (unlimited)"
        parts = []
        if self.global_bucket.enabled:
            parts.append(
                f"{self.global_bucket.rate:g} {unit} global "
                f"(burst {self.global_bucket.burst:g})"
            )
        if self.per_server_rate > 0:
            parts.append(f"{self.per_server_rate:g} {unit} per key")
        return prefix + ", ".join(parts)



class RateLimiterGroup:
    """Named limiters (e.g. one for DNS, one for HTTP) sharing the same maths."""

    def __init__(self, **limiters: RateLimiter) -> None:
        self._limiters = dict(limiters)

    def __getitem__(self, name: str) -> RateLimiter:
        return self._limiters[name]

    def get(self, name: str) -> RateLimiter | None:
        return self._limiters.get(name)

    async def acquire(self, name: str, server: str | None = None) -> float:
        limiter = self._limiters.get(name)
        if limiter is None:
            return 0.0
        return await limiter.acquire(server)

    def stats(self) -> dict[str, Any]:
        return {name: limiter.stats() for name, limiter in self._limiters.items()}

