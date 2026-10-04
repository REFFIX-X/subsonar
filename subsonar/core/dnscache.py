"""Persistent DNS answer cache backed by SQLite.

Brute-force enumeration is overwhelmingly redundant across runs: the same
NXDOMAIN answers are re-queried every time.  A durable cache turns a repeat scan
of the same domain from tens of thousands of packets into a handful.

Only DNS answers are stored — never scan findings — and every entry carries an
absolute expiry so a stale negative answer cannot mask a host that has since
appeared.  Negative answers use a deliberately short TTL.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .config import CACHE_DIR

SCHEMA_VERSION = 1

#: TTL for a successful answer when the record itself carries no TTL.
DEFAULT_POSITIVE_TTL = 900
#: TTL for NXDOMAIN / empty answers.  Short: reality changes.
DEFAULT_NEGATIVE_TTL = 600
#: TTL for transport-level failures — very short, they may be transient.
DEFAULT_ERROR_TTL = 60


@dataclass(slots=True)
class CacheEntry:
    name: str
    qtype: str
    addresses: list[str]
    cnames: list[str]
    error: str | None
    resolver: str | None
    rtt_ms: float
    expires_at: float
    hits: int = 0

    @property
    def age(self) -> float:
        return max(0.0, self.expires_at - time.time())

    def to_json(self) -> str:
        return json.dumps(
            {
                "addresses": self.addresses,
                "cnames": self.cnames,
                "error": self.error,
                "resolver": self.resolver,
                "rtt_ms": self.rtt_ms,
            },
            separators=(",", ":"),
        )

    @classmethod
    def from_row(cls, row: tuple[Any, ...]) -> "CacheEntry":
        name, qtype, payload, expires_at, hits = row
        try:
            data = json.loads(payload)
        except (TypeError, ValueError):
            data = {}
        return cls(
            name=name,
            qtype=qtype,
            addresses=list(data.get("addresses") or []),
            cnames=list(data.get("cnames") or []),
            error=data.get("error"),
            resolver=data.get("resolver"),
            rtt_ms=float(data.get("rtt_ms") or 0.0),
            expires_at=float(expires_at or 0),
            hits=int(hits or 0),
        )


class DNSCache:
    """SQLite-backed DNS answer cache.

    Every method is synchronous and cheap; call the ``*_async`` wrappers from
    coroutines so the (tiny) disk work never blocks the event loop.
    """

    def __init__(
        self,
        path: Path | None = None,
        *,
        enabled: bool = True,
        positive_ttl: int = DEFAULT_POSITIVE_TTL,
        negative_ttl: int = DEFAULT_NEGATIVE_TTL,
        error_ttl: int = DEFAULT_ERROR_TTL,
    ) -> None:
        self.path = Path(path or (CACHE_DIR / "dns-cache.sqlite3"))
        self.enabled = enabled
        self.positive_ttl = positive_ttl
        self.negative_ttl = negative_ttl
        self.error_ttl = error_ttl
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()
        self.hits = 0
        self.misses = 0
        self.writes = 0
        #: Non-fatal problems, surfaced instead of being swallowed silently.
        self.errors: list[str] = []
        self._ready = False
        #: Write-behind buffer: ``(name, qtype) -> (payload_json, expires_at)``.
        #: ``aput`` enqueues here and a bulk ``executemany`` drains it, so a scan
        #: of thousands of names no longer pays a ``to_thread`` + lock round-trip
        #: per answer.
        self._buffer: dict[tuple[str, str], tuple[str, float]] = {}
        #: Buffer size that triggers an immediate flush inside ``aput``.
        self._flush_size = 400

    # -- lifecycle --------------------------------------------------------- #
    def _connect(self) -> sqlite3.Connection | None:
        if not self.enabled:
            return None
        if self._conn is not None:
            return self._conn
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # check_same_thread=False because writes go through a worker thread
            # (``asyncio.to_thread``); all access is serialised by ``_lock``.
            conn = sqlite3.connect(
                self.path, timeout=5.0, isolation_level=None, check_same_thread=False
            )
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dns_cache (
                    name       TEXT NOT NULL,
                    qtype      TEXT NOT NULL,
                    payload    TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    hits       INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (name, qtype)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_expires ON dns_cache(expires_at)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._conn = conn
            self._ready = True
            return conn
        except Exception as exc:
            self.errors.append(f"connect: {exc.__class__.__name__}: {exc}")
            self.enabled = False
            self._conn = None
            return None

    @property
    def ready(self) -> bool:
        if not self._ready:
            self._connect()
        return self._conn is not None

    def close(self) -> None:
        self._flush_sync()
        if self._conn is not None:
            try:
                self._conn.commit()
                self._conn.close()
            except Exception:
                pass
        self._conn = None

    # -- read / write ------------------------------------------------------ #
    def get(self, name: str, qtype: str) -> CacheEntry | None:
        conn = self._connect()
        if conn is None:
            return None
        try:
            row = conn.execute(
                "SELECT name, qtype, payload, expires_at, hits FROM dns_cache "
                "WHERE name = ? AND qtype = ?",
                (name.strip().lower().rstrip("."), qtype.upper()),
            ).fetchone()
        except Exception:
            return None
        if row is None:
            self.misses += 1
            return None
        entry = CacheEntry.from_row(row)
        if entry.expires_at <= time.time():
            self.misses += 1
            self.delete(name, qtype)
            return None
        self.hits += 1
        return entry

    def _payload(
        self,
        name: str,
        qtype: str,
        *,
        addresses: Iterable[str] = (),
        cnames: Iterable[str] = (),
        error: str | None = None,
        resolver: str | None = None,
        rtt_ms: float = 0.0,
        ttl: int | None = None,
    ) -> tuple[str, str, str, float]:
        """Normalise a write into ``(name, qtype, payload_json, expires_at)``."""
        if ttl is None:
            if error in ("NXDOMAIN", "NOERROR/empty") or (not list(addresses) and error):
                ttl = self.negative_ttl
            elif not addresses:
                ttl = self.negative_ttl
            else:
                ttl = self.positive_ttl
        ttl = max(1, min(int(ttl), 86_400))
        entry = CacheEntry(
            name=name.strip().lower().rstrip("."),
            qtype=qtype.upper(),
            addresses=list(addresses),
            cnames=list(cnames),
            error=error,
            resolver=resolver,
            rtt_ms=rtt_ms,
            expires_at=time.time() + ttl,
        )
        return entry.name, entry.qtype, entry.to_json(), entry.expires_at

    def put(
        self,
        name: str,
        qtype: str,
        *,
        addresses: Iterable[str] = (),
        cnames: Iterable[str] = (),
        error: str | None = None,
        resolver: str | None = None,
        rtt_ms: float = 0.0,
        ttl: int | None = None,
    ) -> None:
        conn = self._connect()
        if conn is None:
            return
        row = self._payload(
            name, qtype, addresses=addresses, cnames=cnames, error=error,
            resolver=resolver, rtt_ms=rtt_ms, ttl=ttl,
        )
        try:
            conn.execute(
                "INSERT OR REPLACE INTO dns_cache"
                "(name, qtype, payload, expires_at, hits) VALUES(?,?,?,?,0)",
                row,
            )
            self.writes += 1
        except Exception as exc:
            self.errors.append(f"put: {exc.__class__.__name__}: {exc}")

    def delete(self, name: str, qtype: str) -> None:
        conn = self._connect()
        if conn is None:
            return
        try:
            conn.execute(
                "DELETE FROM dns_cache WHERE name = ? AND qtype = ?",
                (name.strip().lower().rstrip("."), qtype.upper()),
            )
        except Exception:
            pass

    def purge_expired(self) -> int:
        conn = self._connect()
        if conn is None:
            return 0
        try:
            cursor = conn.execute("DELETE FROM dns_cache WHERE expires_at <= ?", (time.time(),))
            return cursor.rowcount or 0
        except Exception:
            return 0

    def stats(self) -> dict[str, Any]:
        conn = self._connect()
        rows = 0
        negative = 0
        if conn is not None:
            try:
                rows = conn.execute("SELECT COUNT(*) FROM dns_cache").fetchone()[0]
                negative = conn.execute(
                    "SELECT COUNT(*) FROM dns_cache WHERE payload LIKE '%\"addresses\":[]%'"
                    " OR payload LIKE '%NXDOMAIN%'"
                ).fetchone()[0]
            except Exception:
                pass
        total = self.hits + self.misses
        return {
            "enabled": self.enabled and conn is not None,
            "path": str(self.path),
            "entries": rows,
            "negative_entries": negative,
            "hits": self.hits,
            "misses": self.misses,
            "writes": self.writes,
            "hit_rate": round(self.hits / total, 4) if total else 0.0,
            "errors": list(self.errors[-5:]),
        }

    # -- async wrappers ---------------------------------------------------- #
    async def aget(self, name: str, qtype: str) -> CacheEntry | None:
        """Read one answer, checking the write-behind buffer first.

        Reads are no longer serialised behind writes: only the in-memory buffer
        is consulted under the lock, and a disk miss falls through to a plain
        ``to_thread`` read.
        """
        key = (name.strip().lower().rstrip("."), qtype.upper())
        async with self._lock:
            row = self._buffer.get(key)
        if row is not None:
            payload, expires_at = row
            if expires_at > time.time():
                self.hits += 1
                return CacheEntry.from_row(
                    (key[0], key[1], payload, expires_at, 0)
                )
            async with self._lock:
                self._buffer.pop(key, None)
        return await asyncio.to_thread(self.get, name, qtype)

    async def aput(self, name: str, qtype: str, **kwargs: Any) -> None:
        """Enqueue one answer for a bulk flush instead of writing immediately."""
        row = self._payload(name, qtype, **kwargs)
        async with self._lock:
            self._buffer[(row[0], row[1])] = (row[2], row[3])
            self.writes += 1
            pending = len(self._buffer)
        if pending >= self._flush_size:
            await self.flush()

    async def flush(self) -> int:
        """Drain the write-behind buffer in a single ``executemany``."""
        async with self._lock:
            rows = list(self._buffer.items())
            self._buffer.clear()
        if not rows:
            return 0
        data = [(key[0], key[1], payload, expires) for key, (payload, expires) in rows]

        def _write() -> int:
            conn = self._connect()
            if conn is None:
                return 0
            try:
                conn.executemany(
                    "INSERT OR REPLACE INTO dns_cache"
                    "(name, qtype, payload, expires_at, hits) VALUES(?,?,?,?,0)",
                    data,
                )
                return len(data)
            except Exception as exc:
                self.errors.append(f"flush: {exc.__class__.__name__}: {exc}")
                return 0

        return await asyncio.to_thread(_write)

    def _flush_sync(self) -> None:
        """Synchronous flush used by :meth:`close` (no event loop available)."""
        if not self._buffer:
            return
        rows = list(self._buffer.items())
        self._buffer.clear()
        conn = self._connect()
        if conn is None:
            return
        try:
            conn.executemany(
                "INSERT OR REPLACE INTO dns_cache"
                "(name, qtype, payload, expires_at, hits) VALUES(?,?,?,?,0)",
                [(key[0], key[1], payload, expires) for key, (payload, expires) in rows],
            )
        except Exception as exc:
            self.errors.append(f"flush: {exc.__class__.__name__}: {exc}")

    async def apurge(self) -> int:
        return await asyncio.to_thread(self.purge_expired)
