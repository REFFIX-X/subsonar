"""Plugin base class, registry and merge helper for discovery sources.

A *discovery source* is any :class:`DiscoverySource` subclass that knows how to
stream hostnames for a target domain.  Plugins live next to this module as
``subsonar/core/sources/<name>.py`` and are imported automatically by
:func:`discover_plugins` (called once from the package ``__init__``), so adding a
new source never requires touching the engine, the scanner or any other module.

Contract every plugin inherits from this base (plugins do **not** re-implement
it):

* hostnames are validated with :func:`subsonar.core.osint.is_valid_hostname`
  against the scanned domain, so out-of-scope / malformed entries are dropped,
* results are de-duplicated per fetch,
* a start event (``Querying X asynchronously...``) and a count summary are
  emitted on the :class:`~subsonar.core.events.EventBus`,
* network and parse failures are caught, logged as warnings and end the stream,
* :class:`asyncio.CancelledError` is always re-raised,
* an injected ``aiohttp.ClientSession`` is reused and never closed; a session
  created by the source itself is closed when the fetch ends,
* the result count is capped (:attr:`DiscoverySource.max_results`, 5000) and the
  whole fetch is bounded by :attr:`DiscoverySource.timeout` (< 60 s).

A plugin therefore only has to implement :meth:`DiscoverySource.fetch_hosts`
plus a pure ``parse_*`` function that converts a raw payload into hostnames.
"""

from __future__ import annotations

import asyncio
import copy
import importlib
import ipaddress
import logging
import pkgutil
import sys
import warnings
from typing import Any, AsyncIterator, Iterable

try:  # pragma: no cover - mirrors subsonar.core.osint
    import aiohttp

    AIOHTTP_AVAILABLE = True
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore[assignment]
    AIOHTTP_AVAILABLE = False

from ..config import USER_AGENT
from ..events import BUS, EventBus
from ..osint import OSINTResult, SourceReport, is_valid_hostname

_log = logging.getLogger("subsonar.sources")

#: Hard ceiling on the number of hostnames a single source may emit.
MAX_RESULTS_DEFAULT = 5000
#: Per-source wall-clock budget — deliberately below the 60 s contract.
DEFAULT_TIMEOUT_SECONDS = 45.0
#: Budget for merging several sources through :func:`collect`.
MERGE_TIMEOUT_SECONDS = 50.0

#: ``name -> registered instance`` for every discovered plugin.
REGISTRY: dict[str, "DiscoverySource"] = {}

_SENTINEL = object()


# --------------------------------------------------------------------------- #
# Discovery source base class
# --------------------------------------------------------------------------- #


class DiscoverySource:
    """Base class for one free, no-signup OSINT discovery plugin."""

    #: Registry key and live-log label.  Filled in by :func:`register`.
    name: str = ""
    #: True when the source needs no payment (all bundled sources are free).
    free: bool = True
    #: True when the source cannot answer without a user-supplied API key.
    requires_key: bool = False
    #: Environment variable consulted by key-based plugins.
    env_var: str | None = None
    #: One-line human description for the CLI / TUI.
    description: str = ""

    #: Per-source result ceiling and wall-clock budget (overridable per class).
    MAX_RESULTS: int = MAX_RESULTS_DEFAULT
    DEFAULT_TIMEOUT: float = DEFAULT_TIMEOUT_SECONDS

    def __init__(
        self,
        *,
        session: Any | None = None,
        bus: EventBus | None = None,
        timeout: float | None = None,
        max_results: int | None = None,
        resolver: Any | None = None,
    ) -> None:
        self.session = session
        self.bus = bus or BUS
        self.timeout = (
            float(timeout) if timeout is not None else float(self.DEFAULT_TIMEOUT)
        )
        self.max_results = (
            int(max_results) if max_results is not None else int(self.MAX_RESULTS)
        )
        #: Optional ``AnonymousResolver`` used only when a payload lacks an IP.
        self.resolver = resolver
        self.report = SourceReport(self.name or type(self).__name__)
        self._owns_session = session is None

    # -- plugin metadata ---------------------------------------------------- #
    def available(self) -> bool:
        """Return ``False`` when the source cannot run right now.

        The base implementation always allows the source to run.  Plugins that
        need an API key or an optional dependency override this and consult
        :attr:`env_var` (see also :attr:`requires_key`).
        """
        return True

    def clone(self, **overrides: Any) -> "DiscoverySource":
        """Shallow copy of this source with constructor-style overrides applied.

        Used by :func:`collect` so a shared/registry instance is never mutated.
        A shallow copy keeps extra plugin state (e.g. test doubles holding
        canned hostnames) intact.
        """
        clone = copy.copy(self)
        clone.report = SourceReport(self.name or type(self).__name__)
        for key, value in overrides.items():
            setattr(clone, key, value)
        if overrides.get("session") is not None:
            # An injected session belongs to the caller — never close it.
            clone._owns_session = False
        return clone

    # -- lifecycle ---------------------------------------------------------- #
    async def __aenter__(self) -> "DiscoverySource":
        await self.ensure_session()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def ensure_session(self) -> Any | None:
        """Return a usable session, creating one only when necessary."""
        if self.session is not None:
            return self.session
        if not AIOHTTP_AVAILABLE:
            self.bus.warn(
                "aiohttp unavailable — discovery sources disabled",
                source=self.name,
            )
            return None
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout, connect=10),
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json, text/plain, */*",
            },
            trust_env=False,
        )
        self._owns_session = True
        return self.session

    async def close(self) -> None:
        """Close the session — but only when this source created it."""
        session = self.session
        if session is None or not self._owns_session:
            return
        self.session = None
        try:
            await session.close()
        except Exception:  # pragma: no cover - close() must never raise
            pass

    # -- HTTP helpers ------------------------------------------------------- #
    async def get_text(self, url: str) -> tuple[int, str]:
        """GET *url* and return ``(status, body)`` (tolerant of any status)."""
        session = await self.ensure_session()
        if session is None:
            raise RuntimeError("aiohttp is not available")
        self.report.requests += 1
        async with session.get(url) as response:
            status = int(getattr(response, "status", 0) or 0)
            text = await response.text()
        return status, text

    async def get_json(self, url: str) -> tuple[int, Any]:
        """GET *url* and return ``(status, payload)``; payload is None on error."""
        session = await self.ensure_session()
        if session is None:
            raise RuntimeError("aiohttp is not available")
        self.report.requests += 1
        async with session.get(url) as response:
            status = int(getattr(response, "status", 0) or 0)
            if status != 200:
                return status, None
            try:
                return status, await response.json(content_type=None)
            except Exception:
                return status, None

    # -- plugin hook -------------------------------------------------------- #
    async def fetch_hosts(self, domain: str) -> AsyncIterator[Any]:
        """Yield raw hostnames (or ``(host, ip)`` pairs) for *domain*.

        Plugins implement this; everything else (validation, de-duplication,
        events, error handling, session handling, caps) is done by :meth:`fetch`.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.fetch_hosts() is not implemented"
        )
        yield  # pragma: no cover - unreachable; marks this an async generator

    # -- public streaming API ----------------------------------------------- #
    async def fetch(self, domain: str) -> AsyncIterator[OSINTResult]:
        """Stream validated, de-duplicated :class:`OSINTResult` objects."""
        target = str(domain).strip().lower().rstrip(".")
        self.report = SourceReport(self.name or type(self).__name__)
        loop = asyncio.get_running_loop()
        started = loop.time()
        self.bus.osint(
            f"Querying {self.name} asynchronously...", host=target, source=self.name
        )
        seen: set[str] = set()
        count = 0
        try:
            if not self.available():
                self.report.note = "unavailable"
                self.bus.warn(
                    f"{self.name} is unavailable (missing API key or dependency) — "
                    f"skipping",
                    host=target,
                    source=self.name,
                )
                return
            if await self.ensure_session() is None:
                self.report.note = "aiohttp unavailable"
                return
            async for entry in self.fetch_hosts(target):
                host, ip = _split_entry(entry)
                host = host.strip().lower().lstrip("*.").rstrip(".")
                if host in seen or not is_valid_hostname(host, target):
                    continue
                seen.add(host)
                count += 1
                self.report.hosts = count
                if ip is None and self.resolver is not None:
                    ip = await self._resolve_ip(host)
                yield OSINTResult(
                    host=host, source=self.name, target=target, ip=ip
                )
                if count >= self.max_results:
                    self.report.note = f"capped at {self.max_results}"
                    self.bus.warn(
                        f"{self.name} result cap reached ({self.max_results}) — "
                        f"truncating",
                        host=target,
                        source=self.name,
                    )
                    break
            if count == 0 and self.report.note is None:
                self.report.note = "no data returned"
            self.bus.osint(
                f"{self.name} returned {count} in-scope hostname(s) for {target}",
                host=target,
                source=self.name,
                count=count,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.report.errors += 1
            self.bus.warn(
                f"{self.name} query failed ({exc.__class__.__name__}: {exc})",
                host=target,
                source=self.name,
            )
            return
        finally:
            self.report.duration += loop.time() - started
            await self.close()

    async def _resolve_ip(self, host: str) -> str | None:
        """Optional hostname -> IP enrichment via an injected resolver."""
        try:
            answer = await self.resolver.resolve(host, log=False)
        except asyncio.CancelledError:
            raise
        except Exception:
            return None
        return getattr(answer, "ip", None)


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


def register(
    target: Any = None, *, name: str | None = None, replace: bool = False
) -> Any:
    """Register a :class:`DiscoverySource` subclass (decorator).

    Usable bare (``@register``) or parameterised (``@register("my-name")``).
    The first registration for a name wins unless ``replace=True``.
    """

    def _register(cls: type[DiscoverySource]) -> type[DiscoverySource]:
        if not isinstance(cls, type) or not issubclass(cls, DiscoverySource):
            raise TypeError("register() expects a DiscoverySource subclass")
        key = str(name or getattr(cls, "name", "") or cls.__name__).strip().lower()
        if not key:
            raise ValueError("discovery source needs a non-empty name")
        cls.name = key
        if key in REGISTRY and not replace:
            warnings.warn(
                f"discovery source {key!r} is already registered — keeping the "
                f"first definition",
                RuntimeWarning,
                stacklevel=3,
            )
            return cls
        REGISTRY[key] = cls()
        _log.debug("registered discovery source %s (%s)", key, cls.__module__)
        return cls

    if target is None:
        return _register
    if isinstance(target, str):
        name = target
        return _register
    return _register(target)


def get_source(name: str) -> DiscoverySource:
    """Return the registered instance for *name* (raises ``KeyError``)."""
    key = str(name).strip().lower()
    try:
        return REGISTRY[key]
    except KeyError:
        raise KeyError(
            f"unknown discovery source {name!r} "
            f"(known: {', '.join(sorted(REGISTRY)) or 'none'})"
        ) from None


def all_sources() -> list[DiscoverySource]:
    """Every registered source, ordered by name."""
    return [REGISTRY[key] for key in sorted(REGISTRY)]


def free_sources() -> list[DiscoverySource]:
    """Registered sources that are free *and* currently usable."""
    return [source for source in all_sources() if source.free and source.available()]


def discover_plugins(package: str | None = None) -> list[str]:
    """Import every non-underscore module in this package and register it.

    A plugin that raises on import is logged and skipped — one broken source can
    never break the package or the engine.
    """
    package = package or __name__.rsplit(".", 1)[0]
    module = sys.modules.get(package)
    paths = getattr(module, "__path__", None)
    if paths is None:  # pragma: no cover - only when called with a bad package
        return []
    loaded: list[str] = []
    for info in pkgutil.iter_modules(paths):
        if info.name.startswith("_"):
            continue
        try:
            importlib.import_module(f"{package}.{info.name}")
            loaded.append(info.name)
        except Exception as exc:  # pragma: no cover - defensive
            _log.warning("discovery plugin %s failed to import: %s", info.name, exc)
    return sorted(loaded)


# --------------------------------------------------------------------------- #
# Merge helper
# --------------------------------------------------------------------------- #


def _coerce_source(
    raw: Any,
    *,
    bus: EventBus | None,
    session: Any | None,
    source_timeout: float | None,
    max_results: int | None,
) -> DiscoverySource:
    source = get_source(raw) if isinstance(raw, str) else raw
    if isinstance(source, type) and issubclass(source, DiscoverySource):
        source = source()
    if not isinstance(source, DiscoverySource):
        raise TypeError(f"not a discovery source: {raw!r}")
    overrides: dict[str, Any] = {}
    if bus is not None:
        overrides["bus"] = bus
    if session is not None:
        overrides["session"] = session
    if source_timeout is not None:
        overrides["timeout"] = source_timeout
    if max_results is not None:
        overrides["max_results"] = max_results
    return source.clone(**overrides) if overrides else source


async def collect(
    sources: Iterable[Any],
    domain: str,
    *,
    bus: EventBus | None = None,
    timeout: float = MERGE_TIMEOUT_SECONDS,
    session: Any | None = None,
    source_timeout: float | None = None,
    max_results: int | None = None,
) -> AsyncIterator[OSINTResult]:
    """Merge *sources* concurrently, tolerating individual failures.

    ``sources`` accepts registry names, :class:`DiscoverySource` subclasses or
    instances.  Sources run as independent tasks; a source that raises, hangs or
    returns nothing is cancelled/logged without disturbing the others, and the
    merged stream ends when every source is done or *timeout* expires.
    """
    target = str(domain).strip().lower().rstrip(".")
    events = bus or BUS
    instances: list[DiscoverySource] = []
    for raw in sources:
        try:
            instances.append(
                _coerce_source(
                    raw,
                    bus=bus,
                    session=session,
                    source_timeout=source_timeout,
                    max_results=max_results,
                )
            )
        except KeyError as exc:
            events.warn(f"Discovery source skipped: {exc.args[0]}", host=target)
        except Exception as exc:
            events.warn(
                f"Discovery source skipped ({exc.__class__.__name__}: {exc})",
                host=target,
            )
    if not instances:
        return

    queue: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()

    async def pump(source: DiscoverySource) -> None:
        try:
            async for result in source.fetch(target):
                await queue.put((source.name, result))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            events.warn(
                f"{source.name} discovery source aborted "
                f"({exc.__class__.__name__}: {exc})",
                host=target,
                source=source.name,
            )
        finally:
            queue.put_nowait((source.name, _SENTINEL))

    tasks = [
        asyncio.create_task(pump(source), name=f"discover:{source.name}")
        for source in instances
    ]
    pending = len(tasks)
    total = 0
    loop = asyncio.get_running_loop()
    budget = max(0.05, float(timeout))
    deadline = loop.time() + budget
    try:
        while pending > 0:
            remaining = deadline - loop.time()
            if remaining <= 0:
                events.warn(
                    f"Discovery merge exceeded its {budget:g}s budget — "
                    f"{pending} source(s) still running",
                    host=target,
                )
                break
            try:
                _name, item = await asyncio.wait_for(queue.get(), timeout=remaining)
            except TimeoutError:
                events.warn(
                    f"Discovery merge exceeded its {budget:g}s budget — "
                    f"{pending} source(s) still running",
                    host=target,
                )
                break
            if item is _SENTINEL:
                pending -= 1
                continue
            total += 1
            yield item
        events.osint(
            f"Discovery merge produced {total} in-scope hostname(s) from "
            f"{len(tasks)} source(s) for {target}",
            host=target,
            count=total,
        )
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _split_entry(entry: Any) -> tuple[str, str | None]:
    """Normalise a plugin entry into ``(host, ip_or_None)``."""
    if isinstance(entry, (tuple, list)):
        host = entry[0] if entry else ""
        ip = entry[1] if len(entry) > 1 else None
        return str(host or ""), _clean_ip(ip)
    return str(entry or ""), None


def _clean_ip(value: Any) -> str | None:
    """Return *value* when it is a literal IP address, else ``None``."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return None
    return text


__all__ = [
    "AIOHTTP_AVAILABLE",
    "DEFAULT_TIMEOUT_SECONDS",
    "DiscoverySource",
    "MAX_RESULTS_DEFAULT",
    "MERGE_TIMEOUT_SECONDS",
    "REGISTRY",
    "all_sources",
    "collect",
    "discover_plugins",
    "free_sources",
    "get_source",
    "register",
]
