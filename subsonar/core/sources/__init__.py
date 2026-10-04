"""Auto-discovered discovery-source plugins for subsonar.

Usage::

    from subsonar.core.sources import REGISTRY, collect, get_source

    async for result in collect(["certspotter", "urlscan"], "example.com", bus=bus):
        print(result.host, result.source)

Adding a source is a matter of dropping ``<name>.py`` into this directory with a
:class:`DiscoverySource` subclass decorated with :func:`register`; the module is
imported automatically below and appears in :data:`REGISTRY`.

The import of ``aiohttp`` is guarded (exactly like :mod:`subsonar.core.osint`), so
this package still imports on a machine without the optional HTTP client; the
sources then simply report themselves as unavailable.
"""

from __future__ import annotations

from ._base import (
    AIOHTTP_AVAILABLE,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_RESULTS_DEFAULT,
    MERGE_TIMEOUT_SECONDS,
    REGISTRY,
    DiscoverySource,
    all_sources,
    collect,
    discover_plugins,
    free_sources,
    get_source,
    register,
)

__all__ = [
    "AIOHTTP_AVAILABLE",
    "DEFAULT_TIMEOUT_SECONDS",
    "DISCOVERED",
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

#: Modules imported by the automatic plugin discovery (filled in below).
DISCOVERED: list[str] = discover_plugins()
