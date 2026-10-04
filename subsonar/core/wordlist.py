"""SecLists wordlist streaming + local caching.

The official *SecLists* DNS wordlist is streamed directly from the raw GitHub
repository, never downloaded by hand.  The file is cached under
``.subsonar_cache/`` and reused on subsequent runs; when the network is
unavailable the cached copy is used automatically, and a small embedded
seed list guarantees the scanner still works from a cold start.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

try:  # pragma: no cover
    import aiohttp

    AIOHTTP_AVAILABLE = True
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore[assignment]
    AIOHTTP_AVAILABLE = False

from .config import CACHE_DIR, SECLISTS_FALLBACK_URLS, SECLISTS_URL, USER_AGENT
from .events import BUS, EventBus
from .wordlists import WordlistSpec, mirror_urls

CACHE_MAX_AGE_DAYS = 30

#: Minimal built-in seed list — used only when the network *and* the cache are
#: both unavailable, so a scan never fails outright.
EMBEDDED_SEED: tuple[str, ...] = (
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp",
    "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal", "ns", "ww1",
    "host", "support", "dev", "web", "bbs", "mx", "email", "cloud", "1", "2",
    "3", "mail1", "api", "admin", "staging", "app", "static", "cdn", "img",
    "media", "assets", "docs", "git", "gitlab", "jenkins", "ci", "stage",
    "demo", "beta", "intranet", "internal", "monitor", "status", "grafana",
    "kibana", "prometheus", "nagios", "zabbix", "jenkins2", "jira", "confluence",
    "wiki", "db", "mysql", "postgres", "redis", "mongo", "elastic", "kafka",
    "rabbitmq", "s3", "storage", "backup", "proxy", "gateway", "router",
    "firewall", "dns", "dns1", "dns2", "ldap", "auth", "sso", "oauth", "id",
    "login", "signin", "register", "account", "accounts", "billing", "pay",
    "payments", "checkout", "cart", "store", "catalog", "search", "help",
    "kb", "faq", "forum", "community", "chat", "meet", "video", "stream",
    "live", "tv", "radio", "news", "press", "careers", "jobs", "hr", "crm",
    "erp", "sap", "oracle", "sql", "report", "reports", "analytics", "bi",
    "data", "warehouse", "etl", "queue", "worker", "cron", "scheduler",
    "k8s", "kube", "kubernetes", "docker", "registry", "harbor", "vault",
    "consul", "nomad", "terraform", "ansible", "puppet", "chef", "salt",
    "node1", "node2", "node3", "web1", "web2", "web3", "app1", "app2",
    "db1", "db2", "cache", "session", "log", "logs", "metrics", "trace",
    "alert", "alerts", "pager", "oncall", "ops", "sre", "it", "tech",
    "engineering", "product", "sales", "marketing", "partners", "vendor",
    "suppliers", "extranet", "partner", "client", "clients", "customer",
    "legacy", "old", "new", "v2", "v3", "api-v2", "api2", "graphql", "rest",
    "ws", "socket", "push", "notify", "sms", "voice", "call", "fax",
    "print", "scanner", "camera", "iot", "edge", "fog", "sensor", "device",
    "devices", "lab", "sandbox", "qa", "uat", "preprod", "prod", "production",
)


@dataclass
class WordlistResult:
    """Outcome of a wordlist acquisition."""

    words: list[str] = field(default_factory=list)
    source: str = "embedded"
    #: Registry name of the list the labels came from (``seclists-top1m``, …).
    wordlist: str = ""
    cached_path: Path | None = None
    downloaded_bytes: int = 0
    from_cache: bool = False
    truncated_from: int = 0

    @property
    def size(self) -> int:
        return len(self.words)

    def to_dict(self) -> dict[str, Any]:
        return {
            "size": self.size,
            "wordlist": self.wordlist,
            "source": self.source,
            "cached_path": str(self.cached_path) if self.cached_path else None,
            "downloaded_bytes": self.downloaded_bytes,
            "from_cache": self.from_cache,
            "truncated_from": self.truncated_from,
        }


def cache_path_for(url: str, cache_dir: Path | None = None) -> Path:
    name = url.rstrip("/").split("/")[-1] or "seclists.txt"
    directory = Path(cache_dir or CACHE_DIR)
    return directory / f"seclists-{name}"


def parse_wordlist(text: str, *, limit: int | None = None, domain: str = "") -> list[str]:
    """Normalise wordlist lines into unique candidate labels.

    When *domain* is supplied, fully-qualified entries are reduced to their
    leading label and out-of-scope names are dropped.
    """
    seen: set[str] = set()
    words: list[str] = []
    domain = (domain or "").strip().lower().rstrip(".")
    suffix = f".{domain}" if domain else ""
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        if line.startswith(".") or line.endswith(".") or ".." in line:
            # Malformed entries such as "bad..host" are dropped outright.
            continue
        if domain:
            if line == domain:
                continue
            if suffix and line.endswith(suffix):
                line = line[: -len(suffix)]
        if "." in line:
            # Full hostname entries keep their first label only when in scope.
            line = line.split(".")[0]
        if not line or len(line) > 63:
            continue
        if not all(ch.isalnum() or ch in "-_" for ch in line):
            continue
        if line in seen:
            continue
        seen.add(line)
        words.append(line)
        if limit is not None and len(words) >= limit:
            break
    return words


class WordlistManager:
    """Streams, caches and slices the SecLists DNS wordlist."""

    def __init__(
        self,
        *,
        spec: "WordlistSpec | None" = None,
        url: str = SECLISTS_URL,
        fallbacks: Sequence[str] = SECLISTS_FALLBACK_URLS,
        cache_dir: Path | None = None,
        bus: EventBus | None = None,
        timeout: float = 90.0,
        max_age_days: int = CACHE_MAX_AGE_DAYS,
    ) -> None:
        self.spec = spec
        self.cache_dir = Path(cache_dir or CACHE_DIR)
        self.bus = bus or BUS
        self.timeout = timeout
        self.max_age_days = max_age_days
        self._memo: dict[int, list[str]] = {}
        if spec is not None and spec.builtin:
            # Packaged list: nothing to stream, nothing to cache.
            self.url = ""
            self.fallbacks = ()
        elif spec is not None:
            # Registry list: the chosen source, then CDN mirrors of the *same*
            # file, then the legacy smaller-list fallbacks.
            self.url = spec.source
            self.fallbacks = tuple(mirror_urls(spec)) + tuple(SECLISTS_FALLBACK_URLS)
        else:
            self.url = url
            self.fallbacks = tuple(fallbacks)

    # -- identity ---------------------------------------------------------- #
    @property
    def name(self) -> str:
        """Registry name of the list in use (falls back to the file name)."""
        if self.spec is not None:
            return self.spec.name
        return self.url.rstrip("/").split("/")[-1] or "wordlist"

    @property
    def builtin_path(self) -> Path | None:
        """Packaged file for a built-in list (``None`` for streamed lists)."""
        if self.spec is None or not self.spec.builtin:
            return None
        path = self.spec.path
        return path if path is not None and path.is_file() else None

    # -- cache ------------------------------------------------------------- #
    def cached_file(self) -> Path:
        if self.spec is not None and self.spec.builtin:
            packaged = self.builtin_path
            return packaged if packaged is not None else self.cache_dir / self.spec.filename
        return cache_path_for(self.url, self.cache_dir)

    def cache_is_fresh(self) -> bool:
        if self.spec is not None and self.spec.builtin:
            return self.builtin_path is not None  # ships with the package
        path = self.cached_file()
        if not path.exists():
            return False
        age = time.time() - path.stat().st_mtime
        return age < self.max_age_days * 86400

    def cached_size(self) -> int:
        path = self.cached_file()
        return path.stat().st_size if path.exists() else 0

    # -- acquisition ------------------------------------------------------- #
    async def acquire(
        self,
        *,
        prefer_cache: bool = False,
        offline: bool = False,
        refresh: bool = False,
    ) -> Path | None:
        """Ensure a wordlist file exists locally; returns its path."""
        if self.spec is not None and self.spec.builtin:
            packaged = self.builtin_path
            if packaged is None:
                self.bus.warn(
                    f"Built-in wordlist {self.name} is missing from the package — "
                    f"using the embedded seed list"
                )
                return None
            self.bus.emit(
                f"Using built-in wordlist {self.name} "
                f"({_human(packaged.stat().st_size)}, no download needed)",
                "info",
                "wordlist",
            )
            return packaged

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        path = self.cached_file()
        if offline:
            if path.exists():
                self.bus.emit(
                    f"Offline mode — using cached {self.name} "
                    f"({_human(path.stat().st_size)})",
                    "info",
                    "wordlist",
                )
                return path
            self.bus.warn("Offline mode and no cached wordlist — using embedded seed list")
            return None
        if path.exists() and self.cache_is_fresh() and not refresh:
            self.bus.emit(
                f"Wordlist cache hit — {self.name} ({path.name}, "
                f"{_human(path.stat().st_size)}, {_age_days(path):.1f} days old)",
                "info",
                "wordlist",
            )
            return path
        if path.exists() and not refresh and prefer_cache:
            return path

        for url in (self.url, *self.fallbacks):
            # Every mirror caches to the canonical path, otherwise a fallback
            # download lands under a name ``cached_file()`` never looks at — the
            # cache never goes fresh and the file is re-downloaded every run.
            streamed = await self._stream(url, path)
            if streamed is not None:
                return streamed
        if path.exists():
            self.bus.warn(
                f"All mirrors for {self.name} unreachable — falling back to cached "
                f"{path.name} ({_human(path.stat().st_size)})"
            )
            return path
        self.bus.warn(
            f"Wordlist {self.name} unavailable — using the embedded seed list"
        )
        return None

    async def _stream(self, url: str, destination: Path | None) -> Path | None:
        if not AIOHTTP_AVAILABLE:
            self.bus.warn("aiohttp unavailable — cannot stream SecLists")
            return None
        name = url.rstrip("/").split("/")[-1]
        self.bus.emit(
            f"Streaming SecLists wordlist from raw.githubusercontent.com — {name}",
            "info",
            "wordlist",
        )
        started = time.time()
        total = 0
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout, connect=15, sock_read=30)
            async with aiohttp.ClientSession(
                timeout=timeout,
                headers={"User-Agent": USER_AGENT},
                trust_env=False,
            ) as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        self.bus.warn(
                            f"SecLists mirror returned HTTP {response.status} — {name}"
                        )
                        return None
                    tmp = self.cache_dir / f".{name}.part"
                    with open(tmp, "wb") as handle:
                        async for chunk in response.content.iter_chunked(65536):
                            handle.write(chunk)
                            total += len(chunk)
                            if total % (1024 * 1024) < 65536:
                                self.bus.emit(
                                    f"SecLists download progress — {_human(total)} "
                                    f"({time.time() - started:.1f}s)",
                                    "debug",
                                    "wordlist",
                                )
            if total <= 0:
                self.bus.warn(f"SecLists mirror returned an empty body — {name}")
                tmp.unlink(missing_ok=True)
                return None
            path = destination or (self.cache_dir / f"seclists-{name}")
            os.replace(tmp, path)
            self.bus.emit(
                f"SecLists wordlist cached — {path.name} "
                f"({_human(total)} in {time.time() - started:.1f}s)",
                "success",
                "wordlist",
                path=str(path),
            )
            return path
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            (self.cache_dir / f".{name}.part").unlink(missing_ok=True)
            self.bus.warn(
                f"SecLists stream failed for {name} "
                f"({exc.__class__.__name__}: {exc})"
            )
            return None

    # -- slicing ----------------------------------------------------------- #
    async def load(
        self,
        limit: int,
        *,
        domain: str = "",
        offline: bool = False,
        refresh: bool = False,
    ) -> WordlistResult:
        """Return the first *limit* candidate labels of the wordlist."""
        if limit in self._memo and self._memo[limit]:
            words = list(self._memo[limit])
            return WordlistResult(
                words=words,
                source="memo",
                wordlist=self.name,
                from_cache=True,
            )
        path = await self.acquire(offline=offline, refresh=refresh)
        result = WordlistResult(cached_path=path, wordlist=self.name)
        raw_words: list[str] = []
        if path is not None and path.exists():
            text = await asyncio.to_thread(_read_text, path)
            raw_words = parse_wordlist(text, domain=domain)
            result.source = path.name
            result.from_cache = True
            result.downloaded_bytes = path.stat().st_size
        if len(raw_words) < limit:
            # Top up with the embedded seed list (order-preserving).
            seen = set(raw_words)
            for word in EMBEDDED_SEED:
                if len(raw_words) >= limit:
                    break
                if word not in seen:
                    seen.add(word)
                    raw_words.append(word)
            result.source = result.source if path else "embedded"
        result.truncated_from = len(raw_words)
        result.words = raw_words[:limit]
        if result.words:
            self._memo[limit] = list(result.words)
        self.bus.emit(
            f"Wordlist ready — {len(result.words)} candidate label(s) from "
            f"{self.name} ({result.source})",
            "info",
            "wordlist",
        )
        return result

    def embedded(self, limit: int | None = None) -> list[str]:
        words = list(EMBEDDED_SEED)
        return words[:limit] if limit else words


def _read_text(path: Path) -> str:
    for encoding in ("utf-8", "latin-1"):
        try:
            with open(path, "r", encoding=encoding, errors="strict") as handle:
                return handle.read()
        except UnicodeDecodeError:
            continue
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return handle.read()


def _human(size: float) -> str:
    """Format a byte count for the live log."""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _age_days(path: Path) -> float:
    return (time.time() - path.stat().st_mtime) / 86400
