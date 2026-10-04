"""Asynchronous TCP/TLS port scanner.

Probing strategy
----------------
The scanner uses **port-major scheduling**: work is queued as ``(host, port)``
pairs and drained by a single pool of workers, instead of fanning one host's 50
ports out and waiting for the slowest.  A host with one filtered port can no
longer idle a worker slot, which is the dominant cost on firewalled targets.

Timeouts are **adaptive**.  A filtered port costs the probe's timeout, so the
first pass uses a short timeout (:data:`DEFAULT_FAST_TIMEOUT`) and only ports
that timed out are retried with the full timeout (:data:`DEFAULT_SLOW_TIMEOUT`)
— and only if the host showed any sign of life.  Refused ports return instantly
so they are never retried.

The probe itself is a non-blocking ``connect()``; no raw SYN is emitted (that
needs administrator/root and breaks behind NAT).  On connect the socket is
opportunistically upgraded to TLS to fingerprint the service (TLS version,
cipher, certificate CN/SAN) and a short banner read is attempted.
"""

from __future__ import annotations

import asyncio
import random
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from .config import PORT_MATRIX, TLS_FIRST_PORTS
from .events import BUS, EventBus
from .ratelimit import RateLimiter
from .services import detect_service

#: First-pass timeout.  Most filtered ports cost exactly this much, so it is
#: deliberately aggressive; anything that times out is retried slowly.
DEFAULT_FAST_TIMEOUT = 0.45

#: Second-pass timeout for ports that timed out on a host that showed life.
DEFAULT_SLOW_TIMEOUT = 1.8

#: Default number of hosts swept together in one port-major batch.
DEFAULT_HOST_BATCH = 32

#: Failure classifications for a closed/unusable port.
MODE_OPEN = "open"
MODE_REFUSED = "refused"
MODE_TIMEOUT = "timeout"
MODE_ERROR = "error"


@dataclass(slots=True)
class PortResult:
    """Outcome of a single TCP probe."""

    host: str
    ip: str
    port: int
    label: str
    open: bool
    failure: str = MODE_REFUSED
    latency_ms: float = 0.0
    timeout_used: float = 0.0
    attempt: int = 1
    tls: bool = False
    tls_version: str | None = None
    tls_cipher: str | None = None
    cert_subject: str | None = None
    cert_sans: list[str] = field(default_factory=list)
    cert_expired: bool | None = None
    banner: str | None = None
    error: str | None = None

    #: Best-effort protocol identification from the banner (SSH, Redis, SMTP,
    #: FTP, MySQL, …) for ports that do not speak HTTP.
    service: str | None = None

    @property
    def timed_out(self) -> bool:
        return self.failure == MODE_TIMEOUT

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "ip": self.ip,
            "port": self.port,
            "label": self.label,
            "open": self.open,
            "failure": self.failure,
            "latency_ms": round(self.latency_ms, 1),
            "tls": self.tls,
            "tls_version": self.tls_version,
            "tls_cipher": self.tls_cipher,
            "cert_subject": self.cert_subject,
            "cert_sans": self.cert_sans,
            "cert_expired": self.cert_expired,
            "banner": self.banner,
            "error": self.error,
            "service": self.service,
        }


@dataclass(slots=True)
class SweepStats:
    """Instrumentation for the port phase."""

    probes: int = 0
    opens: int = 0
    refused: int = 0
    timeouts: int = 0
    errors: int = 0
    retries: int = 0
    batches: int = 0
    duration: float = 0.0
    #: How much the connect rate limiter paced the sweep.
    rate_waits: int = 0
    rate_wait_seconds: float = 0.0

    @property
    def rate(self) -> float:
        return self.probes / self.duration if self.duration > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "probes": self.probes,
            "opens": self.opens,
            "refused": self.refused,
            "timeouts": self.timeouts,
            "errors": self.errors,
            "retries": self.retries,
            "batches": self.batches,
            "duration": round(self.duration, 3),
            "probes_per_second": round(self.rate, 1),
            "rate_waits": self.rate_waits,
            "rate_wait_seconds": round(self.rate_wait_seconds, 3),
        }


class AsyncPortScanner:
    """Concurrent port-major TCP connect scanner with TLS fingerprinting."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_SLOW_TIMEOUT,
        fast_timeout: float = DEFAULT_FAST_TIMEOUT,
        concurrency: int = 300,
        ports: dict[int, str] | None = None,
        bus: EventBus | None = None,
        stealth_delay: tuple[float, float] = (0.0, 0.0),
        log_attempts: bool = True,
        verify_tls: bool = False,
        adaptive_timeout: bool = True,
        host_batch: int = DEFAULT_HOST_BATCH,
        rate_limit: float = 0.0,
        rate_burst: float | None = None,
        per_host_rate: float = 0.0,
    ) -> None:
        self.timeout = timeout
        self.fast_timeout = min(fast_timeout, timeout)
        self.adaptive_timeout = adaptive_timeout
        self.ports = dict(ports or PORT_MATRIX)
        self.bus = bus or BUS
        self.stealth_delay = stealth_delay
        self.log_attempts = log_attempts
        self.verify_tls = verify_tls
        self.host_batch = max(1, host_batch)
        self._semaphore = asyncio.Semaphore(max(1, concurrency))
        #: Worker count for :meth:`probe_batch` — bounded by the concurrency
        #: limit so the pool can saturate the semaphore without task-per-probe.
        self._pool_size = max(1, concurrency)
        #: Connect pacing — the semaphore bounds in-flight sockets, this bounds
        #: connects/second (globally and per target host), which is what a
        #: firewall/IPS actually measures.
        self.rate_limit = max(0.0, float(rate_limit))
        self.limiter = RateLimiter(
            self.rate_limit,
            burst=rate_burst,
            per_server_rate=max(0.0, float(per_host_rate)),
            per_server_burst=per_host_rate or None,
        )
        self.rate_waits = 0
        self.rate_wait_seconds = 0.0
        self._tls_context = ssl.create_default_context()
        self._tls_context.check_hostname = False
        self._tls_context.verify_mode = ssl.CERT_NONE
        try:  # pragma: no cover - platform dependent
            self._tls_context.set_ciphers("DEFAULT@SECLEVEL=1")
        except ssl.SSLError:
            pass
        self.probes_sent = 0
        self.ports_open = 0
        self.stats = SweepStats()

    # -- single probe ------------------------------------------------------ #
    async def _connect(
        self, ip: str, port: int, timeout: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(
            asyncio.open_connection(host=ip, port=port), timeout=timeout
        )

    async def probe(
        self,
        host: str,
        ip: str,
        port: int,
        *,
        timeout: float | None = None,
        attempt: int = 1,
        verbose: bool | None = None,
    ) -> PortResult:
        """Probe one ``host:port`` and return the result."""
        effective_timeout = timeout or self.timeout
        label = self.ports.get(port, "Unknown")
        result = PortResult(
            host=host, ip=ip, port=port, label=label, open=False,
            timeout_used=effective_timeout, attempt=attempt,
        )
        if self.stealth_delay != (0.0, 0.0):
            lo, hi = self.stealth_delay
            # Randomised, not the midpoint: a constant inter-probe gap is a
            # fingerprint of its own.
            await asyncio.sleep(random.uniform(lo, hi) if hi > lo else lo)
        if self.limiter.enabled:
            # Pace *before* taking a worker slot: a waiting probe must not hold a
            # semaphore permit while it sleeps.
            waited = await self.limiter.acquire(host)
            if waited > 0:
                self.rate_waits += 1
                self.rate_wait_seconds += waited
        log = self.log_attempts if verbose is None else verbose
        async with self._semaphore:
            self.probes_sent += 1
            self.stats.probes += 1
            self.bus.bump("ports_probed")
            if log:
                self.bus.port(
                    f"TCP connect() sent to ://{host} on Port: {port} "
                    f"[{label}] → {ip} (timeout {effective_timeout:.2f}s)",
                    host=host,
                    port=port,
                    ip=ip,
                    label=label,
                )
            started = time.perf_counter()
            writer: asyncio.StreamWriter | None = None
            try:
                reader, writer = await self._connect(ip, port, effective_timeout)
                result.open = True
                result.failure = MODE_OPEN
                result.latency_ms = (time.perf_counter() - started) * 1000
                self.ports_open += 1
                self.stats.opens += 1
                self.bus.bump("ports_open")
                self.bus.port(
                    f"Port OPEN ://{host}:{port} [{label}] — handshake in "
                    f"{result.latency_ms:.0f} ms",
                    host=host,
                    port=port,
                    ip=ip,
                    label=label,
                )
                await self._fingerprint(reader, writer, host, ip, result)
            except asyncio.TimeoutError:
                result.failure = MODE_TIMEOUT
                result.error = "timeout"
                self.stats.timeouts += 1
                self.bus.bump("timeouts")
                if log:
                    self.bus.filtered(
                        f"Timeout on ://{host}:{port} — dropping socket",
                        host=host,
                        port=port,
                        ip=ip,
                    )
            except (ConnectionRefusedError, ConnectionResetError) as exc:
                result.failure = MODE_REFUSED
                result.error = exc.__class__.__name__
                self.stats.refused += 1
                if log:
                    self.bus.filtered(
                        f"Port {port} closed on ://{host} "
                        f"({exc.__class__.__name__})",
                        host=host,
                        port=port,
                        ip=ip,
                    )
            except (OSError, asyncio.IncompleteReadError) as exc:
                result.failure = MODE_ERROR
                result.error = exc.__class__.__name__
                self.stats.errors += 1
                if log:
                    self.bus.filtered(
                        f"Port {port} unreachable on ://{host} "
                        f"({exc.__class__.__name__})",
                        host=host,
                        port=port,
                        ip=ip,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                result.failure = MODE_ERROR
                result.error = f"{exc.__class__.__name__}: {exc}"
                self.stats.errors += 1
                self.bus.bump("errors")
                self.bus.error(
                    f"Socket error on ://{host}:{port} — {result.error}",
                    host=host,
                    port=port,
                    ip=ip,
                )
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
                    except Exception:
                        pass
        return result

    # -- batched probing --------------------------------------------------- #
    async def probe_batch(
        self,
        probes: Sequence[tuple[str, str, int]],
        *,
        timeout: float | None = None,
        attempt: int = 1,
        on_result: Callable[[PortResult], Any] | None = None,
        verbose: bool | None = None,
    ) -> list[PortResult]:
        """Probe many ``(host, ip, port)`` triples concurrently.

        Uses a bounded worker pool (sized to the concurrency limit) instead of
        one task per probe, so a 1 600-probe host×port matrix no longer creates
        1 600 short-lived tasks and an ``as_completed`` set to match.
        """
        if not probes:
            return []
        results: list[PortResult] = []
        queue: asyncio.Queue[tuple[str, str, int]] = asyncio.Queue()
        for triple in probes:
            queue.put_nowait(triple)
        worker_count = min(self._pool_size, len(probes))

        async def worker() -> None:
            while True:
                item = await queue.get()
                try:
                    host, ip, port = item
                    try:
                        result = await self.probe(
                            host, ip, port,
                            timeout=timeout, attempt=attempt, verbose=verbose,
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:  # pragma: no cover - defensive
                        result = PortResult(
                            host=host, ip=ip, port=port,
                            label=self.ports.get(port, "Unknown"),
                            open=False, failure=MODE_ERROR,
                            error=f"{exc.__class__.__name__}: {exc}",
                        )
                    results.append(result)
                    if on_result is not None:
                        maybe = on_result(result)
                        if asyncio.iscoroutine(maybe):
                            await maybe
                finally:
                    queue.task_done()

        workers = [
            asyncio.create_task(worker()) for _ in range(max(1, worker_count))
        ]
        try:
            await queue.join()
        except asyncio.CancelledError:
            for task in workers:
                task.cancel()
            raise
        for task in workers:
            task.cancel()
        return results

    async def sweep_hosts(
        self,
        hosts: Sequence[tuple[str, str]],
        ports: Iterable[int] | None = None,
        *,
        on_open: Callable[[PortResult], Any] | None = None,
    ) -> dict[str, list[PortResult]]:
        """Port-major sweep of a host batch; returns ``{host: [open ports]}``.

        Every host in *hosts* is swept across port 1, then port 2, and so on, so
        the worker pool is shared and a single slow host cannot stall the batch.
        Ports that time out are retried once with the full timeout, but only for
        hosts that proved to be alive (an open or refused port).
        """
        port_list = list(ports or self.ports.keys())
        if not hosts or not port_list:
            return {}
        started = time.perf_counter()
        self.stats.batches += 1
        opened: dict[str, list[PortResult]] = {host: [] for host, _ in hosts}
        #: Hosts that answered anything (open or refused) — the only ones worth a
        #: second, slower pass over their timed-out ports.
        responsive: set[str] = set()
        timed_out: dict[str, list[int]] = {host: [] for host, _ in hosts}
        first_pass_timeout = self.fast_timeout if self.adaptive_timeout else self.timeout

        # Issue the whole host×port matrix at once and let the semaphore decide
        # how much runs in parallel.  Iterating port-by-port would serialise the
        # batch behind the slowest port instead of saturating the worker pool.
        batch = [
            (host, ip, port) for port in port_list for host, ip in hosts
        ]
        results = await self.probe_batch(
            batch, timeout=first_pass_timeout, verbose=False
        )
        for result in results:
            if result.open:
                opened[result.host].append(result)
                responsive.add(result.host)
                if on_open is not None:
                    maybe = on_open(result)
                    if asyncio.iscoroutine(maybe):
                        await maybe
            elif result.failure == MODE_REFUSED:
                responsive.add(result.host)
            elif result.failure == MODE_TIMEOUT:
                timed_out[result.host].append(result.port)

        # Adaptive second pass: retry only the timed-out ports of live hosts.
        if self.adaptive_timeout and self.fast_timeout < self.timeout:
            retry_probes: list[tuple[str, str, int]] = []
            ip_lookup = dict(hosts)
            for host in responsive:
                known_open = {r.port for r in opened[host]}
                for port in timed_out.get(host, ()):
                    if port not in known_open:
                        retry_probes.append((host, ip_lookup[host], port))
            if retry_probes:
                self.stats.retries += len(retry_probes)
                self.bus.emit(
                    f"Adaptive timeout — retrying {len(retry_probes)} timed-out "
                    f"port(s) at {self.timeout:.2f}s across "
                    f"{len({h for h, _, _ in retry_probes})} responsive host(s)",
                    "debug",
                    "port",
                )
                retried = await self.probe_batch(
                    retry_probes, timeout=self.timeout, attempt=2, verbose=False
                )
                for result in retried:
                    if result.open:
                        opened[result.host].append(result)
                        if on_open is not None:
                            maybe = on_open(result)
                            if asyncio.iscoroutine(maybe):
                                await maybe

        for host in opened:
            opened[host].sort(key=lambda r: r.port)
        self.stats.duration += time.perf_counter() - started
        self.stats.rate_waits = self.rate_waits
        self.stats.rate_wait_seconds = round(self.rate_wait_seconds, 3)
        return opened

    # -- compatibility ----------------------------------------------------- #
    async def scan_host(
        self,
        host: str,
        ip: str,
        ports: Iterable[int] | None = None,
        *,
        on_open: Callable[[PortResult], Any] | None = None,
    ) -> list[PortResult]:
        """Scan every port of a single host; returns the open ports."""
        swept = await self.sweep_hosts([(host, ip)], ports, on_open=on_open)
        return swept.get(host, [])

    # -- TLS / banner fingerprinting --------------------------------------- #
    async def _fingerprint(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        ip: str,
        result: PortResult,
    ) -> None:
        """Best-effort TLS upgrade + banner read (never raises)."""
        if not result.open:
            return
        if result.port in TLS_FIRST_PORTS:
            await self._tls_handshake(host, ip, result)
            return
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=0.35)
            if data:
                result.banner = _clean_banner(data)
                result.service = detect_service(result.port, data)
                if result.service and result.service != "HTTP":
                    self.bus.port(
                        f"Service on ://{host}:{result.port} — {result.service}"
                        + (f" ({result.banner})" if result.banner else ""),
                        host=host,
                        port=result.port,
                        ip=ip,
                    )
        except (asyncio.TimeoutError, OSError, asyncio.IncompleteReadError):
            pass
        except Exception:  # pragma: no cover
            pass

    async def _tls_handshake(self, host: str, ip: str, result: PortResult) -> None:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=ip, port=result.port, ssl=self._tls_context,
                    server_hostname=host,
                ),
                timeout=max(self.timeout, 2.5),
            )
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is not None:
                result.tls = True
                result.tls_version = ssl_object.version()
                result.service = "HTTPS"
                cipher = ssl_object.cipher()
                result.tls_cipher = cipher[0] if cipher else None
                cert = None
                try:
                    cert = ssl_object.getpeercert()
                except Exception:
                    cert = None
                if cert:
                    result.cert_subject = _cert_cn(cert)
                    result.cert_sans = _cert_sans(cert)
                    result.cert_expired = _cert_expired(cert)
                elif not self.verify_tls:
                    try:
                        der = ssl_object.getpeercert(binary_form=True)
                        if der:
                            subject, sans = parse_der_certificate(der)
                            result.cert_subject = subject
                            result.cert_sans = sans
                            result.cert_expired = _der_expired(der)
                    except Exception:
                        pass
                self.bus.port(
                    f"TLS handshake OK on ://{host}:{result.port} — "
                    f"{result.tls_version} / {result.tls_cipher}"
                    + (f" / CN={result.cert_subject}" if result.cert_subject else ""),
                    host=host,
                    port=result.port,
                    ip=ip,
                )
            try:
                banner = await asyncio.wait_for(reader.read(128), timeout=0.2)
                if banner and not result.banner:
                    result.banner = _clean_banner(banner)
            except Exception:
                pass
        except ssl.SSLError as exc:
            result.tls = False
            result.error = f"tls: {exc.__class__.__name__}"
            self.bus.filtered(
                f"TLS rejected on ://{host}:{result.port} ({exc.__class__.__name__}) "
                f"— continuing in cleartext",
                host=host,
                port=result.port,
                ip=ip,
            )
        except (asyncio.TimeoutError, OSError):
            result.tls = False
        except Exception:  # pragma: no cover
            result.tls = False
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

    def reset_stats(self) -> None:
        self.stats = SweepStats()
        self.probes_sent = 0
        self.ports_open = 0


def _clean_banner(data: bytes) -> str | None:
    text = data.decode("latin-1", "replace")
    for unwanted in ("\r", "\n", "\x00"):
        text = text.replace(unwanted, " ")
    text = " ".join(text.split())
    if not text:
        return None
    return text[:120]


# --------------------------------------------------------------------------- #
# Certificate helpers (pure-python DER parsing — no extra dependency)
# --------------------------------------------------------------------------- #

_OID_CN = "2.5.4.3"
_OID_SAN = "2.5.29.17"


def _cert_cn(cert: dict[str, Any]) -> str | None:
    for rdn in cert.get("subject", ()):  # type: ignore[union-attr]
        for key, value in rdn:
            if key in ("commonName", "CN"):
                return value
    return None


def _cert_sans(cert: dict[str, Any]) -> list[str]:
    return [value for key, value in cert.get("subjectAltName", ()) if key == "DNS"]


def _cert_expired(cert: dict[str, Any]) -> bool | None:
    not_after = cert.get("notAfter")
    if not not_after:
        return None
    try:
        import datetime as _dt

        expiry = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        return expiry < _dt.datetime.utcnow()
    except Exception:
        return None


def parse_der_certificate(der: bytes) -> tuple[str | None, list[str]]:
    """Small ASN.1 walker extracting the CN and dNSName SANs.

    Used by the SAN-harvesting discovery step as well as port fingerprinting.
    """
    common_name: str | None = None
    sans: list[str] = []
    try:
        marker = b"\x06\x03\x55\x1d\x11"  # OID 2.5.29.17 (subjectAltName)
        idx = der.find(marker)
        if idx != -1:
            for offset in range(idx, min(idx + 2048, len(der) - 2)):
                if der[offset] == 0x82:  # [2] dNSName, 2-byte length
                    length = int.from_bytes(der[offset + 1 : offset + 3], "big")
                    raw = der[offset + 3 : offset + 3 + length]
                    if 0 < length < 254 and all(32 <= byte < 127 for byte in raw):
                        try:
                            value = raw.decode("ascii")
                        except UnicodeDecodeError:
                            continue
                        if value not in sans:
                            sans.append(value)
        cn_marker = b"\x06\x03\x55\x04\x03"
        idx = der.find(cn_marker)
        if idx != -1:
            tail = der[idx + 5 : idx + 90]
            for offset in range(len(tail) - 2):
                if tail[offset] in (0x0C, 0x13):
                    length = tail[offset + 1]
                    raw = tail[offset + 2 : offset + 2 + length]
                    if 0 < length < 128 and all(32 <= byte < 127 for byte in raw):
                        common_name = raw.decode("ascii")
                        break
    except Exception:  # pragma: no cover
        pass
    return common_name, sans


#: UTCTime (tag 0x17) and GeneralizedTime (tag 0x18) values inside a DER cert.
_TIME_RE = re.compile(rb"(?:\x17\x0d|\x18\x0f)([0-9]{12,14}Z)")


def _der_expired(der: bytes) -> bool | None:
    """Return whether the certificate's ``notAfter`` is in the past.

    ``getpeercert()`` returns nothing under ``CERT_NONE``, so expiry is read
    from the raw DER.  The validity field holds ``notBefore`` then ``notAfter``,
    so the **second** timestamp is the expiry — reading the first (as this used
    to) compared ``notBefore`` against now and always reported "not expired".
    """
    try:
        from datetime import datetime, timezone

        stamps: list[datetime] = []
        for match in _TIME_RE.finditer(der):
            token = match.group(1)
            # 12 digits + 'Z' = UTCTime (2-digit year); 14 + 'Z' = GeneralizedTime.
            fmt = "%y%m%d%H%M%SZ" if len(token) == 13 else "%Y%m%d%H%M%SZ"
            try:
                when = datetime.strptime(token.decode("ascii"), fmt)
            except ValueError:
                continue
            stamps.append(when.replace(tzinfo=timezone.utc))
        if len(stamps) < 2:
            return None
        return stamps[1] < datetime.now(timezone.utc)
    except Exception:
        return None


def resolve_family(ip: str) -> int:
    return socket.AF_INET6 if ":" in ip else socket.AF_INET
