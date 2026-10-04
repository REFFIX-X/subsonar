"""AXFR (DNS zone transfer) attempt — the classic misconfiguration check.

When an authoritative server fails to restrict zone transfers, one request hands
over the *entire* zone — every subdomain, in one shot.  It is therefore the
highest-signal discovery primitive there is, and also the loudest: unlike the
anonymous UDP DNS the rest of subsonar uses, AXFR opens a TCP/53 connection to
the target's own nameservers and is directly attributable to the scanner.  It is
off by default and enabled explicitly with ``--axfr``.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Any

from .dns import TYPE_NS, TYPE_SOA, build_query, parse_response

#: AXFR query type.
AXFR_QTYPE = 252
#: Nameservers to try, and a hard cap on records read from one transfer.
MAX_SERVERS = 8
MAX_RECORDS = 20_000


@dataclass(slots=True)
class ZoneTransfer:
    """Outcome of one AXFR attempt against one nameserver address."""

    server: str = ""
    names: list[str] = field(default_factory=list)
    records: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return bool(self.names) and self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "names": sorted(set(self.names)),
            "records": self.records,
            "allowed": self.ok,
            "error": self.error,
        }


async def _read_message(reader: asyncio.StreamReader, timeout: float) -> bytes | None:
    """Read one length-prefixed DNS message (RFC 1035 TCP framing)."""
    header = await asyncio.wait_for(reader.readexactly(2), timeout)
    (length,) = struct.unpack("!H", header)
    if length == 0:
        return b""
    return await asyncio.wait_for(reader.readexactly(length), timeout)


async def _axfr_one(
    ip: str, domain: str, *, timeout: float, port: int = 53
) -> ZoneTransfer:
    """Attempt a zone transfer of *domain* from nameserver address *ip*."""
    out = ZoneTransfer(server=ip)
    packet, qid = build_query(domain, AXFR_QTYPE)
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout
        )
        writer.write(struct.pack("!H", len(packet)) + packet)
        await asyncio.wait_for(writer.drain(), timeout)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        soa_seen = 0
        names: list[str] = []
        total = 0
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                body = await _read_message(reader, remaining)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
                break
            if not body:
                break
            try:
                records, rcode = parse_response(body, qid)
            except Exception:
                break
            if rcode != 0:
                out.error = f"rcode={rcode}"
                break
            for record in records:
                total += 1
                if record.rtype == TYPE_SOA:
                    soa_seen += 1
                name = getattr(record, "name", "") or ""
                if name:
                    names.append(name)
            # The transfer ends when the opening SOA repeats.
            if soa_seen >= 2 or total >= MAX_RECORDS:
                break
        out.records = total
        out.names = names
        if total == 0 and out.error is None:
            out.error = "empty transfer (transfer refused)"
    except Exception as exc:  # noqa: BLE001 - an AXFR is best effort
        out.error = exc.__class__.__name__
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:  # pragma: no cover
                pass
    return out


async def attempt_zone_transfer(
    resolver: Any,
    domain: str,
    *,
    bus: Any = None,
    timeout: float = 6.0,
    max_servers: int = MAX_SERVERS,
    port: int = 53,
) -> list[ZoneTransfer]:
    """Try every nameserver of *domain* for an unrestricted zone transfer.

    Never raises: a missing NS record, an unreachable server or a refused
    transfer all simply yield a :class:`ZoneTransfer` with ``ok`` false.
    """
    from .osint import is_valid_hostname  # local import to avoid a cycle

    domain = str(domain or "").strip().lower().rstrip(".")
    results: list[ZoneTransfer] = []

    servers: list[str] = []
    try:
        ns_result = await resolver.query_raw(domain, TYPE_NS, log=False)
    except Exception:  # noqa: BLE001
        ns_result = None
    for record in getattr(ns_result, "records", ()):
        if getattr(record, "rtype", None) == TYPE_NS and record.value:
            servers.append(str(record.value).strip().rstrip("."))

    addresses: list[str] = []
    for server in servers[:max_servers]:
        try:
            resolved = await resolver.resolve(server, log=False)
        except Exception:  # noqa: BLE001
            continue
        if resolved is not None and getattr(resolved, "addresses", None):
            addresses.extend(list(resolved.addresses)[:2])
    if not addresses:
        return results

    for ip in addresses[:max_servers]:
        outcome = await _axfr_one(ip, domain, timeout=timeout, port=port)
        results.append(outcome)
        if bus is not None:
            try:
                if outcome.ok:
                    bus.emit(
                        f"AXFR — {ip} allowed a zone transfer of {domain} "
                        f"({len(set(outcome.names))} name(s))",
                        "warn",
                        "osint",
                        host=domain,
                    )
            except Exception:  # pragma: no cover
                pass

    if not results:
        return results

    # Keep only in-scope names from a successful transfer, so the caller gets a
    # clean candidate list rather than raw zone data.
    for outcome in results:
        if outcome.ok:
            outcome.names = [
                name for name in outcome.names if is_valid_hostname(name, domain)
            ]
    return results
