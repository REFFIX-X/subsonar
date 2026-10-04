"""Interrogate one host:port over both schemes with the raw response visible.

Usage::

    python tools/probe_one.py support.example.com 2082
    python tools/probe_one.py support.example.com 2082 --scheme https
"""

from __future__ import annotations

import argparse
import asyncio
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from subsonar.core.dns import AnonymousResolver
from subsonar.core.events import EventBus
from subsonar.core.web_probe import WebProbe


async def raw_http(host: str, ip: str, port: int) -> str:
    """Send a hand-written HTTP/1.1 request and return the raw response head."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=6
        )
    except Exception as exc:
        return f"TCP connect failed: {exc.__class__.__name__}: {exc}"
    try:
        request = (
            f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"User-Agent: subsonar-probe/1.0\r\nAccept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=8)
        text = data.decode("latin-1", "replace")
        return text.split("\r\n\r\n")[0]
    except Exception as exc:
        return f"read failed: {exc.__class__.__name__}: {exc}"
    finally:
        writer.close()


async def raw_tls(host: str, ip: str, port: int) -> str:
    """Attempt a real TLS handshake and report exactly what happens."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=ip, port=port, ssl=ctx, server_hostname=host),
            timeout=8,
        )
    except ssl.SSLError as exc:
        return f"TLS handshake FAILED: ssl.SSLError: {exc}"
    except Exception as exc:
        return f"TLS handshake FAILED: {exc.__class__.__name__}: {exc}"
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        return (
            f"TLS handshake OK: version={ssl_obj.version()} "
            f"cipher={ssl_obj.cipher()[0] if ssl_obj.cipher() else '?'} "
            f"ALPN={ssl_obj.selected_alpn_protocol()}"
        )
    finally:
        writer.close()


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--scheme", choices=("http", "https", "both"), default="both")
    args = parser.parse_args()

    resolver = AnonymousResolver(timeout=3.0, retries=3, verbose_queries=False)
    await resolver.health_check(timeout=2.0, log=False)
    resolved = await resolver.resolve(args.host, log=False)
    if not resolved.ok:
        print(f"DNS failed for {args.host}: {resolved.error}")
        return 1
    ip = resolved.ip
    print(f"target   : {args.host}:{args.port}")
    print(f"resolved : {ip} (via {resolved.resolver})")
    print()

    if args.scheme in ("http", "both"):
        print("--- raw plain HTTP/1.1 request ---")
        print(await raw_http(args.host, ip, args.port))
        print()
    if args.scheme in ("https", "both"):
        print("--- raw TLS handshake ---")
        print(await raw_tls(args.host, ip, args.port))
        print()

    if args.scheme == "both":
        print("--- subsonar WebProbe verdict ---")
        probe = WebProbe(resolver=resolver, timeout=8.0, concurrency=2, bus=EventBus())
        await probe.start()
        try:
            for scheme in ("http", "https"):
                result = await probe.probe(args.host, ip, args.port, schemes=[scheme])
                print(
                    f"  {scheme:<5} url={result.url:<40} "
                    f"status={result.status} ok={result.ok} kind={result.kind!r} "
                    f"tls={result.tls} title={result.title!r}"
                )
                print(
                    f"        server={result.server!r} len={result.content_length} "
                    f"redirects={result.redirect_chain} error={result.error!r}"
                )
        finally:
            await probe.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
