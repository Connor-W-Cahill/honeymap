"""Asyncio TCP honeypot — listens on high ports, grabs banners, broadcasts hits."""

import asyncio
import time
from typing import Callable, Awaitable

from . import geo

# Person A changed ports to 8022, 8023, 8444, 8445 — adopted here
HONEYPOT_PORTS = [8022, 8023, 8444, 8445]

# Fake banners to send before closing, keyed by port
_FAKE_BANNERS: dict[int, bytes] = {
    8022: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n",
    8023: b"\xff\xfd\x18",  # Telnet IAC DO TERM
    8444: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\n\r\n",
    8445: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\n\r\n",
}


async def _handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    port: int,
    broadcast: Callable[[dict], Awaitable[None]],
) -> None:
    addr = writer.get_extra_info("peername")
    ip = addr[0] if addr else "unknown"

    # Send fake banner first (entice the attacker to send data)
    if port in _FAKE_BANNERS:
        try:
            writer.write(_FAKE_BANNERS[port])
            await writer.drain()
        except Exception:
            pass

    # Grab up to 256 bytes of attacker data
    banner: str | None = None
    try:
        raw = await asyncio.wait_for(reader.read(256), timeout=2.0)
        if raw:
            banner = raw.decode("utf-8", errors="replace").strip() or None
    except (asyncio.TimeoutError, Exception):
        pass

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass

    # Enrich in parallel
    geo_data, rdns_val, abuse = await asyncio.gather(
        geo.lookup(ip),
        geo.rdns(ip),
        geo.abuse_score(ip),
    )

    message = {
        "type": "honeypot_hit",
        "ip": ip,
        "port": port,
        "ts": int(time.time()),
        "lat": geo_data["lat"],
        "lng": geo_data["lng"],
        "country": geo_data["country"],
        "isp": geo_data["isp"],
        "rdns": rdns_val,
        "banner": banner,
        "abuse_score": abuse,
    }
    await broadcast(message)


async def start_honeypot(broadcast: Callable[[dict], Awaitable[None]]) -> None:
    """Start asyncio TCP servers on all honeypot ports."""
    for port in HONEYPOT_PORTS:
        try:
            server = await asyncio.start_server(
                lambda r, w, p=port: _handle_connection(r, w, p, broadcast),
                host="0.0.0.0",
                port=port,
            )
            asyncio.ensure_future(server.serve_forever())
            print(f"[honeypot] Listening on port {port}")
        except OSError as e:
            print(f"[honeypot] Could not bind port {port}: {e}")
