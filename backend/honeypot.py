"""Asyncio TCP honeypot — listens on high ports, grabs banners, broadcasts hits."""

import asyncio
import time
from typing import Callable, Awaitable

from . import geo

HONEYPOT_PORTS = [8022, 8023, 8444, 8445]

FAKE_BANNERS: dict[int, bytes] = {
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

    # Send fake banner to make the honeypot look convincing
    try:
        writer.write(FAKE_BANNERS.get(port, b""))
        await writer.drain()
    except Exception:
        pass

    # Grab whatever the attacker sends back (2s window)
    banner: str | None = None
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=2.0)
        if data:
            banner = data.decode("utf-8", errors="replace").strip() or None
    except (asyncio.TimeoutError, Exception):
        pass

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    # Enrich in parallel
    geo_data, hostname, score = await asyncio.gather(
        geo.lookup(ip),
        geo.rdns(ip),
        geo.abuse_score(ip),
    )

    await broadcast({
        "type": "honeypot_hit",
        "ip": ip,
        "port": port,
        "ts": int(time.time()),
        "lat": geo_data["lat"],
        "lng": geo_data["lng"],
        "country": geo_data["country"],
        "isp": geo_data["isp"],
        "rdns": hostname,
        "banner": banner,
        "abuse_score": score,
    })


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
