import asyncio
import time
from backend import geo as geo_module

HONEYPOT_PORTS = [8022, 8023, 8444, 8445]

FAKE_BANNERS = {
    8022: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n",
    8023: b"\xff\xfd\x18",  # Telnet IAC DO TERM
    8444: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\n\r\n",
    8445: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\n\r\n",
}

async def handle(reader, writer, port, broadcast):
    ip = writer.get_extra_info("peername")[0]

    # Send fake banner to make the honeypot look convincing
    try:
        writer.write(FAKE_BANNERS.get(port, b""))
        await writer.drain()
    except Exception:
        pass

    # Grab whatever the attacker sends back (2s window)
    banner = None
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
    geo, hostname, score = await asyncio.gather(
        geo_module.lookup(ip),
        geo_module.rdns(ip),
        geo_module.abuse_score(ip),
    )

    await broadcast({
        "type": "honeypot_hit",
        "ip": ip,
        "port": port,
        "ts": int(time.time()),
        **geo,
        "rdns": hostname,
        "banner": banner,
        "abuse_score": score,
    })

async def start(broadcast):
    for port in HONEYPOT_PORTS:
        server = await asyncio.start_server(
            lambda r, w, p=port, b=broadcast: handle(r, w, p, b),
            "0.0.0.0", port,
        )
        asyncio.ensure_future(server.serve_forever())
