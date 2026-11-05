import asyncio
import time
from backend.geo import lookup

HONEYPOT_PORTS = [8022, 8023, 8444, 8445]

async def handle(reader, writer, broadcast):
    ip = writer.get_extra_info("peername")[0]
    port = writer.get_extra_info("sockname")[1]
    writer.close()
    geo = await lookup(ip)
    await broadcast({
        "type": "honeypot_hit",
        "ip": ip,
        "port": port,
        "ts": int(time.time()),
        **geo,
    })

async def start(broadcast):
    for port in HONEYPOT_PORTS:
        server = await asyncio.start_server(
            lambda r, w, p=port, b=broadcast: handle(r, w, b),
            "0.0.0.0", port,
        )
        asyncio.ensure_future(server.serve_forever())
