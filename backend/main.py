"""HoneyMap — FastAPI backend."""

import asyncio
import json
import time
from contextlib import asynccontextmanager

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv()

from . import db, honeypot, scanner

# ---------------------------------------------------------------------------
# WebSocket connection hub
# ---------------------------------------------------------------------------

_connections: set[WebSocket] = set()


async def broadcast(message: dict) -> None:
    """Send a JSON message to every connected WebSocket client."""
    if not _connections:
        return
    data = json.dumps(message)
    dead: set[WebSocket] = set()
    for ws in list(_connections):
        try:
            await ws.send_text(data)
        except Exception:
            dead.add(ws)
    _connections.difference_update(dead)


# ---------------------------------------------------------------------------
# Repeat-offender tracker
# ---------------------------------------------------------------------------

_hit_counts: dict[str, int] = {}
_ESCALATION_THRESHOLD = 5


async def _handle_honeypot_hit(hit: dict) -> None:
    """Persist hit, update count, broadcast hit + optional escalation + stats."""
    ip = hit["ip"]
    _hit_counts[ip] = _hit_counts.get(ip, 0) + 1
    hit["hit_count"] = _hit_counts[ip]

    # Persist to SQLite
    await asyncio.to_thread(db.save_hit, hit)

    # Fire webhook if configured (non-blocking)
    if _webhook_url:
        asyncio.ensure_future(_fire_webhook(hit))

    # Broadcast the hit
    await broadcast(hit)

    # Threat escalation when threshold crossed
    if _hit_counts[ip] == _ESCALATION_THRESHOLD:
        await broadcast({
            "type": "threat_escalation",
            "ip": ip,
            "hit_count": _hit_counts[ip],
            "ts": int(time.time()),
        })

    # Broadcast updated stats after every hit
    stats = await asyncio.to_thread(db.get_stats)
    await broadcast(stats)


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------

_webhook_url: str | None = None


async def _fire_webhook(payload: dict) -> None:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(_webhook_url, json=payload)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Seed data — only used when DB is empty (first ever run)
# ---------------------------------------------------------------------------

_SEED_HITS = [
    {"ip": "185.220.101.5",  "port": 8022, "lat": 52.5,  "lng": 13.4,   "country": "Germany",       "isp": "Tor Project",  "rdns": "tor-exit.for-privacy.net", "banner": None,            "abuse_score": 90, "hit_count": 1},
    {"ip": "218.92.0.180",   "port": 8444, "lat": 31.0,  "lng": 121.0,  "country": "China",          "isp": "ChinaNet",     "rdns": None,                       "banner": "USER root\r\n", "abuse_score": 55, "hit_count": 1},
    {"ip": "45.142.212.100", "port": 8023, "lat": 55.75, "lng": 37.6,   "country": "Russia",         "isp": "Selectel",     "rdns": None,                       "banner": None,            "abuse_score": 72, "hit_count": 1},
    {"ip": "192.241.220.100","port": 8445, "lat": 40.7,  "lng": -74.0,  "country": "United States",  "isp": "DigitalOcean", "rdns": "scan.example.com",         "banner": None,            "abuse_score": 30, "hit_count": 1},
    {"ip": "91.108.56.130",  "port": 8022, "lat": 48.9,  "lng": 2.3,    "country": "France",         "isp": "OVH",          "rdns": None,                       "banner": None,            "abuse_score": None, "hit_count": 1},
]


# ---------------------------------------------------------------------------
# Lifespan — init DB, start honeypot
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    asyncio.ensure_future(honeypot.start_honeypot(_handle_honeypot_hit))
    yield


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="HoneyMap", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    _connections.add(ws)

    now = int(time.time())

    # Send persisted history first (replay real hits from DB)
    history = await asyncio.to_thread(db.get_hits)
    for hit in reversed(history):
        await ws.send_text(json.dumps(hit))

    # If DB is empty (first run), send seed hits so the map isn't blank
    if not history:
        for hit in _SEED_HITS:
            await ws.send_text(json.dumps({"type": "honeypot_hit", "ts": now, **hit}))

    # Send current stats
    stats = await asyncio.to_thread(db.get_stats)
    await ws.send_text(json.dumps(stats))

    try:
        while True:
            await ws.receive_text()  # keep-alive; client messages ignored
    except WebSocketDisconnect:
        pass
    finally:
        _connections.discard(ws)


class ScanRequest(BaseModel):
    host: str


@app.post("/scan")
async def scan(req: ScanRequest):
    ports = await scanner.scan_host(req.host, broadcast)
    return {"host": req.host, "ports": ports}


@app.get("/hits")
async def get_hits(limit: int = 200):
    return await asyncio.to_thread(db.get_hits, limit)


@app.get("/stats")
async def get_stats():
    return await asyncio.to_thread(db.get_stats)


@app.get("/geo")
async def geo_lookup(ip: str):
    from . import geo
    return await geo.lookup(ip)


class AlertConfig(BaseModel):
    webhook_url: str


@app.post("/alert-config")
async def set_alert_config(config: AlertConfig):
    global _webhook_url
    _webhook_url = config.webhook_url
    return {"status": "ok", "webhook_url": _webhook_url}
