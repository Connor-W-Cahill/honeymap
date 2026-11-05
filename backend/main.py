import asyncio
import json
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend import honeypot, scanner, db

clients: set[WebSocket] = set()
hit_counts: dict[str, int] = {}
_webhook_url: str | None = None

async def broadcast(message: dict):
    data = json.dumps(message)
    for ws in list(clients):
        try:
            await ws.send_text(data)
        except Exception:
            clients.discard(ws)

async def on_honeypot_hit(hit: dict):
    """Called by honeypot.handle — enriches with hit_count, persists, stats, webhook."""
    ip = hit["ip"]
    hit_counts[ip] = hit_counts.get(ip, 0) + 1
    hit["hit_count"] = hit_counts[ip]

    await broadcast(hit)

    # Persist
    await asyncio.to_thread(db.save_hit, hit)

    # Threat escalation
    if hit_counts[ip] == 5:
        await broadcast({"type": "threat_escalation", "ip": ip, "hit_count": hit_counts[ip], "ts": hit["ts"]})

    # Stats broadcast
    stats = await asyncio.to_thread(db.get_stats)
    await broadcast(stats)

    # Webhook (fire and forget)
    if _webhook_url:
        asyncio.ensure_future(_fire_webhook(hit))

async def _fire_webhook(hit: dict):
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(_webhook_url, json=hit)
    except Exception:
        pass

# Fake hits for demo reliability (now with full schema)
FAKE_HITS = [
    {"type": "honeypot_hit", "ip": "185.220.101.5",  "port": 8022, "ts": 0, "lat": 52.5,  "lng": 13.4,  "country": "DE", "isp": "Tor Project",  "rdns": "tor-exit.for-privacy.net", "banner": None,            "abuse_score": 90, "hit_count": 1},
    {"type": "honeypot_hit", "ip": "218.92.0.180",   "port": 8444, "ts": 0, "lat": 31.0,  "lng": 121.0, "country": "CN", "isp": "ChinaNet",      "rdns": None,                       "banner": "USER root\r\n", "abuse_score": 55, "hit_count": 1},
    {"type": "honeypot_hit", "ip": "45.142.212.100", "port": 8023, "ts": 0, "lat": 55.75, "lng": 37.6,  "country": "RU", "isp": "Selectel",       "rdns": None,                       "banner": None,            "abuse_score": 72, "hit_count": 1},
    {"type": "honeypot_hit", "ip": "192.241.220.100","port": 8445, "ts": 0, "lat": 40.7,  "lng": -74.0, "country": "US", "isp": "DigitalOcean",   "rdns": "scan.example.com",         "banner": None,            "abuse_score": 30, "hit_count": 1},
    {"type": "honeypot_hit", "ip": "91.108.56.130",  "port": 8022, "ts": 0, "lat": 48.9,  "lng": 2.3,   "country": "FR", "isp": "OVH",            "rdns": None,                       "banner": None,            "abuse_score": None, "hit_count": 1},
]

@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    await honeypot.start(on_honeypot_hit)
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.add(websocket)
    now = int(time.time())
    # Send persisted history first
    history = await asyncio.to_thread(db.get_hits)
    for hit in reversed(history):
        await websocket.send_text(json.dumps(hit))
    # Then seed fake hits (only if DB is empty)
    if not history:
        for hit in FAKE_HITS:
            await websocket.send_text(json.dumps({**hit, "ts": now}))
    # Current stats
    stats = await asyncio.to_thread(db.get_stats)
    await websocket.send_text(json.dumps(stats))
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        clients.discard(websocket)

class ScanRequest(BaseModel):
    host: str

@app.post("/scan")
async def scan_endpoint(req: ScanRequest):
    result = await asyncio.to_thread(scanner.scan, req.host)
    await broadcast(result)
    return result

@app.get("/hits")
async def hits_endpoint():
    return await asyncio.to_thread(db.get_hits)

@app.get("/stats")
async def stats_endpoint():
    return await asyncio.to_thread(db.get_stats)

class AlertConfig(BaseModel):
    webhook_url: str

@app.post("/alert-config")
async def alert_config_endpoint(config: AlertConfig):
    global _webhook_url
    _webhook_url = config.webhook_url
    return {"status": "ok", "webhook_url": _webhook_url}
