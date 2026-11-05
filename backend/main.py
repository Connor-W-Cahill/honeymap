import asyncio
import json
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend import honeypot, scanner

clients: set[WebSocket] = set()

async def broadcast(message: dict):
    data = json.dumps(message)
    for ws in list(clients):
        try:
            await ws.send_text(data)
        except Exception:
            clients.discard(ws)

# Fake hits for demo reliability
FAKE_HITS = [
    {"type": "honeypot_hit", "ip": "185.220.101.5",  "port": 8022, "ts": 0, "lat": 52.5,  "lng": 13.4,   "country": "DE", "isp": "Tor Project"},
    {"type": "honeypot_hit", "ip": "218.92.0.180",   "port": 8444, "ts": 0, "lat": 31.0,  "lng": 121.0,  "country": "CN", "isp": "ChinaNet"},
    {"type": "honeypot_hit", "ip": "45.142.212.100", "port": 8023, "ts": 0, "lat": 55.75, "lng": 37.6,   "country": "RU", "isp": "Selectel"},
    {"type": "honeypot_hit", "ip": "192.241.220.100","port": 8445, "ts": 0, "lat": 40.7,  "lng": -74.0,  "country": "US", "isp": "DigitalOcean"},
    {"type": "honeypot_hit", "ip": "91.108.56.130",  "port": 8022, "ts": 0, "lat": 48.9,  "lng": 2.3,    "country": "FR", "isp": "OVH"},
]

@asynccontextmanager
async def lifespan(app: FastAPI):
    await honeypot.start(broadcast)
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.add(websocket)
    # Send seeded fake hits immediately on connect
    now = int(time.time())
    for hit in FAKE_HITS:
        await websocket.send_text(json.dumps({**hit, "ts": now}))
    try:
        while True:
            await websocket.receive_text()  # keep alive
    except WebSocketDisconnect:
        clients.discard(websocket)

class ScanRequest(BaseModel):
    host: str

@app.post("/scan")
async def scan_endpoint(req: ScanRequest):
    result = await asyncio.to_thread(scanner.scan, req.host)
    await broadcast(result)
    return result
