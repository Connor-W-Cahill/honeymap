# 🍯 HoneyMap — Build Plan

> **Concept:** A dual-mode security dashboard. Actively scan a target to map exposed services, and passively listen as a honeypot to catch who's already scanning you. One live dashboard shows both in real time.

---

## Agreed JSON Schema (read this first — both people must agree before writing code)

All WebSocket messages share this shape:

```json
// Honeypot hit — emitted every time someone connects to a listener port
{ "type": "honeypot_hit", "ip": "1.2.3.4", "port": 22, "ts": 1700000000, "lat": 51.5, "lng": -0.1, "country": "GB", "isp": "BT" }

// Scan result — emitted once per host after a scan completes
{ "type": "scan_result", "host": "192.168.1.1", "ports": [{ "port": 80, "service": "http", "version": "nginx 1.24" }] }
```

**Do not change this schema without telling the other person.**

---

## Architecture

```
┌─────────────────────────────────────────┐
│              Web Dashboard              │
│   (React or vanilla JS + WebSockets)    │
│                                         │
│  [ Port Scan View ]  [ Honeypot View ]  │
│   service map         live attack feed  │
│   open ports          IP geolocation    │
│   OS fingerprint      attempt log       │
└──────────────┬──────────────────────────┘
               │ WebSocket (ws://localhost:8000/ws)
┌──────────────▼──────────────────────────┐
│           Python Backend                │
│             (FastAPI)                   │
│                                         │
│  /scan  ──► nmap wrapper                │
│  /honey ──► TCP listener threads        │
│  /geo   ──► ip-api.com lookup           │
└─────────────────────────────────────────┘
```

---

## Tech Stack

| Layer     | Choice          | Why                                      |
|-----------|-----------------|------------------------------------------|
| Backend   | Python + FastAPI | async WebSocket support, easy subprocess |
| Scanner   | `python-nmap`   | wraps nmap cleanly                       |
| Honeypot  | `asyncio` sockets | lightweight, no extra deps             |
| Frontend  | Vanilla JS      | no build step, fast to iterate           |
| Map       | Leaflet.js      | free, no API key needed                  |
| Geo       | ip-api.com      | free JSON API, no auth required          |

---

## Timeline

```
0:00  ── Agree on schema (this file) ───────────────────────────────
      Person A: backend           │   Person B: frontend (mock data)
1:30  ── Sync: connect WebSocket, fix schema drift ──────────────────
2:00  ── Integration: swap mocks for live backend ───────────────────
2:30  ── Polish + rehearse demo ─────────────────────────────────────
3:00  ── Present ───────────────────────────────────────────────────
```

---

---

# 👤 Person A — Backend & Honeypot

**Branch:** `person-a`
**Directory:** `backend/`

### First AI Prompt (paste this to start your session)
> "You are building a Python FastAPI backend for a real-time security dashboard called HoneyMap.
> Scaffold a FastAPI app in a `backend/` directory with:
> - A WebSocket endpoint at `/ws` that broadcasts JSON messages to all connected clients
> - A POST endpoint at `/scan` that accepts `{ host: string }` and runs an nmap scan via python-nmap
> - An asyncio TCP honeypot that listens on ports 8022, 8023, 8080, 8443 (high ports, no root needed)
> - Each honeypot hit should resolve the attacker IP via ip-api.com and broadcast this JSON to all WebSocket clients:
>   `{ type: 'honeypot_hit', ip, port, ts, lat, lng, country, isp }`
> - Each scan result should broadcast:
>   `{ type: 'scan_result', host, ports: [{ port, service, version }] }`
> Use `requirements.txt` for dependencies."

---

### Hour-by-Hour Tasks

#### Hour 1 — Scaffold & Core Logic
- [ ] Create `backend/` directory and `requirements.txt`
  - Dependencies: `fastapi`, `uvicorn`, `python-nmap`, `httpx`, `websockets`
- [ ] `backend/main.py` — FastAPI app with `/ws` WebSocket endpoint
  - Maintain a set of active connections
  - `broadcast(message: dict)` helper that sends to all
- [ ] `backend/honeypot.py` — asyncio TCP listeners
  - Listen on ports `8022`, `8023`, `8080`, `8443`
  - On connection: log IP, port, timestamp → call geo lookup → broadcast honeypot_hit
- [ ] `backend/geo.py` — call `http://ip-api.com/json/{ip}` → return lat, lng, country, isp

#### Hour 2 — Scanner & Integration
- [ ] `backend/scanner.py` — wrap `python-nmap`
  - Accept a host/IP, run `nmap -sV`, parse output
  - Broadcast `scan_result` over WebSocket when done
- [ ] Wire honeypot startup into FastAPI lifespan event (starts on app boot)
- [ ] Test with `uvicorn backend.main:app --reload`
- [ ] Manually verify WebSocket messages with a browser console or wscat

#### Hour 2.5 — Polish
- [ ] Add CORS middleware so the frontend can connect from a different port
- [ ] Handle edge cases: nmap not installed, geo lookup failure (return nulls, don't crash)
- [ ] Seed 3–5 fake honeypot hits at startup for demo reliability

---

### Deliverable by Sync (1:30)
- WebSocket at `ws://localhost:8000/ws` is live
- Connecting to it and triggering a port probe on `8022` produces a `honeypot_hit` message in the console
- POST to `/scan` with `{ "host": "127.0.0.1" }` returns and broadcasts a `scan_result`

---

### Files You Own
```
backend/
├── main.py          # FastAPI app, WebSocket hub, lifespan
├── honeypot.py      # asyncio TCP listeners
├── scanner.py       # nmap wrapper
├── geo.py           # ip-api.com lookup
└── requirements.txt
```

---

---

# 👤 Person B — Frontend & Dashboard

**Branch:** `person-b`
**Directory:** `frontend/`

### First AI Prompt (paste this to start your session)
> "You are building a vanilla JS frontend for a real-time security dashboard called HoneyMap.
> Scaffold a `frontend/` directory with a single `index.html` file (inline JS and CSS, no build step).
> The dashboard has two panels side by side:
>
> LEFT PANEL — Port Scanner:
> - Text input for a target IP + a 'Scan' button
> - Fires POST to `http://localhost:8000/scan` with body `{ host: '<ip>' }`
> - Renders results as a table: Port | Service | Version
>
> RIGHT PANEL — Honeypot Feed:
> - A Leaflet.js map (use CDN) plotting dots at lat/lng from incoming hits
> - A scrolling table below it: Timestamp | IP | Port | Country | ISP
> - New rows animate in (fade or slide)
>
> Connect to `ws://localhost:8000/ws` on page load.
> Route incoming messages by `type`:
> - `honeypot_hit` → add dot to map + prepend row to feed table
> - `scan_result` → populate the scan results table
>
> For now, use this hardcoded mock data to develop without a backend:
> ```js
> const MOCK = [
>   { type: 'honeypot_hit', ip: '185.220.101.5', port: 22, ts: Date.now(), lat: 52.5, lng: 13.4, country: 'DE', isp: 'Tor Project' },
>   { type: 'scan_result', host: '127.0.0.1', ports: [{ port: 80, service: 'http', version: 'nginx 1.24' }] }
> ]
> ```
> Make swapping mock → live WebSocket a 2-line change."

---

### Hour-by-Hour Tasks

#### Hour 1 — Layout & Mock Data
- [ ] Create `frontend/index.html` — two-panel layout, basic CSS grid
- [ ] Add Leaflet.js via CDN, render a world map centered at `[20, 0]` zoom 2
- [ ] Wire up mock data: call a `handleMessage(event)` function with each mock object
- [ ] `honeypot_hit` handler: drop a red circle marker at lat/lng, prepend a table row
- [ ] `scan_result` handler: populate the left panel results table

#### Hour 2 — Live WebSocket & Polish
- [ ] Replace mock loop with real `WebSocket('ws://localhost:8000/ws')`
- [ ] Add scan input + button → `fetch('http://localhost:8000/scan', { method: 'POST', body: ... })`
- [ ] Animate new honeypot rows (CSS `@keyframes` fade-in)
- [ ] Color-code scan results: port 22/23/3389 = red, 80/443 = yellow, others = green
- [ ] Show connection status indicator (green dot = WS connected, red = disconnected)

#### Hour 2.5 — Polish
- [ ] Cap honeypot table at 50 rows (remove oldest when over limit)
- [ ] Map popup on marker click: show IP, port, ISP
- [ ] Responsive layout check — looks okay on a laptop screen

---

### Deliverable by Sync (1:30)
- `index.html` opens in a browser with no errors
- Mock data renders correctly: dot on map, rows in feed table, scan result table populated
- The only change needed to go live is replacing mock calls with the WebSocket connection

---

### Files You Own
```
frontend/
└── index.html       # single file — HTML + inline CSS + inline JS
```

---

---

## Integration Checklist (Hour 2 sync)

- [ ] Person A: confirm WebSocket is running and CORS is enabled
- [ ] Person B: swap mock data for `new WebSocket('ws://localhost:8000/ws')`
- [ ] Trigger a real honeypot hit: `nc localhost 8022` from a terminal
- [ ] Verify dot appears on map and row appears in table
- [ ] Trigger a real scan: enter `127.0.0.1` in the scanner input
- [ ] Verify scan results populate the left panel

---

## Demo Script (Last 30 Min)

1. Open dashboard in browser — map is visible, status dot is green
2. Show the honeypot feed pre-seeded with hits from "real" IPs on the map
3. Open a terminal: `nc localhost 8022` → new row animates in live
4. Enter `127.0.0.1` in the scanner → results appear showing open ports
5. One-liner pitch: **"We show you what attackers see when they look at your network — and catch them looking."**

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| `nmap` not installed | Fall back to raw Python socket connect-scan |
| Port binding needs root | Use ports >1024 (8022, 8080, etc.) |
| Geo lookup rate limited | Cache results in a dict by IP |
| WebSocket CORS issues | Add `CORSMiddleware` to FastAPI on startup |
| Scanning a host you don't own is illegal | Demo only against `localhost` or a local VM |
