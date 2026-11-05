# 🍯 HoneyMap — Build Plan

> **Concept:** A dual-mode security dashboard. Actively scan a target to map exposed services, and passively listen as a honeypot to catch who's already scanning you. One live dashboard shows both in real time.

---

## Agreed JSON Schema (read this first — both people must agree before writing code)

All WebSocket messages share this shape:

```json
// Honeypot hit — emitted every time someone connects to a listener port
{
  "type": "honeypot_hit",
  "ip": "1.2.3.4",
  "port": 8022,
  "ts": 1700000000,
  "lat": 51.5,
  "lng": -0.1,
  "country": "GB",
  "isp": "BT",
  "rdns": "tor-exit.example.com",      // reverse DNS — may be null
  "banner": "USER admin\r\n",          // data attacker sent — may be null
  "abuse_score": 87,                   // AbuseIPDB confidence 0–100 — may be null
  "hit_count": 3                       // how many times this IP has hit us total
}

// Scan result — emitted once per host after a scan completes
{ "type": "scan_result", "host": "192.168.1.1", "ports": [{ "port": 80, "service": "http", "version": "nginx 1.24" }] }

// Threat escalation — emitted when an IP crosses the repeat-hit threshold
{ "type": "threat_escalation", "ip": "1.2.3.4", "hit_count": 5, "ts": 1700000000 }

// Stats update — emitted after every honeypot hit
{
  "type": "stats",
  "total_hits": 142,
  "unique_ips": 87,
  "top_port": 8022,
  "top_country": "CN",
  "hits_last_hour": 14
}
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
│  /scan      ──► nmap wrapper            │
│  /honey     ──► TCP listener threads    │
│  /geo       ──► ip-api.com lookup       │
│  /hits      ──► SQLite history          │
│  /stats     ──► aggregate stats         │
│  /alert-config ──► webhook config       │
└─────────────────────────────────────────┘
```

---

## Tech Stack

| Layer        | Choice              | Why                                      |
|--------------|---------------------|------------------------------------------|
| Backend      | Python + FastAPI    | async WebSocket support, easy subprocess |
| Scanner      | `python-nmap`       | wraps nmap cleanly                       |
| Honeypot     | `asyncio` sockets   | lightweight, no extra deps               |
| Persistence  | `sqlite3` (stdlib)  | no extra dep, survives restarts          |
| Geo          | ip-api.com          | free JSON API, no auth required          |
| Threat Intel | AbuseIPDB (free)    | abuse confidence score per IP            |
| rDNS         | `socket` (stdlib)   | hostname reveal, zero deps               |
| Frontend     | Vanilla JS          | no build step, fast to iterate           |
| Map          | Leaflet.js          | free, no API key needed                  |

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

#### ✅ Hour 1 — COMPLETE (already shipped to `person-a`)
- [x] `backend/requirements.txt` — `fastapi`, `uvicorn`, `python-nmap`, `httpx`
- [x] `backend/main.py` — FastAPI app, `/ws` WebSocket hub, `/scan` POST, CORS, seed hits
- [x] `backend/honeypot.py` — asyncio TCP listeners on `8022`, `8023`, `8444`, `8445`
- [x] `backend/geo.py` — ip-api.com lookup, returns nulls on failure
- [x] `backend/scanner.py` — nmap wrapper, broadcasts `scan_result`

#### Hour 2 — Extended Features (implement in this order)

**Feature 1 — SQLite Persistence** (`backend/db.py`)
- [ ] `init_db()` — create `hits` table: `id, ip, port, ts, lat, lng, country, isp, rdns, banner, abuse_score`
- [ ] `save_hit(hit: dict)` — insert a row
- [ ] `GET /hits` endpoint — return last 200 hits as JSON array (for frontend page-load history)
- [ ] Call `init_db()` in lifespan, call `save_hit()` inside honeypot handler after broadcast

**Feature 2 — Reverse DNS** (`backend/geo.py` addition)
- [ ] Add `rdns(ip)` — `await asyncio.to_thread(socket.gethostbyaddr, ip)` → return hostname string or `None`
- [ ] Include `rdns` field in every `honeypot_hit` broadcast

**Feature 3 — Banner Grabbing** (`backend/honeypot.py` change)
- [ ] After accepting connection, `await asyncio.wait_for(reader.read(256), timeout=2.0)` before closing
- [ ] Decode bytes to string (ignore errors), strip, include as `banner` field (or `None` if timeout)

**Feature 4 — Repeat Offender Tracker** (`backend/main.py` addition)
- [ ] In-memory `hit_counts: dict[str, int]` — increment on every honeypot hit
- [ ] Include `hit_count` in every `honeypot_hit` broadcast
- [ ] If `hit_count` crosses 5, also broadcast a `threat_escalation` message

**Feature 5 — AbuseIPDB Enrichment** (`backend/geo.py` addition)
- [ ] `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}` with `Key: <ABUSEIPDB_KEY>` header
- [ ] Read key from env var `ABUSEIPDB_KEY` — if unset, skip silently (return `None`)
- [ ] Add `abuse_score` field to honeypot_hit; cache results in a dict by IP to avoid re-fetching

**Feature 6 — Port-Specific Fake Banners** (`backend/honeypot.py` change)
- [ ] Before closing, send a fake banner based on port:
  - `8022` → `b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n"`
  - `8023` → `b"\xff\xfd\x18"` (Telnet IAC DO TERM)
  - `8444/8445` → `b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\n\r\n"`

**Feature 7 — Stats Endpoint + Broadcast** (`backend/main.py` addition)
- [ ] `GET /stats` — query SQLite for: total hits, unique IPs, top port, top country, hits last hour
- [ ] After every honeypot hit, compute stats and broadcast a `stats` message over WebSocket

**Feature 8 — Webhook / Alert Config** (`backend/main.py` addition)
- [ ] `POST /alert-config` accepts `{ "webhook_url": "https://..." }`
- [ ] On each honeypot hit, if webhook is configured, fire `httpx.post(webhook_url, json=hit)` in background (don't await, don't crash if it fails)

#### Hour 2.5 — Polish
- [ ] Verify all 8 features work end-to-end with the WebSocket test script
- [ ] Confirm `GET /hits` returns history after server restart (SQLite persisted)
- [ ] Commit and push to `person-a`

---

### Deliverable by Sync (updated)
- `ws://localhost:8000/ws` delivers enriched `honeypot_hit` with `rdns`, `banner`, `abuse_score`, `hit_count`
- `threat_escalation` fires after 5 hits from same IP
- `stats` message arrives after each hit
- `GET /hits` returns persisted history
- `GET /stats` returns aggregate JSON

---

### Files You Own
```
backend/
├── main.py          # FastAPI app, WebSocket hub, lifespan, stats, webhook
├── honeypot.py      # asyncio TCP listeners, banner grab, fake banners
├── scanner.py       # nmap wrapper
├── geo.py           # ip-api.com, rDNS, AbuseIPDB
├── db.py            # SQLite init + save_hit
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
- [ ] Wire up mock data: call a `handleMessage(event: object)` function with each mock object
- [ ] `honeypot_hit` handler: drop a circle marker at lat/lng, prepend a table row
- [ ] `scan_result` handler: populate the left panel results table

**Use this expanded mock data** (matches the new schema):
```js
const MOCK = [
  { type: 'honeypot_hit', ip: '185.220.101.5', port: 8022, ts: Date.now(), lat: 52.5, lng: 13.4,  country: 'DE', isp: 'Tor Project', rdns: 'tor-exit.example.com', banner: null,           abuse_score: 90, hit_count: 1 },
  { type: 'honeypot_hit', ip: '218.92.0.180',  port: 8444, ts: Date.now(), lat: 31.0, lng: 121.0, country: 'CN', isp: 'ChinaNet',    rdns: null,                   banner: 'USER root\r\n', abuse_score: 55, hit_count: 1 },
  { type: 'threat_escalation', ip: '185.220.101.5', hit_count: 5, ts: Date.now() },
  { type: 'scan_result', host: '127.0.0.1', ports: [{ port: 80, service: 'http', version: 'nginx 1.24' }, { port: 22, service: 'ssh', version: 'OpenSSH 8.9' }] },
  { type: 'stats', total_hits: 42, unique_ips: 17, top_port: 8022, top_country: 'CN', hits_last_hour: 8 }
]
```

#### Hour 2 — Live WebSocket & New Feature Panels
- [ ] Replace mock loop with real `WebSocket('ws://localhost:8000/ws')`
- [ ] On connect: also `fetch('http://localhost:8000/hits')` to load history into the feed table
- [ ] Add scan input + button → `fetch('http://localhost:8000/scan', { method: 'POST', body: ... })`
- [ ] Animate new honeypot rows (CSS `@keyframes` fade-in)
- [ ] **Map dot color by abuse score:** red = score ≥ 70, orange = 30–69, yellow = <30 or null
- [ ] **Threat escalation handler** (`threat_escalation` type): flash the matching row red, add a 🔴 badge in the feed
- [ ] **Stats strip** (`stats` type): render a header bar showing Total Hits | Unique IPs | Top Port | Top Country | Last Hour
- [ ] **Feed table columns** (updated): Timestamp | IP | Port | Country | ISP | rDNS | Banner | Abuse Score
- [ ] Show connection status indicator (green dot = WS connected, red = disconnected)

#### Hour 2.5 — Polish
- [ ] Color-code scan results: port 22/23/3389 = red, 80/443 = yellow, others = green
- [ ] Cap honeypot table at 50 rows (remove oldest when over limit)
- [ ] Map popup on marker click: show IP, port, ISP, rDNS, abuse score
- [ ] Add webhook config form: text input + Save button → `POST /alert-config`
- [ ] Responsive layout check — looks okay on a laptop screen

---

### Deliverable by Sync (updated)
- `index.html` opens in a browser with no errors
- All 5 mock message types render correctly (honeypot_hit, threat_escalation, scan_result, stats, history load)
- Stats strip updates on each hit
- Threat escalation visually highlights the offending IP
- The only change needed to go live is the WebSocket URL swap

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
- [ ] Person A: confirm `GET /hits` returns persisted hit history
- [ ] Person B: swap mock for `new WebSocket('ws://localhost:8000/ws')` + `fetch('/hits')` on load
- [ ] Trigger a real honeypot hit: `nc localhost 8022` from a terminal
- [ ] Verify dot appears on map and row appears in feed table with rDNS + banner columns
- [ ] Hit the same port 5 times → verify `threat_escalation` fires and row highlights red
- [ ] Verify stats strip updates after each hit
- [ ] Trigger a real scan: enter `127.0.0.1` in the scanner input
- [ ] Verify scan results populate the left panel with color-coded ports

---

## Demo Script (Last 30 Min)

1. Open dashboard — stats strip shows history from SQLite, map has pre-seeded dots
2. Status dot is green (WS connected)
3. Open a terminal: `nc localhost 8022` → row animates in with rDNS + banner data
4. Repeat 4 more times from same terminal → 🔴 threat escalation fires, row flashes red
5. Enter `127.0.0.1` in the scanner → port table populates with color-coded risk
6. One-liner pitch: **"We show you what attackers see when they look at your network — and catch them looking."**

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| `nmap` not installed | Falls back gracefully, returns empty ports array |
| Port binding needs root | Using ports >1024 (8022, 8023, 8444, 8445) |
| Geo lookup rate limited | Results cached in memory by IP |
| AbuseIPDB key missing | Feature skips silently, `abuse_score` returns null |
| WebSocket CORS issues | `CORSMiddleware` already added with `allow_origins=["*"]` |
| Scanning a host you don't own is illegal | Demo only against `localhost` or a local VM |
