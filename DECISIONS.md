# 🍯 HoneyMap — Implementation Notes & Design Decisions

> Read this alongside `BUILDPLAN.md`. It documents where the implementation
> deliberately diverges from the plan, and why — so Person B's agent and any
> future contributor aren't surprised.

---

## What Was Built

```
backend/
├── __init__.py      # makes backend/ a package (required for relative imports)
├── main.py          # FastAPI app, WebSocket hub, lifespan, all HTTP routes, seed data
├── honeypot.py      # asyncio TCP listeners, fake banners, banner grabbing
├── scanner.py       # nmap wrapper + raw-socket fallback
├── geo.py           # ip-api.com lookup, reverse DNS, AbuseIPDB enrichment
├── db.py            # SQLite init, save_hit, get_recent_hits, get_stats
└── requirements.txt # fastapi, uvicorn[standard], python-nmap, httpx, websockets
```

```
frontend/
└── index.html       # single-file dashboard — HTML + inline CSS + inline JS
```

Run the backend:
```bash
uvicorn backend.main:app --reload
```
Then open `frontend/index.html` directly in a browser (no build step).

All routes confirmed live: `/ws`, `/scan`, `/hits`, `/stats`, `/geo`, `/alert-config`

---

## Merge — Person A's v2 push (integrated 2026-11-05)

Person A pushed a second set of changes that updated `BUILDPLAN.md` with 8 new
features and a revised schema. Their files arrived with raw git conflict markers
in every backend file. All conflicts were resolved and all 8 features integrated.

### Conflict resolution strategy
- **Honeypot ports**: Person A changed `[8022, 8023, 8080, 8443]` → `[8022, 8023, 8444, 8445]`. **Adopted Person A's version** — port numbers are deployment config, not logic.
- **Seed IPs**: Person A's seed set (DE, CN, RU, US, FR) is more geographically varied than the original. **Adopted Person A's version**.
- **Import style**: Person A used `from backend import x` (absolute); our version used `from . import x` (relative). **Kept relative imports** — they work correctly when run as `uvicorn backend.main:app` and don't depend on the working directory.
- **Broadcast dead-connection cleanup**: Person A's version silently discarded dead sockets mid-loop without tracking them. **Kept our version** — collects dead connections in a set and removes them after the loop to avoid mutating a set while iterating.
- **Scanner**: Person A's version had no nmap fallback — it would crash if nmap wasn't installed. **Kept our raw-socket fallback**.

### Schema changes (Person A extended the schema)
The `honeypot_hit` message gained 4 new fields:

```json
{
  "type": "honeypot_hit",
  "ip": "1.2.3.4", "port": 8022, "ts": 1700000000,
  "lat": 51.5, "lng": -0.1, "country": "GB", "isp": "BT",
  "rdns": "tor-exit.example.com",   // reverse DNS — may be null
  "banner": "USER admin\r\n",       // data attacker sent — may be null
  "abuse_score": 87,                // AbuseIPDB confidence 0–100 — may be null
  "hit_count": 3                    // how many times this IP has hit us total
}
```

Two new message types were added:

```json
{ "type": "threat_escalation", "ip": "1.2.3.4", "hit_count": 5, "ts": 1700000000 }

{
  "type": "stats",
  "total_hits": 142, "unique_ips": 87,
  "top_port": 8022, "top_country": "CN", "hits_last_hour": 14
}
```

**`scan_result` is unchanged.**

---

## Decision 1 — `/geo` endpoint: initially skipped, added in v2 merge

**v1:** `geo.py` was internal-only. No HTTP route.

**v2 (now):** `GET /geo?ip=<ip>` is exposed. It was added as part of the merge
because the updated architecture diagram in `BUILDPLAN.md` explicitly lists it,
and the expanded feature set (AbuseIPDB, rDNS) makes a standalone geo debug
endpoint genuinely useful during integration testing.

---

## Decision 2 — More mock data than the plan specified

**Plan said:** Use exactly two mock objects.

**What was built:** The frontend has **6 mock objects** covering all 4 message types:
3 honeypot hits, 1 threat escalation, 1 scan result, 1 stats update.

**Why:** The demo script requires the map to look populated immediately, and
the stats strip / threat escalation UI needs exercise to confirm it renders
correctly without a live backend. The extra objects cover all new message types
from the v2 schema.

**To run purely on live data:** Comment out these 3 lines at the bottom of
`index.html`:
```js
setTimeout(() => {
  MOCK.forEach((msg, i) => setTimeout(() => handleMessage(msg), i * 350));
}, 600);
```

---

## Decision 3 — Mock data and live WebSocket run simultaneously

**Plan said:** "Make swapping mock → live WebSocket a 2-line change."

**What was built:** `connectWS()` always runs. The mock `setTimeout` block also
always fires. They are additive.

**Why this is fine for the demo:** The backend seeds the same 5 IPs via
WebSocket on connect, so the frontend sees those IPs from two sources. The map
shows slightly more dots than on mock-only, but no contradictory data.

**To go fully live:** Remove the mock `setTimeout` block (3 lines, see Decision 2).

---

## Decision 4 — OS fingerprinting not implemented

**Plan said:** Port Scanner panel mentions "OS fingerprint".

**What was built:** Scan table is Port | Service | Version only.

**Why:** nmap's `-O` flag requires root/administrator privileges on most systems,
contradicting the plan's own risk mitigation. `-sV` (version detection) gives
more useful per-port data without requiring elevation.

**To add it:** Change `scanner.py` line to `nm.scan(hosts=host, arguments="-sV -O --open -T4")`
and read `nm[h]['osmatch'][0]['name']` — but expect it to fail on most demo machines.

---

## Decision 5 — No responsive breakpoints

**Plan said:** "Responsive layout check — looks okay on a laptop screen."

**What was built:** CSS grid `1fr 1fr`. No `@media` queries.

**Why:** The plan explicitly scopes this to a laptop. The grid works at 1280px+
without breakpoints. Mobile support is out of scope for a hackathon demo.

---

## Decision 6 — Honeypot pipeline order: enrich then broadcast (not save then broadcast)

**Plan said:** "call `save_hit()` inside honeypot handler after broadcast."

**What was built:** The pipeline in `main._handle_honeypot_hit()` is:
1. Increment hit count
2. `db.save_hit()` — persist to SQLite
3. Fire webhook (non-blocking)
4. `broadcast()` — send to WebSocket clients
5. Broadcast `threat_escalation` if threshold crossed
6. Broadcast `stats`

**Why save before broadcast:** If the broadcast raises, the hit is still
persisted. SQLite is synchronous and fast; the broadcast is the latency-sensitive
step. Saving first is the safer order.

---

## Decision 7 — Stats are computed from SQLite, not from in-memory counters

**Plan said:** Feature 7 — compute stats and broadcast after every honeypot hit.

**What was built:** `db.get_stats()` queries SQLite for all aggregate figures.
The in-memory `_hit_counts` dict is only used for per-IP repeat tracking and
`threat_escalation` — it is not the source of truth for the stats strip.

**Why:** SQLite stats survive a server restart. In-memory stats would reset to
zero on every `uvicorn --reload`, which would confuse the demo. Using the DB
also means `GET /stats` and the WS broadcast always agree.

---

## Decision 8 — AbuseIPDB key is optional, skips silently

**Plan said:** "Read key from env var `ABUSEIPDB_KEY` — if unset, skip silently."

**What was built:** `geo.abuse_score()` returns `None` immediately if
`ABUSEIPDB_KEY` is not set. The frontend renders `—` for a `null` abuse score.
No error is logged. No request is made.

**To enable it:** `set ABUSEIPDB_KEY=your_key_here` before starting uvicorn.
Results are cached in `_abuse_cache` per IP so the same IP is only looked up once.

---

## Current Schema (authoritative)

```json
// honeypot_hit — emitted on every TCP connection to a listener port
{
  "type": "honeypot_hit",
  "ip": "1.2.3.4", "port": 8022, "ts": 1700000000,
  "lat": 51.5, "lng": -0.1, "country": "Germany", "isp": "BT",
  "rdns": "tor-exit.example.com",
  "banner": "USER admin\r\n",
  "abuse_score": 87,
  "hit_count": 3
}

// scan_result — emitted once per /scan call when complete
{ "type": "scan_result", "host": "192.168.1.1", "ports": [{ "port": 80, "service": "http", "version": "nginx 1.24" }] }

// threat_escalation — emitted when an IP crosses 5 hits
{ "type": "threat_escalation", "ip": "1.2.3.4", "hit_count": 5, "ts": 1700000000 }

// stats — emitted after every honeypot hit
{ "type": "stats", "total_hits": 142, "unique_ips": 87, "top_port": 8022, "top_country": "CN", "hits_last_hour": 14 }
```

`rdns`, `banner`, `abuse_score` may all be `null`. All other fields are always present.

---

## Integration Checklist Notes

- WebSocket: `ws://localhost:8000/ws` ✅
- CORS: `allow_origins=["*"]` — no restrictions ✅
- On WS connect, backend immediately sends 5 seed hits (no delay)
- On WS connect, frontend also fetches `GET /hits` to load persisted history
- To trigger a real honeypot hit: `nc localhost 8022`
- Hit the same port 5 times → `threat_escalation` fires, row flashes red
- To trigger a scan: enter `127.0.0.1` in the scanner input (result arrives via WS)
- To enable webhook alerts: fill the Webhook URL field and click Save → `POST /alert-config`
- To enable AbuseIPDB: `set ABUSEIPDB_KEY=<key>` before starting uvicorn
