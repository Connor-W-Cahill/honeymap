# HoneyMap

A real-time network intrusion detection dashboard. Runs a honeypot on four TCP ports impersonating SSH, Telnet, and Apache, capturing attacker IPs, credentials, and exploit payloads. Hits are geo-located, enriched with ISP and abuse score data, and streamed live to a three-panel dashboard with a port scanner, attack feed, and country heatmap.

Built in 3 hours for a hackathon.

---

## Features

- **Honeypot** — TCP listeners on ports 8022, 8023, 8444, 8445 that send fake SSH/Telnet/HTTP banners and capture attacker payloads
- **Live map** — geo-located hit markers colored by abuse score, with a country heatmap toggle
- **Attack feed** — real-time table of every connection with IP, port, country, and risk score
- **Port scanner** — nmap-backed scan with version detection and CVE matching against scanned service versions
- **Network discovery** — ping-sweep a subnet to find live hosts
- **IP blocking** — block/unblock IPs from the UI; persisted to SQLite
- **IP profile modal** — full hit history, ISP, rDNS, abuse score for any IP
- **Threat escalation** — alerts when an IP hits 5+ times
- **Port knock detection** — alerts when an IP probes 3+ distinct ports within 30 seconds
- **Discord alerts** — webhook notifications for every honeypot hit
- **CSV export** — download full hit history
- **Hits/min rate graph** — 30-minute activity bar chart in the header

---

## Architecture

```
browser (frontend/index.html)
    │  WebSocket  │  REST
    ▼             ▼
backend/main.py  (FastAPI)
    ├── honeypot.py   asyncio TCP listeners on 4 ports
    ├── scanner.py    nmap wrapper + socket fallback
    ├── geo.py        ip-api.com + rDNS + AbuseIPDB
    └── db.py         SQLite (honeymap.db)
```

The frontend is a single HTML file served statically. The backend is a FastAPI app with a WebSocket hub — every connected client receives all events in real time.

---

## Quick Start

### 1. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

nmap is required for full port scanning and version detection:

```bash
# Debian / Ubuntu
sudo apt install nmap

# macOS
brew install nmap
```

### 2. (Optional) Configure AbuseIPDB

Create a `.env` file in the repo root:

```
ABUSEIPDB_KEY=your_key_here
```

Without a key, abuse scores will show as `—`. Get a free API key at [abuseipdb.com](https://www.abuseipdb.com).

### 3. Start the backend

```bash
cd backend
uvicorn main:app --reload --port 8000
```

The honeypot starts automatically when the server boots and listens on `0.0.0.0:8022`, `8023`, `8444`, `8445`.

### 4. Serve the frontend

```bash
cd frontend
python -m http.server 5500
```

Open [http://localhost:5500](http://localhost:5500).

> **Note:** The frontend must be served over HTTP, not opened as `file://`. WebSocket and fetch calls will be blocked otherwise.

---

## Port Scanner — nmap permissions

Version detection (`-sV`) works best with root privileges. Two options:

**Option A — setuid (recommended):**
```bash
sudo chmod u+s /usr/bin/nmap
```

**Option B — sudoers rule (no-password nmap only):**
Add to `/etc/sudoers` via `visudo`:
```
youruser ALL=(root) NOPASSWD: /usr/bin/nmap
```
Then pass `sudo=True` in the `nm.scan()` call in `backend/scanner.py`.

Without elevated privileges nmap falls back to a connect scan, which still works but returns fewer version details — so CVE matching will be less accurate.

---

## REST API

All endpoints are on `http://localhost:8000`.

| Method | Path | Description |
|--------|------|-------------|
| `WS` | `/ws` | WebSocket event stream |
| `GET` | `/hits?limit=200` | Recent honeypot hits |
| `GET` | `/hits/timeline?minutes=30` | Hit counts per minute |
| `GET` | `/stats` | Aggregate stats |
| `GET` | `/ip/{ip}` | Full history + block status for an IP |
| `GET` | `/geo?ip={ip}` | Geo lookup for an IP |
| `GET` | `/blocklist` | All blocked IPs |
| `POST` | `/block` | Block an IP `{"ip": "1.2.3.4"}` |
| `POST` | `/unblock` | Unblock an IP `{"ip": "1.2.3.4"}` |
| `POST` | `/scan` | Port-scan a host `{"host": "192.168.1.1"}` |
| `POST` | `/discover` | Ping-sweep a subnet `{"subnet": "192.168.1.0/24"}` |
| `POST` | `/alert-config` | Update Discord webhook URL `{"webhook_url": "..."}` |
| `GET` | `/export/csv` | Download all hits as CSV |

---

## WebSocket Events

All events are JSON objects with a `type` field.

| `type` | Fields | Description |
|--------|--------|-------------|
| `honeypot_hit` | `ip, port, ts, lat, lng, country, isp, rdns, banner, abuse_score, hit_count` | New connection to a honeypot port |
| `scan_result` | `host, ports[]` | Result of a port scan. Each port: `port, service, version` |
| `stats` | `total_hits, unique_ips, top_port, top_country, hits_last_hour` | Aggregate stats, sent after every hit |
| `threat_escalation` | `ip, hit_count, ts` | IP has exceeded 5 hits |
| `port_knock` | `ip, ports[], ts` | IP probed 3+ distinct ports within 30 seconds |
| `discover_host` | `ip, subnet` | Live host found during a subnet sweep |
| `discover_done` | `subnet, total` | Subnet sweep completed |
| `ip_blocked` | `ip` | IP was blocked |
| `ip_unblocked` | `ip` | IP was unblocked |

---

## CVE Matching

The port scanner shows CVE badges only when the detected service version falls within the vulnerable range. Logic:

1. nmap returns `product` + `version` (e.g. `OpenSSH 8.9p1`)
2. Each CVE entry has a `product` (substring match) and `fixed_version`
3. If the scanned version is older than `fixed_version`, the badge is shown
4. Protocol-level CVEs with no product (Telnet, RDP) are always shown regardless of version
5. If nmap returns no version string, no CVE badges are shown

CVE data lives in `backend/cve_data.json`.

---

## Honeypot Ports

| Port | Impersonates | Fake banner |
|------|-------------|-------------|
| 8022 | SSH | `SSH-2.0-OpenSSH_8.9p1 Ubuntu` |
| 8023 | Telnet | IAC DO TERM sequence |
| 8444 | HTTP | `Apache/2.4.54 200 OK` |
| 8445 | HTTP | `Apache/2.4.54 200 OK` |

Standard ports (22, 23, 80) are avoided because binding them requires root and they are likely already in use.

---

## Database

SQLite file at `backend/honeymap.db` (git-ignored, auto-created on first run).

**Tables:**

`hits` — every honeypot connection:
```
id, ip, port, ts, lat, lng, country, isp, rdns, banner, abuse_score, hit_count
```

`blocklist` — manually blocked IPs:
```
ip, blocked_at
```

---

## Project Structure

```
honeymap/
├── .env                  # ABUSEIPDB_KEY= (not committed)
├── .env.example          # Template
├── backend/
│   ├── main.py           # FastAPI app, endpoints, WebSocket hub, webhooks
│   ├── honeypot.py       # Asyncio TCP listeners
│   ├── scanner.py        # nmap wrapper + socket fallback
│   ├── geo.py            # ip-api.com, rDNS, AbuseIPDB
│   ├── db.py             # SQLite persistence
│   ├── cve_data.json     # CVE entries by service name
│   └── requirements.txt
└── frontend/
    └── index.html        # Single-file dashboard (HTML + CSS + JS)
```
