"""SQLite persistence for honeypot hits."""

import sqlite3
import time
from pathlib import Path

_DB_PATH = Path(__file__).parent / "honeymap.db"
_conn: sqlite3.Connection | None = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
    return _conn


def init_db() -> None:
    """Create tables if they don't exist."""
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hits (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT,
            port        INTEGER,
            ts          INTEGER,
            lat         REAL,
            lng         REAL,
            country     TEXT,
            isp         TEXT,
            rdns        TEXT,
            banner      TEXT,
            abuse_score INTEGER,
            hit_count   INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocklist (
            ip          TEXT PRIMARY KEY,
            blocked_at  INTEGER
        )
    """)
    conn.commit()


def save_hit(hit: dict) -> None:
    """Insert a honeypot hit row."""
    _get_conn().execute(
        """INSERT INTO hits (ip, port, ts, lat, lng, country, isp, rdns, banner, abuse_score, hit_count)
           VALUES (:ip, :port, :ts, :lat, :lng, :country, :isp, :rdns, :banner, :abuse_score, :hit_count)""",
        {
            "ip":          hit.get("ip"),
            "port":        hit.get("port"),
            "ts":          hit.get("ts", int(time.time())),
            "lat":         hit.get("lat"),
            "lng":         hit.get("lng"),
            "country":     hit.get("country"),
            "isp":         hit.get("isp"),
            "rdns":        hit.get("rdns"),
            "banner":      hit.get("banner"),
            "abuse_score": hit.get("abuse_score"),
            "hit_count":   hit.get("hit_count", 1),
        },
    )
    _get_conn().commit()


def get_hits(limit: int = 200) -> list[dict]:
    """Return the most recent `limit` hits as dicts with type field, newest first."""
    rows = _get_conn().execute(
        "SELECT * FROM hits ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    return [{"type": "honeypot_hit", **dict(r)} for r in rows]


# Alias used by the REST endpoint
get_recent_hits = get_hits


def get_stats() -> dict:
    """Aggregate stats across all stored hits."""
    # Use a fresh connection — this is called from worker threads via asyncio.to_thread
    with sqlite3.connect(_DB_PATH) as conn:
        total = conn.execute("SELECT COUNT(*) FROM hits").fetchone()[0]
        unique = conn.execute("SELECT COUNT(DISTINCT ip) FROM hits").fetchone()[0]

        top_port_row = conn.execute(
            "SELECT port FROM hits GROUP BY port ORDER BY COUNT(*) DESC LIMIT 1"
        ).fetchone()
        top_port = top_port_row[0] if top_port_row else None

        top_country_row = conn.execute(
            "SELECT country FROM hits WHERE country IS NOT NULL GROUP BY country ORDER BY COUNT(*) DESC LIMIT 1"
        ).fetchone()
        top_country = top_country_row[0] if top_country_row else None

        one_hour_ago = int(time.time()) - 3600
        hits_last_hour = conn.execute(
            "SELECT COUNT(*) FROM hits WHERE ts >= ?", (one_hour_ago,)
        ).fetchone()[0]

    return {
        "type": "stats",
        "total_hits": total,
        "unique_ips": unique,
        "top_port": top_port,
        "top_country": top_country,
        "hits_last_hour": hits_last_hour,
    }


def block_ip(ip: str) -> None:
    _get_conn().execute(
        "INSERT OR REPLACE INTO blocklist (ip, blocked_at) VALUES (?, ?)",
        (ip, int(time.time()))
    )
    _get_conn().commit()

def unblock_ip(ip: str) -> None:
    _get_conn().execute("DELETE FROM blocklist WHERE ip = ?", (ip,))
    _get_conn().commit()

def get_blocklist() -> list[str]:
    rows = _get_conn().execute("SELECT ip FROM blocklist ORDER BY blocked_at DESC").fetchall()
    return [r[0] for r in rows]

def is_blocked(ip: str) -> bool:
    row = _get_conn().execute("SELECT 1 FROM blocklist WHERE ip = ?", (ip,)).fetchone()
    return row is not None

def get_timeline(minutes: int = 30) -> list[dict]:
    """Return hit counts per minute for the last N minutes."""
    since = int(time.time()) - (minutes * 60)
    with sqlite3.connect(_DB_PATH) as conn:
        rows = conn.execute(
            "SELECT (ts / 60) * 60 AS bucket, COUNT(*) as count FROM hits WHERE ts >= ? GROUP BY bucket ORDER BY bucket",
            (since,)
        ).fetchall()
    buckets = {r[0]: r[1] for r in rows}
    now_bucket = (int(time.time()) // 60) * 60
    result = []
    for i in range(minutes):
        t = now_bucket - ((minutes - 1 - i) * 60)
        result.append({"ts": t, "count": buckets.get(t, 0)})
    return result

def get_ip_history(ip: str) -> list[dict]:
    """All hits from a specific IP."""
    rows = _get_conn().execute(
        "SELECT * FROM hits WHERE ip = ? ORDER BY ts DESC", (ip,)
    ).fetchall()
    return [{"type": "honeypot_hit", **dict(r)} for r in rows]

def export_csv() -> str:
    """Return all hits as a CSV string."""
    import io, csv
    rows = _get_conn().execute("SELECT ip,port,ts,country,isp,rdns,banner,abuse_score,hit_count FROM hits ORDER BY ts DESC").fetchall()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["ip","port","ts","country","isp","rdns","banner","abuse_score","hit_count"])
    w.writerows(rows)
    return out.getvalue()
