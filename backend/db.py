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
    """Create the hits table if it doesn't exist."""
    _get_conn().execute("""
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
    _get_conn().commit()


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
    conn = _get_conn()
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
