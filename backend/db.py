import sqlite3
import time

DB_PATH = "honeymap.db"

def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
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

def save_hit(hit: dict):
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            "INSERT INTO hits (ip,port,ts,lat,lng,country,isp,rdns,banner,abuse_score,hit_count) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (hit.get("ip"), hit.get("port"), hit.get("ts"), hit.get("lat"), hit.get("lng"),
             hit.get("country"), hit.get("isp"), hit.get("rdns"), hit.get("banner"),
             hit.get("abuse_score"), hit.get("hit_count")),
        )

def get_hits(limit: int = 200) -> list[dict]:
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT * FROM hits ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
    return [{"type": "honeypot_hit", **dict(r)} for r in rows]

def get_stats() -> dict:
    with sqlite3.connect(DB_PATH) as con:
        total = con.execute("SELECT COUNT(*) FROM hits").fetchone()[0]
        unique = con.execute("SELECT COUNT(DISTINCT ip) FROM hits").fetchone()[0]
        top_port = con.execute("SELECT port FROM hits GROUP BY port ORDER BY COUNT(*) DESC LIMIT 1").fetchone()
        top_country = con.execute("SELECT country FROM hits WHERE country IS NOT NULL GROUP BY country ORDER BY COUNT(*) DESC LIMIT 1").fetchone()
        hour_ago = int(time.time()) - 3600
        last_hour = con.execute("SELECT COUNT(*) FROM hits WHERE ts >= ?", (hour_ago,)).fetchone()[0]
    return {
        "type": "stats",
        "total_hits": total,
        "unique_ips": unique,
        "top_port": top_port[0] if top_port else None,
        "top_country": top_country[0] if top_country else None,
        "hits_last_hour": last_hour,
    }
