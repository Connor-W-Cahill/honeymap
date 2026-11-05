import asyncio
import os
import socket
import httpx

_geo_cache: dict = {}
_abuse_cache: dict = {}

async def lookup(ip: str) -> dict:
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}")
            d = r.json()
            result = {
                "lat": d.get("lat"),
                "lng": d.get("lon"),
                "country": d.get("countryCode"),
                "isp": d.get("isp"),
            }
    except Exception:
        result = {"lat": None, "lng": None, "country": None, "isp": None}
    _geo_cache[ip] = result
    return result

async def rdns(ip: str) -> str | None:
    try:
        hostname, _, _ = await asyncio.to_thread(socket.gethostbyaddr, ip)
        return hostname
    except Exception:
        return None

async def abuse_score(ip: str) -> int | None:
    if ip in _abuse_cache:
        return _abuse_cache[ip]
    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        return None
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": key, "Accept": "application/json"},
            )
            score = r.json()["data"]["abuseConfidenceScore"]
            _abuse_cache[ip] = score
            return score
    except Exception:
        return None
