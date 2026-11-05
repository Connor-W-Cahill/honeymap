"""Geo lookup, reverse DNS, and AbuseIPDB enrichment."""

import asyncio
import os
import socket

import httpx
from dotenv import load_dotenv

load_dotenv()

_geo_cache: dict[str, dict] = {}
_abuse_cache: dict[str, int | None] = {}

_GEO_FALLBACK = {"lat": None, "lng": None, "country": None, "isp": None}


async def lookup(ip: str) -> dict:
    """Return {lat, lng, country, isp} for the given IP. Returns nulls on failure."""
    if ip in _geo_cache:
        return _geo_cache[ip]

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}?fields=lat,lon,country,isp,status"
            )
            d = r.json()
            if d.get("status") == "success":
                result = {
                    "lat": d["lat"],
                    "lng": d["lon"],
                    "country": d["country"],
                    "isp": d["isp"],
                }
                _geo_cache[ip] = result
                return result
    except Exception:
        pass

    return _GEO_FALLBACK


async def rdns(ip: str) -> str | None:
    """Reverse DNS lookup — returns hostname string or None."""
    try:
        hostname, _, _ = await asyncio.to_thread(socket.gethostbyaddr, ip)
        return hostname
    except Exception:
        return None


async def abuse_score(ip: str) -> int | None:
    """AbuseIPDB confidence score 0–100, or None if key not set / lookup fails."""
    if ip in _abuse_cache:
        return _abuse_cache[ip]

    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        return None

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": key, "Accept": "application/json"},
            )
            score = r.json()["data"]["abuseConfidenceScore"]
            _abuse_cache[ip] = score
            return score
    except Exception:
        _abuse_cache[ip] = None
        return None
