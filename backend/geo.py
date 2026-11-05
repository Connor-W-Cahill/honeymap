import httpx

async def lookup(ip: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}")
            d = r.json()
            return {
                "lat": d.get("lat"),
                "lng": d.get("lon"),
                "country": d.get("countryCode"),
                "isp": d.get("isp"),
            }
    except Exception:
        return {"lat": None, "lng": None, "country": None, "isp": None}
