"""nmap wrapper — falls back to raw socket scan if nmap is not installed."""

import asyncio
import socket
from typing import Callable, Awaitable

try:
    import nmap  # type: ignore
    _NMAP_AVAILABLE = True
except ImportError:
    _NMAP_AVAILABLE = False


# Ports to probe in fallback mode
_FALLBACK_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]

_SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 8080: "http-alt", 8443: "https-alt",
}


def _nmap_scan(host: str) -> list[dict]:
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments="-sV --open -T4")
    results = []
    for h in nm.all_hosts():
        for proto in nm[h].all_protocols():
            for port, info in nm[h][proto].items():
                if info["state"] == "open":
                    results.append({
                        "port": port,
                        "service": info.get("name", ""),
                        "version": f"{info.get('product', '')} {info.get('version', '')}".strip(),
                    })
    return results


def _socket_scan(host: str) -> list[dict]:
    results = []
    for port in _FALLBACK_PORTS:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                results.append({
                    "port": port,
                    "service": _SERVICE_NAMES.get(port, "unknown"),
                    "version": "",
                })
        except (OSError, ConnectionRefusedError):
            pass
    return results


async def scan_host(
    host: str,
    broadcast: Callable[[dict], Awaitable[None]],
) -> list[dict]:
    """Run a scan and broadcast the result. Returns the port list."""
    loop = asyncio.get_event_loop()

    if _NMAP_AVAILABLE:
        ports = await loop.run_in_executor(None, _nmap_scan, host)
    else:
        print("[scanner] nmap not found — using raw socket fallback")
        ports = await loop.run_in_executor(None, _socket_scan, host)

    message = {"type": "scan_result", "host": host, "ports": ports}
    await broadcast(message)
    return ports
