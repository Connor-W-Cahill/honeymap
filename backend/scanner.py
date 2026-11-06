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
_FALLBACK_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8022, 8023, 8080, 8443, 8444, 8445]

_SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 8022: "ssh", 8023: "telnet",
    8080: "http-alt", 8443: "https-alt", 8444: "http-alt", 8445: "http-alt",
}

# Scan the top 1000 ports plus the honeypot ports explicitly
_SCAN_PORTS = "1-1024,3306,3389,8022,8023,8080,8443,8444,8445"


def _nmap_scan(host: str) -> list[dict]:
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments=f"-sV --open -T5 --version-intensity 0 -p {_SCAN_PORTS}")
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


def _ping_sweep(subnet: str) -> list[str]:
    """Return list of live IPs in the subnet using nmap ping sweep."""
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments="-sn -T4 --open")
    return [h for h in nm.all_hosts() if nm[h].state() == "up"]


def _socket_ping(subnet: str) -> list[str]:
    """Fallback: try TCP connect on port 80 and 22 for each host in a /24."""
    import ipaddress
    live = []
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        hosts = list(net.hosts())[:254]  # cap at /24
    except ValueError:
        return []
    for ip in hosts:
        for port in (80, 22, 443):
            try:
                with socket.create_connection((str(ip), port), timeout=0.3):
                    live.append(str(ip))
                    break
            except OSError:
                pass
    return live


async def discover_network(
    subnet: str,
    broadcast: Callable[[dict], Awaitable[None]],
) -> list[str]:
    """Ping-sweep a subnet, broadcast each live host, then broadcast done."""
    loop = asyncio.get_event_loop()

    if _NMAP_AVAILABLE:
        live_hosts = await loop.run_in_executor(None, _ping_sweep, subnet)
    else:
        live_hosts = await loop.run_in_executor(None, _socket_ping, subnet)

    for ip in live_hosts:
        await broadcast({"type": "discover_host", "ip": ip, "subnet": subnet})

    await broadcast({"type": "discover_done", "subnet": subnet, "total": len(live_hosts)})
    return live_hosts
