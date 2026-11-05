import nmap

def scan(host: str) -> dict:
    nm = nmap.PortScanner()
    nm.scan(host, arguments="-sV --open -T4")
    ports = []
    for h in nm.all_hosts():
        for proto in nm[h].all_protocols():
            for port, info in nm[h][proto].items():
                ports.append({
                    "port": port,
                    "service": info.get("name", ""),
                    "version": info.get("version", ""),
                })
    return {"type": "scan_result", "host": host, "ports": ports}
