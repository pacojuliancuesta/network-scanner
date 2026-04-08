import nmap
import json
import socket
import struct
import datetime
import os
from jinja2 import Environment, FileSystemLoader

NETWORK = "192.168.1.134/24"  # Cambia esto a tu red

RISK_PORTS = {
    21:   {"name": "FTP",        "risk": "high",   "desc": "File transfer — often unencrypted"},
    22:   {"name": "SSH",        "risk": "medium",  "desc": "Secure shell — check auth config"},
    23:   {"name": "Telnet",     "risk": "critical","desc": "Unencrypted remote access"},
    25:   {"name": "SMTP",       "risk": "medium",  "desc": "Mail server"},
    53:   {"name": "DNS",        "risk": "low",     "desc": "Domain name resolution"},
    80:   {"name": "HTTP",       "risk": "medium",  "desc": "Web server — unencrypted"},
    110:  {"name": "POP3",       "risk": "high",    "desc": "Mail retrieval — often unencrypted"},
    135:  {"name": "RPC",        "risk": "high",    "desc": "Windows RPC — common attack vector"},
    139:  {"name": "NetBIOS",    "risk": "high",    "desc": "Windows file sharing"},
    143:  {"name": "IMAP",       "risk": "medium",  "desc": "Mail access protocol"},
    443:  {"name": "HTTPS",      "risk": "low",     "desc": "Encrypted web server"},
    445:  {"name": "SMB",        "risk": "critical","desc": "Windows sharing — EternalBlue target"},
    1433: {"name": "MSSQL",      "risk": "high",    "desc": "Microsoft SQL Server"},
    3306: {"name": "MySQL",      "risk": "high",    "desc": "MySQL database"},
    3389: {"name": "RDP",        "risk": "critical","desc": "Remote Desktop — brute force target"},
    5900: {"name": "VNC",        "risk": "high",    "desc": "Remote desktop — often unencrypted"},
    6379: {"name": "Redis",      "risk": "critical","desc": "Database — often no auth by default"},
    8080: {"name": "HTTP-Alt",   "risk": "medium",  "desc": "Alternative web port"},
    8443: {"name": "HTTPS-Alt",  "risk": "low",     "desc": "Alternative HTTPS port"},
    27017:{"name": "MongoDB",    "risk": "critical","desc": "Database — often no auth by default"},
}

def get_risk_level(ports):
    levels = [RISK_PORTS.get(p, {}).get("risk", "low") for p in ports]
    if "critical" in levels: return "critical"
    if "high"     in levels: return "high"
    if "medium"   in levels: return "medium"
    return "low"

def scan_network(network):
    print(f"[*] Scanning {network} ...")
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments="-sS -sV -O --top-ports 100 -T4")

    devices = []
    for host in nm.all_hosts():
        if nm[host].state() != "up":
            continue

        open_ports = []
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                state   = nm[host][proto][port]["state"]
                service = nm[host][proto][port]["name"]
                version = nm[host][proto][port].get("version", "")
                if state == "open":
                    port_info = RISK_PORTS.get(port, {
                        "name": service,
                        "risk": "low",
                        "desc": "Unknown service"
                    })
                    open_ports.append({
                        "port":    port,
                        "service": port_info["name"],
                        "version": version,
                        "risk":    port_info["risk"],
                        "desc":    port_info["desc"],
                    })

        hostname = ""
        try:
            hostname = socket.gethostbyaddr(host)[0]
        except:
            hostname = "Unknown"

        os_name = "Unknown"
        try:
            os_matches = nm[host].get("osmatch", [])
            if os_matches:
                os_name = os_matches[0]["name"]
        except:
            pass

        devices.append({
            "ip":         host,
            "hostname":   hostname,
            "os":         os_name,
            "ports":      open_ports,
            "risk_level": get_risk_level([p["port"] for p in open_ports]),
            "port_count": len(open_ports),
        })

    return sorted(devices, key=lambda x: struct.unpack("!I",
        socket.inet_aton(x["ip"]))[0])

def generate_report(devices, network):
    env      = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report.html")

    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for d in devices:
        risk_counts[d["risk_level"]] += 1

    port_frequency = {}
    for d in devices:
        for p in d["ports"]:
            name = p["service"]
            port_frequency[name] = port_frequency.get(name, 0) + 1
    top_ports = sorted(port_frequency.items(), key=lambda x: x[1], reverse=True)[:8]

    html = template.render(
        devices      = devices,
        network      = network,
        scan_time    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_hosts  = len(devices),
        risk_counts  = risk_counts,
        top_ports    = top_ports,
    )

    os.makedirs("reports", exist_ok=True)
    filename = f"reports/scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, "w") as f:
        f.write(html)

    print(f"[+] Report saved: {filename}")
    return filename

if __name__ == "__main__":
    devices = scan_network(NETWORK)
    print(f"[+] Found {len(devices)} active hosts")
    generate_report(devices, NETWORK)
