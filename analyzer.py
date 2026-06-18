from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict

SUSPICIOUS_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP",
    4444: "Metasploit", 5900: "VNC",
    6666: "Malware C2", 31337: "Elite/Backdoor"
}

SAFE_PORTS = {80: "HTTP", 443: "HTTPS", 53: "DNS", 8080: "HTTP-Alt"}

def analyze(filepath):
    packets = rdpcap(filepath)
    traffic = defaultdict(list)

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
            port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
            traffic[src].append({"dst": dst, "port": port, "proto": proto})

    alerts = []
    ip_summary = []

    for src, conns in traffic.items():
        ports_hit = set(c["port"] for c in conns if c["port"])
        conn_count = len(conns)
        risk = "Low"
        reasons = []

        # Rule 1: Port scan
        if len(ports_hit) > 15:
            risk = "High"
            reasons.append(f"Port scan: {len(ports_hit)} unique ports hit")

        # Rule 2: Suspicious ports
        for port in ports_hit & set(SUSPICIOUS_PORTS.keys()):
            risk = "High"
            reasons.append(f"Suspicious port {port} ({SUSPICIOUS_PORTS[port]})")
            alerts.append({
                "src": src,
                "port": port,
                "service": SUSPICIOUS_PORTS[port],
                "reason": f"Known high-risk port used by {src}"
            })

        # Rule 3: Traffic flood
        if conn_count > 200:
            risk = "Medium" if risk == "Low" else risk
            reasons.append(f"High traffic volume: {conn_count} packets")

        ip_summary.append({
            "ip": src,
            "connections": conn_count,
            "unique_ports": len(ports_hit),
            "risk": risk,
            "reasons": reasons
        })

    # Sort by risk
    risk_order = {"High": 0, "Medium": 1, "Low": 2}
    ip_summary.sort(key=lambda x: risk_order[x["risk"]])

    return {
        "total_packets": len(packets),
        "unique_ips": len(traffic),
        "alerts": alerts,
        "ip_summary": ip_summary[:20]  # top 20
    }