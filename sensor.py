import socket
import time
import threading
import requests
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

API_URL = "http://127.0.0.1:8000/api/analyze"
WINDOW_SECONDS = 3
HIGH_VOLUME_THRESHOLD = 30  # Only report high-volume traffic (>= 30 packets in 3s)
PLAINTEXT_PORTS = {80, 8000, 8080, 21, 23, 25}  # Inspect payloads only on unencrypted ports

TCP_FLAG_NAMES = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}

def get_local_ip() -> str:
    """Detect the primary local IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def is_printable_ascii(text: str) -> bool:
    """Return True if at least 85% of characters are readable ASCII (filters out encrypted binary)."""
    if not text:
        return False
    printable = sum(32 <= ord(c) <= 126 or c in "\r\n\t" for c in text)
    return (printable / len(text)) >= 0.85

def format_tcp_flags(tcp_layer) -> str:
    """Convert Scapy TCP flags (e.g., 'S', 'PA', 'FPU', '') into readable labels."""
    raw_flags = str(tcp_layer.flags)
    if not raw_flags:
        return "NULL"
    return "-".join(TCP_FLAG_NAMES.get(ch, ch) for ch in raw_flags)

LOCAL_IP = get_local_ip()
traffic_lock = threading.Lock()
traffic_stats = defaultdict(
    lambda: {"protocol": "OTHER", "tcp_flags": [], "port": 0, "count": 0, "payload": ""}
)

def process_packet(packet):
    """Callback triggered for every captured incoming IP packet."""
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Monitor only incoming traffic targeting this host
    if src_ip == LOCAL_IP or src_ip == "127.0.0.1" or dst_ip != LOCAL_IP:
        return

    protocol = "OTHER"
    tcp_flag = "-"
    dst_port = 0
    src_port = 0

    if packet.haslayer(TCP):
        protocol = "TCP"
        dst_port = packet[TCP].dport
        src_port = packet[TCP].sport
        tcp_flag = format_tcp_flags(packet[TCP])
    elif packet.haslayer(UDP):
        protocol = "UDP"
        dst_port = packet[UDP].dport
        src_port = packet[UDP].sport
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    else:
        return

    # Ignore normal HTTPS/QUIC web browsing responses coming back from external port 443
    if src_port == 443 or dst_port == 443:
        return

    payload_text = ""
    if packet.haslayer(Raw) and dst_port in PLAINTEXT_PORTS:
        try:
            raw_bytes = packet[Raw].load[:200]
            decoded = raw_bytes.decode("utf-8", errors="ignore").strip()
            if is_printable_ascii(decoded):
                payload_text = decoded
        except Exception:
            payload_text = ""

    with traffic_lock:
        entry = traffic_stats[src_ip]
        entry["protocol"] = protocol
        entry["port"] = dst_port
        entry["count"] += 1
        if tcp_flag != "-" and tcp_flag not in entry["tcp_flags"] and len(entry["tcp_flags"]) < 3:
            entry["tcp_flags"].append(tcp_flag)
        if payload_text and not entry["payload"]:
            entry["payload"] = payload_text

def flush_and_analyze():
    """Aggregate captured traffic every WINDOW_SECONDS and send to the IPS backend."""
    while True:
        time.sleep(WINDOW_SECONDS)
        with traffic_lock:
            snapshot = dict(traffic_stats)
            traffic_stats.clear()

        for ip, info in snapshot.items():
            pkt_per_sec = max(1, info["count"] // WINDOW_SECONDS)
            has_payload = bool(info["payload"])

            # Forward only if traffic is high-volume OR contains a readable plaintext payload
            if info["count"] >= HIGH_VOLUME_THRESHOLD or has_payload:
                tcp_flags_str = ", ".join(info["tcp_flags"]) if info["tcp_flags"] else "-"
                telemetry = {
                    "ip": ip,
                    "protocol": info["protocol"],
                    "tcp_flags": tcp_flags_str,
                    "port": info["port"],
                    "packet_count": pkt_per_sec,
                    "payload": info["payload"],
                }
                flag_display = f" [{tcp_flags_str}]" if tcp_flags_str != "-" else ""
                print(f"[REAL SENSOR] Forwarding {ip} ({info['protocol']}{flag_display}:{info['port']}, {pkt_per_sec} pkt/s)")
                try:
                    requests.post(API_URL, json=telemetry, timeout=120)
                except Exception as e:
                    print(f"[SENSOR ERROR] Failed to reach IPS API: {e}")

if __name__ == "__main__":
    print(f"[REAL PACKET SENSOR] Monitoring incoming traffic on {LOCAL_IP} ...")
    print("Ignoring encrypted Port 443 responses to prevent false positives.")

    reporter_thread = threading.Thread(target=flush_and_analyze, daemon=True)
    reporter_thread.start()

    sniff(filter="ip", prn=process_packet, store=False)