import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2"

def analyze_traffic(ip: str, protocol: str, port: int, packet_count: int, payload: str = "") -> dict:
    """
    Send network traffic telemetry and optional payload to the local Ollama AI Agent.
    Applies stricter rate thresholds for ICMP (normal ping is ~1 pkt/s).
    """
    proto = protocol.upper()

    if proto == "ICMP":
        if packet_count >= 15:
            volume_tier = "CRITICAL (ICMP >= 15 pkt/s - Ping Flood / ICMP Anomaly)"
        else:
            volume_tier = "LOW (Normal ICMP rate)"
    elif packet_count > 500:
        volume_tier = "CRITICAL (> 500 pkt/s - Severe Volumetric Anomaly)"
    elif packet_count >= 100:
        volume_tier = "ELEVATED (100-500 pkt/s - Suspicious Activity)"
    else:
        volume_tier = "LOW (< 100 pkt/s - Check Payload First)"

    system_prompt = """You are an autonomous Cybersecurity Intrusion Prevention System (IPS) AI Agent.
You MUST analyze BOTH the Payload Sample AND the Volume Tier.

STRICT DECISION ORDER:
Step 1 (Payload Inspection - HIGHEST PRIORITY):
Inspect the Payload Sample for ANY exploit patterns, even if Volume Tier is LOW:
- Directory/Path Traversal (e.g., '../', '..\\', '/etc/passwd', 'win.ini') -> MUST BLOCK
- SQL Injection (e.g., "' OR ", "UNION SELECT", "--") -> MUST BLOCK
- XSS / Command Injection (e.g., '<script>', '; cat ', '| whoami') -> MUST BLOCK
If a malicious payload is found, set "is_attack": true, "action": "block", and name the exact attack.

Step 2 (Volume Inspection):
If Volume Tier is CRITICAL or ELEVATED, classify the attack based on protocol, port, and behavior (e.g., ICMP Ping Flood, Port Scanning, Brute Force, DDoS), and set "is_attack": true, "action": "block".

Step 3 (Normal Traffic):
ONLY if Volume Tier is LOW AND the Payload Sample is completely benign or 'None', set "is_attack": false, "attack_name": "Normal Traffic", "action": "ignore".

Respond ONLY in valid JSON with exact keys: "is_attack", "attack_name", "action", "reason"."""

    prompt = f"""
Example 1 (Low-Volume Path Traversal):
Input: IP=91.134.12.10, Protocol=TCP, Port=8080, Packets/sec=5, Volume Tier=LOW (< 100 pkt/s - Check Payload First), Payload Sample="GET /download?file=../../../../etc/passwd HTTP/1.1"
Output: {{"is_attack": true, "attack_name": "Path Traversal", "action": "block", "reason": "Payload contains directory traversal sequence (../) attempting to access /etc/passwd."}}

Example 2 (ICMP Ping Flood):
Input: IP=192.168.1.55, Protocol=ICMP, Port=0, Packets/sec=35, Volume Tier=CRITICAL (ICMP >= 15 pkt/s - Ping Flood / ICMP Anomaly), Payload Sample="None"
Output: {{"is_attack": true, "attack_name": "ICMP Ping Flood", "action": "block", "reason": "ICMP traffic at 35 packets/sec exceeds normal ping rate, indicating a Ping Flood."}}

Example 3 (Normal Traffic):
Input: IP=192.168.1.10, Protocol=TCP, Port=443, Packets/sec=25, Volume Tier=LOW (< 100 pkt/s - Check Payload First), Payload Sample="GET /index.html HTTP/1.1"
Output: {{"is_attack": false, "attack_name": "Normal Traffic", "action": "ignore", "reason": "Low packet rate with a standard benign HTTP request."}}

Now analyze this real-time network event:
Input: IP={ip}, Protocol={proto}, Port={port}, Packets/sec={packet_count}, Volume Tier={volume_tier}, Payload Sample="{payload if payload else 'None'}"
Output:
"""
    request_body = {
        "model": MODEL_NAME,
        "system": system_prompt,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.0
        }
    }

    try:
        response = requests.post(OLLAMA_URL, json=request_body, timeout=120)
        response.raise_for_status()
        raw_text = response.json().get("response", "{}")
        decision = json.loads(raw_text)
        return decision
    except Exception as e:
        print(f"[AI AGENT ERROR] {e}")
        is_attack = (proto == "ICMP" and packet_count >= 15) or (packet_count >= 100)
        return {
            "is_attack": is_attack,
            "attack_name": "ICMP Ping Flood (Fallback)" if (proto == "ICMP" and is_attack) else ("Anomalous Traffic (Fallback)" if is_attack else "Normal Traffic"),
            "action": "block" if is_attack else "ignore",
            "reason": "Ollama connection failed; used volume-based fallback."
        }