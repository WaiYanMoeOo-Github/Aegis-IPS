# Aegis-AI IPS

An autonomous, cross-platform **AI-Driven Intrusion Prevention System (IPS)** powered by **Scapy**, **FastAPI**, and a local **Ollama (`llama3.2`)** LLM agent. It monitors real-time network traffic, detects volumetric attacks and application-layer exploits, and automatically enforces OS-level firewall blocks without relying on external cloud APIs.

## Key Features
- **Real-Time Packet Inspection:** Captures live network traffic via Scapy while filtering encrypted TLS (`443`) noise to minimize false positives.
- **Autonomous AI Threat Analysis:** Uses a local Ollama LLM (`llama3.2`) to inspect payloads (SQL Injection, Path Traversal, XSS, Command Injection) and traffic spikes (ICMP Flood, Port Scanning, DDoS).
- **Cross-Platform Firewall Enforcement:** Automatically detects the host OS and applies block/unblock rules using `netsh` (Windows), `iptables` (Linux), or `pfctl` (macOS).
- **Live Web Dashboard:** Bootstrap 5 interface with real-time attack logs, AI reasoning explanations, and one-click manual block/unblock controls backed by SQLite.
- **One-Command Setup & Background Auto-Start:** Includes `setup.py` for automated environment provisioning and native background startup support (`run_hidden.vbs` on Windows, `systemd` on Linux).

## Project Structure
```text
Aegis-IPS/
├── main.py               # FastAPI backend, REST API, and SQLite state manager
├── sensor.py             # Real-time Scapy packet sniffer and rate aggregator
├── ai_agent.py           # Local Ollama LLM threat analysis agent
├── firewall_manager.py   # Cross-platform firewall controller (Windows/Linux/macOS)
├── setup.py              # Automated cross-platform venv, Ollama, and model installer
├── run_hidden.vbs        # Silent background launcher for Windows startup
├── requirements.txt      # Python dependencies
├── .gitignore            # Git exclusion rules
└── templates/
    └── index.html        # Live monitoring web dashboard
```

## Prerequisites
1. **Python 3.9+**
2. **Windows Only — Npcap:** Windows does not include a raw packet capture driver by default. Download and install [Npcap](https://npcap.com/) with **`Install Npcap in WinPcap API-compatible Mode`** checked before running `sensor.py`.

## Quick Setup (Windows, Linux & macOS)

Clone the repository and run `setup.py` to automatically create a native virtual environment (`venv`), install Python packages, install Ollama (if missing), and pull `llama3.2`:

```bash
git clone [https://github.com/WaiYanMoeOo-Github/Aegis-IPS.git](https://github.com/WaiYanMoeOo-Github/Aegis-IPS.git)
cd Aegis-IPS
python setup.py    # Use 'python3 setup.py' on Linux/macOS
```

## Running Aegis-AI IPS

Packet sniffing and firewall modification require **Administrator** (Windows) or **root** (Linux/macOS) privileges.

### Option A: Run Manually

**Windows (PowerShell / CMD as Administrator)**
```powershell
# Terminal 1: Backend & Dashboard
venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000

# Terminal 2: Real-Time Packet Sensor
venv\Scripts\python.exe sensor.py
```

**Linux & macOS (Terminal with `sudo`)**
```bash
# Terminal 1: Backend & Dashboard
sudo venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000

# Terminal 2: Real-Time Packet Sensor
sudo venv/bin/python sensor.py
```

Open `http://127.0.0.1:8000` in your browser to access the dashboard.

### Option B: Background Auto-Start on Boot

- **Windows:** Use `run_hidden.vbs` (launches both backend and sensor silently without console windows). Schedule `wscript.exe "C:\path\to\Aegis-IPS\run_hidden.vbs"` in **Task Scheduler** set to **At startup** with **Run with highest privileges** enabled.
- **Linux (Ubuntu / Kali):** Configure `systemd` services (`aegis-backend.service` and `aegis-sensor.service`) running as `User=root` pointing to `venv/bin/python`.