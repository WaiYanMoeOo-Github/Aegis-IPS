# Aegis-AI IPS

An autonomous, cross-platform **AI-Driven Intrusion Prevention System (IPS)** powered by **Scapy**, **FastAPI**, and a local **Ollama (`llama3.2`)** LLM agent. It monitors real-time network traffic, detects volumetric attacks and application-layer exploits, and automatically enforces OS-level firewall blocks without relying on external cloud APIs.

## Key Features
- **Real-Time Packet Inspection:** Captures live network traffic via Scapy while filtering encrypted TLS (`443`) noise to minimize false positives.
- **Autonomous AI Threat Analysis:** Uses a local Ollama LLM (`llama3.2`) to inspect payloads (SQL Injection, Path Traversal, XSS, Command Injection) and traffic rates (ICMP Flood, Port Scanning, DDoS).
- **Cross-Platform Firewall Enforcement:** Automatically detects the host OS and applies block/unblock rules using `netsh` (Windows), `iptables` (Linux), or `pfctl` (macOS).
- **Live Web Dashboard:** Bootstrap 5 interface with real-time attack logs, AI reasoning explanations, and one-click manual block/unblock controls backed by SQLite.
- **One-Command Setup & Silent Auto-Start:** Includes `setup.py` for automated environment provisioning and native background startup support (`run_hidden.vbs` + Task Scheduler on Windows, `systemd` on Linux).

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
1. **Python 3.9+** (On Windows, use standard `win_amd64` Python; `setup.py` will automatically switch if invoked from MSYS2/MinGW).
2. **Windows Only — Npcap:** Windows does not include a raw packet capture driver by default. Download and install [Npcap](https://npcap.com/) with **`Install Npcap in WinPcap API-compatible Mode`** checked before running `sensor.py`.

## Quick Setup (Windows, Linux & macOS)

Clone the repository and run `setup.py` to create a virtual environment (`venv`), install dependencies, install Ollama via its official script, and pull `llama3.2`:

```bash
git clone [https://github.com/WaiYanMoeOo-Github/Aegis-IPS.git](https://github.com/WaiYanMoeOo-Github/Aegis-IPS.git)
cd Aegis-IPS
python setup.py    # Use 'py setup.py' on Windows if MSYS2 is in PATH, or 'python3 setup.py' on Linux/macOS
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

---

### Option B: Background Auto-Start on Boot

#### 1. Windows (Silent Startup via `run_hidden.vbs` & Task Scheduler)
`run_hidden.vbs` launches both the FastAPI backend and Scapy packet sensor silently in the background with zero console windows.

**Method 1 — Quick PowerShell Setup (Run as Administrator inside `Aegis-IPS` folder):**
```powershell
$action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$PWD\run_hidden.vbs`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
Register-ScheduledTask -TaskName "Aegis-AI-IPS" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
```
*(To test immediately without rebooting, run: `Start-ScheduledTask -TaskName "Aegis-AI-IPS"`)*

**Method 2 — Manual GUI Setup (`taskschd.msc`):**
1. Press `Win + R`, type `taskschd.msc`, and press **Enter**.
2. Click **Create Task...** in the right-hand Actions pane.
3. **General Tab:**
   - **Name:** `Aegis-AI-IPS`
   - Select **Run whether user is logged on or not**
   - Check **Run with highest privileges**
4. **Triggers Tab:** Click **New...** ➔ set **Begin the task** to **At startup** ➔ click **OK**.
5. **Actions Tab:** Click **New...** ➔ set **Action** to **Start a program**:
   - **Program/script:** `wscript.exe`
   - **Add arguments (optional):** `"C:\full\path\to\Aegis-IPS\run_hidden.vbs"` *(wrap path in double quotes if it contains spaces)*
6. **Conditions & Settings Tabs:**
   - Uncheck **Start the task only if the computer is on AC power** (recommended for laptops).
   - Uncheck **Stop the task if it runs longer than: 3 days** so the IPS runs continuously.
7. Click **OK** to save.

#### 2. Linux (Ubuntu / Kali via `systemd`)
Create two `systemd` unit files pointing to your `Aegis-IPS` directory (`User=root`) for the backend (`uvicorn`) and `sensor.py`, then enable both with `sudo systemctl enable --now aegis-backend aegis-sensor`.