# Aegis-AI IPS

An autonomous, cross-platform **AI-Driven Intrusion Prevention System (IPS)** powered by **Scapy**, **FastAPI**, and a local **Ollama (`llama3.2`)** LLM agent. It monitors real-time network traffic, detects volumetric attacks and application-layer exploits, and automatically enforces OS-level firewall blocks without relying on external cloud APIs.
<br><br>

## Key Features
- **Real-Time Packet Inspection:** Captures live network traffic via Scapy while filtering encrypted TLS (`443`) noise to minimize false positives.
- **Autonomous AI Threat Analysis:** Uses a local Ollama LLM (`llama3.2`) to inspect payloads (SQL Injection, Path Traversal, XSS, Command Injection) and traffic rates (ICMP Flood, Port Scanning, DDoS).
- **Cross-Platform Firewall Enforcement:** Automatically detects the host OS and applies block/unblock rules using `netsh` (Windows), `iptables` (Linux), or `pfctl` (macOS).
- **Live Web Dashboard:** Bootstrap 5 interface with real-time attack logs, AI reasoning explanations, and one-click manual block/unblock controls backed by SQLite.
- **One-Command Setup & Silent Auto-Start:** Includes `setup.py` for automated environment provisioning and native background startup support (`run_hidden.vbs` + Task Scheduler on Windows, `systemd` on Linux, `launchd` on macOS).
<br><br>

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
<br>

## Prerequisites
1. **Python 3.9+**
2. **Windows Only — Npcap:** Download and install [Npcap](https://npcap.com/) with **`Install Npcap in WinPcap API-compatible Mode`** checked before running `sensor.py`.
<br><br><br>

## Quick Setup

Clone the repository:
<br>

**Open Powershell or Terminal**
```bash
git clone [https://github.com/WaiYanMoeOo-Github/Aegis-IPS.git](https://github.com/WaiYanMoeOo-Github/Aegis-IPS.git)
cd Aegis-IPS
```
<br>

Run `setup.py` to create a virtual environment (`venv`), install dependencies, install Ollama, and pull `llama3.2`:
<br>

**Windows**
```powershell
python setup.py    # Or 'py setup.py' if MSYS2 is in PATH
```
<br>

**Linux & MacOS**
```bash
sudo -v && python3 setup.py
```
<br>

## Running Aegis-AI IPS

Packet sniffing and firewall modification require **Administrator** (Windows) or **root** (Linux/macOS) privileges.

<br>

### Option A: Run Manually

**Windows (PowerShell / CMD as Administrator)**
```powershell
# Terminal 1: Backend & Dashboard
venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000

# Terminal 2: Real-Time Packet Sensor
venv\Scripts\python.exe sensor.py
```
<br>

**Linux & MacOS (Terminal with `sudo`)**
```bash
# Terminal 1: Backend & Dashboard
sudo venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000

# Terminal 2: Real-Time Packet Sensor
sudo venv/bin/python sensor.py
```
<br>

Open `http://127.0.0.1:8000` in your browser to access the dashboard.

<br>

---

### Option B: Background Auto-Start on Boot

#### 1. Windows (Task Scheduler GUI)
1. Press `Win + R`, type `taskschd.msc`, and press **Enter** (or open Task Scheduler as Administrator).
2. Click **Create Task...** in the right-hand Actions pane.
3. **General Tab:** Enter **Name** (`Aegis-AI-IPS`), click **Change User or Group...** ➔ type `SYSTEM` ➔ click **OK**, and check **Run with highest privileges**.
4. **Triggers Tab:** Click **New...** ➔ set **Begin the task** to **At startup** ➔ click **OK**.
5. **Actions Tab:** Click **New...** ➔ set **Program/script** to `wscript.exe`, **Add arguments** to `"C:\full\path\to\Aegis-IPS\run_hidden.vbs"`, and **Start in** to `C:\full\path\to\Aegis-IPS` ➔ click **OK**.
6. **Conditions & Settings Tabs:** Uncheck **Start the task only if the computer is on AC power** and **Stop the task if it runs longer than: 3 days**.
7. Click **OK** to save.

<br><br>

#### 2. Linux (Ubuntu / Kali via `systemd`)
Run `sudo nano /etc/systemd/system/aegis-backend.service`, paste the following:
- Replace `/path/to/Aegis-IPS` with your actual project directory path.

```ini
[Unit]
Description=Aegis-AI IPS FastAPI Backend
After=network.target ollama.service

[Service]
User=root
WorkingDirectory=/path/to/Aegis-IPS
ExecStart="/path/to/Aegis-IPS/venv/bin/python" -m uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```
Save File: (`Ctrl + O`, `Enter`, `Ctrl + X`).
<br><br>

2. Create `/etc/systemd/system/aegis-sensor.service`:
```ini
[Unit]
Description=Aegis-AI IPS Scapy Packet Sensor
After=network.target aegis-backend.service
Requires=aegis-backend.service

[Service]
User=root
WorkingDirectory=/path/to/Aegis-IPS
ExecStart="/path/to/Aegis-IPS/venv/bin/python" "/path/to/Aegis-IPS/sensor.py"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```
<br>

3. Enable and start both services:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-backend aegis-sensor
```
<br><br>

#### 3. macOS (via `launchd` / `LaunchDaemons`)
Replace `/path/to/Aegis-IPS` with your actual project directory path.

1. Create `/Library/LaunchDaemons/com.aegis.backend.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "[http://www.apple.com/DTDs/PropertyList-1.0.dtd](http://www.apple.com/DTDs/PropertyList-1.0.dtd)">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aegis.backend</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/Aegis-IPS/venv/bin/python</string>
        <string>-m</string>
        <string>uvicorn</string>
        <string>main:app</string>
        <string>--host</string>
        <string>0.0.0.0</string>
        <string>--port</string>
        <string>8000</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/path/to/Aegis-IPS</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```
<br>

2. Create `/Library/LaunchDaemons/com.aegis.sensor.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "[http://www.apple.com/DTDs/PropertyList-1.0.dtd](http://www.apple.com/DTDs/PropertyList-1.0.dtd)">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aegis.sensor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/Aegis-IPS/venv/bin/python</string>
        <string>/path/to/Aegis-IPS/sensor.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/path/to/Aegis-IPS</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```
<br>

3. Set permissions and load both daemons:
```bash
sudo chown root:wheel /Library/LaunchDaemons/com.aegis.backend.plist /Library/LaunchDaemons/com.aegis.sensor.plist
sudo chmod 644 /Library/LaunchDaemons/com.aegis.backend.plist /Library/LaunchDaemons/com.aegis.sensor.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.aegis.backend.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.aegis.sensor.plist
```
<br>

---

## Uninstall / Clean Removal

To completely remove auto-start, Ollama (including downloaded models), `venv`, and the `Aegis-IPS` directory:
<br>

### 1. Windows (PowerShell as Administrator)
1. Stop and delete the Task Scheduler task, running processes, and firewall rules:
```powershell
Stop-ScheduledTask -TaskName "Aegis-AI-IPS" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "Aegis-AI-IPS" -Confirm:$false -ErrorAction SilentlyContinue
Stop-Process -Name "python", "wscript", "ollama*" -Force -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayName "Aegis*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
```
<br>

2. Uninstall Ollama and delete model files:
```powershell
& "$env:LOCALAPPDATA\Programs\Ollama\unins000.exe" /SILENT
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:LOCALAPPDATA\Programs\Ollama", "$env:USERPROFILE\.ollama"
```
<br>

3. Delete the `Aegis-IPS` folder (includes `venv`):
```powershell
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "C:\full\path\to\Aegis-IPS"
```
<br><br>

### 2. Linux (Ubuntu / Kali)
1. Stop, disable, and delete `systemd` services:
```bash
sudo systemctl stop aegis-backend aegis-sensor ollama 2>/dev/null
sudo systemctl disable aegis-backend aegis-sensor ollama 2>/dev/null
sudo rm -f /etc/systemd/system/aegis-backend.service /etc/systemd/system/aegis-sensor.service /etc/systemd/system/ollama.service
sudo systemctl daemon-reload
```
<br>

2. Remove Ollama binary, models, and service user:
```bash
sudo rm -f /usr/local/bin/ollama /usr/bin/ollama
sudo rm -rf /usr/share/ollama ~/.ollama
sudo userdel ollama 2>/dev/null; sudo groupdel ollama 2>/dev/null
```
<br>

3. Delete the `Aegis-IPS` folder (includes `venv`):
```bash
rm -rf /path/to/Aegis-IPS
```
<br><br>

### 3. macOS
1. Unload and delete `launchd` daemons:
```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.aegis.backend.plist 2>/dev/null
sudo launchctl bootout system /Library/LaunchDaemons/com.aegis.sensor.plist 2>/dev/null
sudo rm -f /Library/LaunchDaemons/com.aegis.backend.plist /Library/LaunchDaemons/com.aegis.sensor.plist
```
<br>

2. Remove Ollama app, CLI binary, and models:
```bash
pkill -f Ollama 2>/dev/null; pkill -f ollama 2>/dev/null
sudo rm -rf /Applications/Ollama.app /usr/local/bin/ollama ~/.ollama
```
<br>

3. Delete the `Aegis-IPS` folder (includes `venv`):
```bash
rm -rf /path/to/Aegis-IPS
```
