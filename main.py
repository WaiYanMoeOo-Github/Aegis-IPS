from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from datetime import datetime
import sqlite3
import time
import os
from ai_agent import analyze_traffic
from firewall_manager import execute_firewall_action

app = FastAPI(title="Aegis IPS Dashboard")
templates = Jinja2Templates(directory="templates")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "aegis.db")

def get_db_connection():
    """Open a new SQLite connection with row dictionary access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the SQLite database and create the attack_logs table if missing."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT NOT NULL,
            ip TEXT UNIQUE NOT NULL,
            attack TEXT NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL,
            updated_at REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Initialize database on server startup
init_db()

class ActionRequest(BaseModel):
    ip: str
    action: str  # "block" or "unblock"

class TrafficData(BaseModel):
    ip: str
    protocol: str
    port: int
    packet_count: int
    payload: str = ""

def run_firewall_script(action: str, ip: str) -> str:
    """Delegate firewall enforcement to the cross-platform firewall manager."""
    return execute_firewall_action(action, ip)

@app.get("/")
async def dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/api/logs")
async def get_logs():
    """Fetch all threat logs ordered by most recently updated."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, time, ip, attack, reason, status FROM attack_logs ORDER BY updated_at DESC"
    ).fetchall()
    conn.close()
    return {"logs": [dict(row) for row in rows]}

@app.post("/api/action")
async def execute_action(req: ActionRequest):
    """Manually block or unblock an IP and persist the new status in SQLite."""
    try:
        output = run_firewall_script(req.action, req.ip)
        new_status = "Blocked" if req.action == "block" else "Unblocked"

        conn = get_db_connection()
        conn.execute(
            "UPDATE attack_logs SET status = ?, updated_at = ? WHERE ip = ?",
            (new_status, time.time(), req.ip)
        )
        conn.commit()
        conn.close()

        return {
            "status": "success",
            "message": f"Successfully {req.action}ed {req.ip}",
            "output": output
        }
    except Exception as e:
        print(f"[ERROR] {str(e)}", flush=True)
        return {"status": "error", "message": str(e)}

@app.post("/api/analyze")
async def analyze_and_prevent(data: TrafficData):
    """Receive traffic telemetry, consult AI Agent, auto-block if malicious, and preserve Blocked status."""
    conn = get_db_connection()
    existing = conn.execute(
        "SELECT id, time, ip, attack, reason, status FROM attack_logs WHERE ip = ?", (data.ip,)
    ).fetchone()

    # If the IP is already Blocked, do NOT let subsequent low-volume traffic overwrite it to Normal/Unblocked
    if existing and existing["status"] == "Blocked":
        print(f"[IPS] Ignoring telemetry from already-blocked IP: {data.ip}", flush=True)
        conn.close()
        return {
            "status": "already_blocked",
            "log": dict(existing)
        }

    print(f"\n[SENSOR ALERT] Analyzing {data.ip} ({data.protocol}:{data.port}, {data.packet_count} pkt/s)...", flush=True)
    decision = analyze_traffic(data.ip, data.protocol, data.port, data.packet_count, data.payload)
    print(f"[AI DECISION] {decision}", flush=True)

    status = "Unblocked"
    if decision.get("is_attack") and decision.get("action") == "block":
        run_firewall_script("block", data.ip)
        status = "Blocked"

    current_time = datetime.now().strftime("%H:%M:%S")
    attack_name = decision.get("attack_name", "Unknown Threat")
    reason = decision.get("reason", "No reasoning provided by AI Agent.")
    now_ts = time.time()

    # Insert new IP or update existing IP record cleanly without duplicates
    conn.execute("""
        INSERT INTO attack_logs (time, ip, attack, reason, status, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            time = excluded.time,
            attack = excluded.attack,
            reason = excluded.reason,
            status = excluded.status,
            updated_at = excluded.updated_at
    """, (current_time, data.ip, attack_name, reason, status, now_ts))
    conn.commit()

    active_row = conn.execute(
        "SELECT id, time, ip, attack, reason, status FROM attack_logs WHERE ip = ?", (data.ip,)
    ).fetchone()
    conn.close()

    return {
        "status": "processed",
        "decision": decision,
        "log": dict(active_row)
    }