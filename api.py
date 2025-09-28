# api.py -- FastAPI dashboard + block endpoint for honeypot
# Features:
# - REST API to list events from SQLite
# - Simple HTML dashboard with auto-refresh
# - Endpoint to manually block/unblock IPs
# - Uses environment vars for config

import os
import sqlite3
import subprocess
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

DB_PATH = os.getenv("HP_DB", "honeypot_events.db")
ENABLE_BLOCK = os.getenv("HP_ENABLE_BLOCK", "false").lower() == "true"
BLOCK_COMMAND_TEMPLATE = os.getenv("HP_BLOCK_CMD", "sudo iptables -I INPUT -s {ip} -j DROP")
REMOVE_BLOCK_CMD = os.getenv("HP_REMOVE_BLOCK_CMD", "sudo iptables -D INPUT -s {ip} -j DROP")

app = FastAPI(title="Honeypot Dashboard")

# Mount static dir for CSS/JS if needed
if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

class BlockRequest(BaseModel):
    ip: str
    action: str  # "block" or "unblock"

@app.get("/events")
async def list_events(limit: int = 50):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    return rows

@app.post("/block")
async def block_ip(req: BlockRequest):
    ip = req.ip
    if not ENABLE_BLOCK:
        return {"status": "BLOCK disabled", "ip": ip}
    try:
        if req.action == "block":
            cmd = BLOCK_COMMAND_TEMPLATE.format(ip=ip)
        else:
            cmd = REMOVE_BLOCK_CMD.format(ip=ip)
        subprocess.run(cmd.split(), check=True)
        return {"status": "ok", "action": req.action, "ip": ip}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM events ORDER BY ts DESC LIMIT 100")
    rows = cur.fetchall()
    html_rows = ""
    for r in rows:
        flagged = "🚨" if r["flagged"] else "✅"
        html_rows += f"<tr><td>{r['ts']}</td><td>{r['ip']}</td><td>{r['port']}</td><td>{flagged}</td><td>{r['reason']}</td><td>{r['bytes_recv']}</td><td>{r['bytes_sent']}</td></tr>"
    html = f"""
    <html>
    <head>
        <title>Honeypot Dashboard</title>
        <meta http-equiv="refresh" content="10" />
        <style>
            body {{ font-family: Arial; margin: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ccc; padding: 4px; text-align: left; }}
            th {{ background: #eee; }}
        </style>
    </head>
    <body>
        <h1>Honeypot Events</h1>
        <table>
            <tr><th>Timestamp</th><th>IP</th><th>Port</th><th>Flagged</th><th>Reason</th><th>Bytes Recv</th><th>Bytes Sent</th></tr>
            {html_rows}
        </table>
    </body>
    </html>
    """
    return HTMLResponse(html)

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=int(os.getenv("API_PORT", 8000)), reload=True)
