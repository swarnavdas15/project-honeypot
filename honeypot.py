# honeypot.py -- Enhanced VNC honeypot MVP
# Features implemented:
# - opens N random RFB-like ports (default 2)
# - low-interaction RFB handshake + fake auth prompt
# - decoy file serving within session
# - JSON event logging to file & SQLite (for AI ingestion)
# - per-IP tracking, threshold -> iptables block for configurable duration (default 6 hours)
# - scheduled block removal (background thread)
#
# WARNING: iptables commands require root. Set HP_ENABLE_BLOCK=false for safe testing.

import os
import asyncio
import logging
import uuid
import sqlite3
import json
import random
import socket
import subprocess
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Tuple

# ---------- Config ----------
HOST = os.getenv("HP_HOST", "0.0.0.0")
PORT_RANGE = os.getenv("HP_PORT_RANGE", "5900-5999")  # inclusive range string
NUM_PORTS = int(os.getenv("HP_NUM_PORTS", "2"))
DB_PATH = os.getenv("HP_DB", "honeypot_events.db")
EVENT_DIR = os.getenv("HP_LOG_DIR", "events")
ENABLE_BLOCK = os.getenv("HP_ENABLE_BLOCK", "false").lower() == "true"
BLOCK_THRESHOLD = int(os.getenv("HP_BLOCK_THRESHOLD", "3"))
BLOCK_DURATION = int(os.getenv("HP_BLOCK_DURATION", str(6*3600)))  # seconds
ADMIN_CALLBACK = os.getenv("HP_ADMIN_CALLBACK", "")  # optional
BLOCK_CMD = os.getenv("HP_BLOCK_CMD", "sudo iptables -I INPUT -s {ip} -j DROP")
REMOVE_BLOCK_CMD = os.getenv("HP_REMOVE_BLOCK_CMD", "sudo iptables -D INPUT -s {ip} -j DROP")

RFB_HELLO = b"RFB 003.008\n"
LOG_FMT = "%(asctime)s %(levelname)s %(message)s"
logging.basicConfig(level=os.getenv("HP_LOG_LEVEL", "INFO"), format=LOG_FMT)
log = logging.getLogger("honeypot")

# ensure event dir exists
os.makedirs(EVENT_DIR, exist_ok=True)

# ---------- DB ----------
def init_db(path=DB_PATH):
    c = sqlite3.connect(path, check_same_thread=False)
    cur = c.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events(
            id TEXT PRIMARY KEY,
            ts TEXT,
            ip TEXT,
            port INTEGER,
            first_bytes TEXT,
            duration REAL,
            bytes_sent INTEGER,
            bytes_recv INTEGER,
            flagged INTEGER,
            reason TEXT,
            raw_json TEXT
        )
    """)
    c.commit()
    return c

DB = init_db()

def save_event_db(evt: dict):
    cur = DB.cursor()
    cur.execute("INSERT INTO events(id, ts, ip, port, first_bytes, duration, bytes_sent, bytes_recv, flagged, reason, raw_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (evt["id"], evt["ts"], evt["ip"], evt["port"], evt.get("first_bytes","")[:500], evt.get("duration",0.0),
                 evt.get("bytes_sent",0), evt.get("bytes_recv",0), 1 if evt.get("flagged") else 0, evt.get("reason",""), json.dumps(evt)))
    DB.commit()

def save_event_file(evt: dict):
    outpath = os.path.join(EVENT_DIR, f"{evt['id']}.json")
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(evt, f, indent=2)
    log.debug(f"Saved event JSON {outpath}")

# ---------- block management ----------
# simple in-memory blocked map to avoid duplicate blocks; persisted removal scheduled in thread
blocked_ips = {}  # ip -> unblock_time (datetime)

def _run_cmd(cmd: str) -> Tuple[int,str]:
    try:
        parts = cmd.split()
        proc = subprocess.run(parts, capture_output=True, text=True)
        return proc.returncode, proc.stdout + proc.stderr
    except Exception as e:
        return 1, str(e)

def schedule_unblock(ip: str, duration: int):
    unblock_at = datetime.utcnow() + timedelta(seconds=duration)
    blocked_ips[ip] = unblock_at
    log.info(f"Scheduled unblock for {ip} at {unblock_at.isoformat()}")

    def remover():
        try:
            seconds = duration
            # sleep loop to allow graceful shutdown if needed
            while seconds > 0:
                # sleep in short increments so process can be interrupted
                sleep_chunk = 5 if seconds > 5 else seconds
                threading.Event().wait(timeout=sleep_chunk)
                seconds -= sleep_chunk
            # execute removal
            cmd = REMOVE_BLOCK_CMD.format(ip=ip)
            log.info(f"Removing block: {cmd}")
            code, out = _run_cmd(cmd)
            if code != 0:
                log.warning(f"Failed remove-block for {ip}: {out.strip()}")
            else:
                log.info(f"Removed block for {ip}")
            # cleanup
            blocked_ips.pop(ip, None)
        except Exception as e:
            log.exception(f"Exception in unblock thread for {ip}: {e}")

    t = threading.Thread(target=remover, daemon=True)
    t.start()

def apply_block(ip: str):
    if not ENABLE_BLOCK:
        log.info(f"[BLOCK DISABLED] would block {ip} for {BLOCK_DURATION}s")
        return
    if ip in blocked_ips:
        log.info(f"{ip} already blocked until {blocked_ips[ip].isoformat()}")
        return
    cmd = BLOCK_CMD.format(ip=ip)
    log.info(f"Applying block: {cmd}")
    code, out = _run_cmd(cmd)
    if code != 0:
        log.warning(f"Failed apply-block: {out.strip()}")
        return
    schedule_unblock(ip, BLOCK_DURATION)

# ---------- per-IP counters ----------
ip_counters: Dict[str, Dict[str,int]] = {}  # ip -> {"attempts":n, "flagged":n}

def incr_ip(ip: str, key: str):
    rec = ip_counters.setdefault(ip, {"attempts":0, "flagged":0})
    rec[key] = rec.get(key,0) + 1
    return rec[key]

# ---------- detection & scoring (simple rule-set; feed AI with JSON events) ----------
def detect(first_bytes: bytes, bytes_sent: int, bytes_recv: int) -> Tuple[bool,str]:
    fb = (first_bytes or b"").lower()
    # rules:
    if b"get_file" in fb or b"get /decoy" in fb or b"download" in fb or b"file" in fb:
        return True, "file_request"
    if bytes_recv > 200_000:  # large recv: possible exfil
        return True, "large_transfer"
    # add more heuristics here or call your AI scoring endpoint synchronously/asynchronously
    return False, ""

# ---------- admin notifier (async) ----------
async def notify_admin(evt: dict):
    if not ADMIN_CALLBACK:
        return
    try:
        import aiohttp
        async with aiohttp.ClientSession() as s:
            await s.post(ADMIN_CALLBACK, json=evt, timeout=5)
            log.debug("Notified admin callback")
    except Exception as e:
        log.warning(f"Admin callback failed: {e}")

# ---------- decoy generator ----------
def make_decoy_payload(conn_id: str) -> bytes:
    # harmless decoy content with traceable GUID
    txt = (
        "=== DECOY FILE ===\n"
        f"Reference: DEC-{conn_id}\n"
        "This is a harmless decoy file provided by the honeypot.\n"
        "Forensic ID embedded.\n"
    )
    return txt.encode("utf-8")

# ---------- session handler ----------
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "unknown"
    local_port = writer.get_extra_info("socket").getsockname()[1]
    conn_id = str(uuid.uuid4())[:12]
    start = datetime.utcnow()
    log.info(f"[{conn_id}] CONNECT from {ip} -> localport {local_port}")

    bytes_sent = 0
    bytes_recv = 0
    first_bytes = b""
    flagged = False
    reason = ""

    try:
        # send RFB hello
        writer.write(RFB_HELLO)
        await writer.drain()
        bytes_sent += len(RFB_HELLO)

        # send fake auth challenge (makes it appear real)
        auth_msg = b"AUTH: please send credentials\n"
        writer.write(auth_msg)
        await writer.drain()
        bytes_sent += len(auth_msg)

        # read attacker's response (short timeout)
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=12.0)
        except asyncio.TimeoutError:
            data = b""
        first_bytes = data[:1024]
        bytes_recv += len(data)
        log.debug(f"[{conn_id}] first bytes: {first_bytes[:200]!r}")

        # naive: if attacker responds with credentials, we 'accept' some and present fake FS
        # Accept anything to keep attacker engaged (low-interaction trap)
        if data:
            # simulate login success (so attacker believes)
            welcome = b"AUTH_OK: Welcome to VNC server\nFake desktop available. Type GET_FILE or LIST\n"
            writer.write(welcome)
            await writer.drain()
            bytes_sent += len(welcome)

            # session loop: read commands, respond lightly (timeout per command)
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=8.0)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                bytes_recv += len(chunk)
                cmd = chunk.strip().lower()
                log.debug(f"[{conn_id}] cmd: {cmd!r}")
                # file request triggers decoy serve
                if b"get_file" in cmd or b"get /decoy" in cmd or b"download" in cmd or b"file" in cmd:
                    decoy = make_decoy_payload(conn_id)
                    header = f"START_FILE {len(decoy)}\n".encode()
                    writer.write(header)
                    writer.write(decoy)
                    writer.write(b"\nEND_FILE\n")
                    await writer.drain()
                    bytes_sent += len(header) + len(decoy) + len(b"\nEND_FILE\n")
                    log.info(f"[{conn_id}] served decoy file to {ip}")
                elif b"list" in cmd or b"ls" in cmd:
                    writer.write(b"desktop: Documents, secret.txt (permission denied), logs\n")
                    await writer.drain()
                    bytes_sent += 100
                else:
                    # generic lure text
                    writer.write(b"Unknown command. Try LIST or GET_FILE\n")
                    await writer.drain()
                    bytes_sent += 40

        else:
            # no response -> do nothing
            pass

    except Exception as e:
        log.exception(f"[{conn_id}] exception: {e}")
    finally:
        # finalize
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        end = datetime.utcnow()
        duration = (end - start).total_seconds()

        flagged, reason = detect(first_bytes, bytes_sent, bytes_recv)
        evt = {
            "id": conn_id,
            "ts": start.isoformat(),
            "ip": ip,
            "port": local_port,
            "first_bytes": first_bytes.decode("utf-8", errors="replace"),
            "duration": duration,
            "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv,
            "flagged": bool(flagged),
            "reason": reason,
            "raw": {
                "banner": RFB_HELLO.decode(errors="ignore"),
                "auth_sent": "AUTH_CHALLENGE"
            }
        }

        # persist & deliver
        save_event_file(evt)
        save_event_db(evt)
        log.info(f"[{conn_id}] DISCONNECT ip={ip} dur={duration:.2f}s sent={bytes_sent} recv={bytes_recv} flagged={flagged} reason={reason}")

        # counters & response
        incr_ip(ip, "attempts")
        if flagged:
            incr_ip(ip, "flagged")
            # if flagged count exceeds threshold, block
            flagged_count = ip_counters.get(ip, {}).get("flagged", 0)
            if flagged_count >= BLOCK_THRESHOLD:
                apply_block(ip)

            # notify admin async
            try:
                asyncio.create_task(notify_admin(evt))
            except Exception:
                pass

# ---------- server startup ----------
def pick_random_ports(range_str: str, n: int) -> List[int]:
    lo, hi = [int(x) for x in range_str.split("-",1)]
    pool = list(range(lo, hi+1))
    random.shuffle(pool)
    return pool[:n]

async def start_listeners(ports: List[int]):
    servers = []
    for p in ports:
        srv = await asyncio.start_server(handle_client, host=HOST, port=p)
        servers.append(srv)
        for s in srv.sockets or []:
            log.info(f"Listening fake RFB on {s.getsockname()}")
    await asyncio.gather(*(s.serve_forever() for s in servers))

def main():
    ports = pick_random_ports(PORT_RANGE, NUM_PORTS)
    log.info(f"Selected ports: {ports}")
    try:
        asyncio.run(start_listeners(ports))
    except KeyboardInterrupt:
        log.info("Shutdown requested")

if __name__ == "__main__":
    main()
