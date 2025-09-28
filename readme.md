# Project Honeypot 🔮

## What This Is

A low‑interaction, realistic VNC honeypot that:

- Opens 2 random RFB (VNC-like) ports (configurable)
- Presents a believable auth/banner, accepts anything to keep attacker engaged
- Serves harmless decoy files when attacker requests downloads
- Logs each session as JSON files and into an SQLite DB (for your AI ingestion)
- Flags suspicious sessions (rules) and—optionally—applies a temporary iptables block for repeat offenders (default OFF)
- Ships with a simple FastAPI dashboard to view events and manually block/unblock IPs

Think of it as a glass jar full of bait — visible, instrumented, and ready to teach your detectors.

## Prerequisites ⚙️

- Python 3.10+ (for local runs)
- Docker & Docker Compose (for containerized run) — optional but recommended
- iptables privileges if you enable automatic blocking (root / CAP_NET_ADMIN)

## Project Files 📁

Important files include:

- `honeypot.py` — main honeypot service
- `api.py` — FastAPI dashboard & manual block endpoint
- `requirements.txt` — Python deps
- `Dockerfile.honeypot`, `Dockerfile.api` — container images
- `docker-compose.yml` — orchestration (safe defaults: blocking disabled)
- `.env` — environment vars (template provided as `.env.example`)
- `events/` — JSON event files (created at runtime)
- `honeypot_events.db` — SQLite DB (created at runtime)

## Quick Start - Local 🛠️

1. Create venv & install deps:
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows: .venv\Scripts\activate
    pip install -r requirements.txt
    ```

2. Create helper files/folders:
    ```bash
    mkdir -p events
    type nul > honeypot_events.db  # On Windows
    ```

3. Start API (dashboard):
    ```bash
    uvicorn api:app --host 0.0.0.0 --port 8000
    # open: http://localhost:8000/
    ```

4. Start honeypot (blocking disabled by default):
    ```bash
    set HP_ENABLE_BLOCK=false  # On Windows
    python honeypot.py
    ```

5. Test from another host (or same host if networked):
    ```bash
    nc <honeypot-ip> <port>
    # type anything (acts like credentials), then:
    # LIST
    # GET_FILE
    ```

Check `events/` for JSON output and open the dashboard to inspect DB rows.

## Quick Start - Docker 🐳

1. Ensure docker and docker compose installed

2. Put `.env` (copy from `.env.example`) in project root. Keep `HP_ENABLE_BLOCK=false` while testing

3. Build & run:
    ```bash
    docker compose up --build
    ```

4. Dashboard: http://localhost:8000/

> **Note**: To enable iptables blocking in container (advanced & risky): uncomment `network_mode: "host"` and `cap_add: ["NET_ADMIN"]` in docker-compose.yml, set `HP_ENABLE_BLOCK=true` and run with sudo. Do not enable on a production host without approvals.

## Environment Variables 🔧

Key vars you'll use (see `.env.example`):

| Variable | Description | Default |
|----------|-------------|---------|
| `HP_NUM_PORTS` | Number of random ports | 2 |
| `HP_PORT_RANGE` | Ports pool | 5900-5999 |
| `HP_ENABLE_BLOCK` | Enable blocking | false |
| `HP_BLOCK_THRESHOLD` | Flagged attempts before block | 3 |
| `HP_BLOCK_DURATION` | Seconds to block | 21600 (6 hours) |
| `HP_ADMIN_CALLBACK` | Optional HTTP endpoint for flagged events | - |
| `HP_LOG_LEVEL` | Log level (DEBUG\|INFO\|WARNING\|ERROR) | INFO |

> **Important**: No secret keys are stored here — keep `.env` out of git (`.gitignore` recommended).

## Safety & Legal Notes ⚠️

- Only deploy on networks you own or have written permission to test
- iptables blocking affects whole host (NAT/shared IPs risk). Keep threshold conservative
- Decoy files are harmless — do not embed any code that executes on attacker machines
- Keep logs and audit trails. Create an unblock SOP for false positives
- For production, prefer secret managers and container security best practices

