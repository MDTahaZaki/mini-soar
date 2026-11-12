# mini-soar — Agent Notes

Context for AI agents (and humans) working on this project.

## Purpose
A small SOAR-style toolkit for checking threat-intel reputation of indicators. Currently: IP reputation lookups.

## Environment
- Python virtualenv in `venv/` — run scripts with `venv/bin/python`.
- Dependencies (`requirements.txt`): `requests`, `python-dotenv`, `fastapi`, `uvicorn`.
- API keys live in `.env` (never commit it, never print its values):
  - `VT_API_KEY` — VirusTotal
  - `ABUSE_API_KEY` — AbuseIPDB

## Files
### `check_ip.py`
Library module (no CLI). Usage: `from check_ip import get_ip_report; get_ip_report("8.8.8.8")`

- `get_ip_report(ip_address: str) -> dict` returns `{"ip", "virustotal", "abuseipdb"}`; nothing is printed.
- Validates the input with `ipaddress.ip_address` before any API call; raises `ValueError` if invalid.
- Loads keys via `load_dotenv()`; raises `ValueError` if either key is missing.
- **VirusTotal v3**: `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}`, header `x-apikey`.
  - Uses `data.attributes.last_analysis_stats` (malicious/suspicious/harmless/undetected → engine detections)
  - and `data.attributes.total_votes.malicious` (community votes), plus `as_owner`, `country`.
- **AbuseIPDB v2**: `GET https://api.abuseipdb.com/api/v2/check`, header `Key`, params `ipAddress`, `maxAgeInDays=90`.
  - Uses `data.abuseConfidenceScore`, `totalReports`, `isp`, `countryCode`, `lastReportedAt`.
- Each API call is wrapped independently: if one fails (rate limit, bad key), that source's entry becomes `{"error": "<message>"}` and the other result is still returned.
- 15s request timeout.

### `main.py`
FastAPI app. Run: `venv/bin/uvicorn main:app` (default port 8000).

- `GET /` → `{"status": "Mini-SOAR API is running"}`
- `POST /scan` with body `{"ip": "8.8.8.8"}` → the `get_ip_report()` dict.
  - `ValueError` (invalid IP, or missing API keys) → 400; any other exception → 500; missing `ip` field → 422 (FastAPI validation).
  - Endpoint is a sync `def` so the blocking `requests` calls run in FastAPI's threadpool.
- `CORSMiddleware` allows all origins, methods, and headers (fine for local dev; restrict `allow_origins` before deploying).

### `automation.py`
Batch scanner. Run: `venv/bin/python automation.py`.

- Reads `suspicious_ips.txt` (one IP per line; blank lines and `#` comments skipped).
- For each IP: `get_ip_report()` → saves a `ScanHistory` row → if VT `malicious > 0` OR AbuseIPDB `score > 10`, POSTs a Markdown alert to `DISCORD_WEBHOOK_URL` (from `.env`).
- Sleeps 15s between checks. Invalid IPs are logged and skipped; a failed Discord post is logged and doesn't stop the run.

### `frontend/`
Static UI (`index.html`, `script.js`, `style.css`). `script.js` POSTs `{"ip": ...}` to `http://127.0.0.1:8000/scan`.
Serve it on its own so `.env` isn't exposed: `python3 -m http.server 5500 --directory frontend` → http://127.0.0.1:5500 (backend must be running too).

## Status / history
- 2026-11-05: `check_ip.py` created and verified working against live APIs (tested with 8.8.8.8 and an invalid input).
- 2026-11-06: Refactored into `get_ip_report()` returning a dict; CLI/argparse removed.

## Open items
- No `.gitignore` yet — should exclude `.env` and `venv/` before the first commit.
