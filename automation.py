"""Extract IPs from sample_auth.log, scan them, save results, and alert Discord on hits.

Run: venv/bin/python automation.py
"""

import ipaddress
import os
import re
import time

import requests
from dotenv import load_dotenv

from check_ip import get_ip_report
from database import Base, SessionLocal, engine
from models import ScanHistory

LOG_FILE = "sample_auth.log"
SLEEP_SECONDS = 15  # pause between checks to respect API rate limits
VT_THRESHOLD = 3  # alert if VT malicious count >= this
ABUSE_THRESHOLD = 10  # alert if AbuseIPDB score >= this


# Dotted-quad pattern; out-of-range octets (e.g. 999.1.1.1) are rejected later
# by get_ip_report()'s ipaddress validation.
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ips(path):
    """Return the set of unique IPv4 addresses found anywhere in the log file."""
    with open(path, encoding="utf-8", errors="replace") as f:
        return set(IPV4_RE.findall(f.read()))


def is_non_routable(ip):
    """True for private, loopback, or link-local IPs (no point querying threat intel)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False  # let get_ip_report() reject and report it
    return addr.is_private or addr.is_loopback or addr.is_link_local


def save_report(report):
    # A failed source is {"error": ...}, so .get() gives None -> NULL column.
    db = SessionLocal()
    try:
        db.add(
            ScanHistory(
                ip_address=report["ip"],
                vt_malicious=report["virustotal"].get("malicious"),
                abuse_score=report["abuseipdb"].get("score"),
            )
        )
        db.commit()
    finally:
        db.close()


def is_threat(vt_malicious, abuse_score):
    return (vt_malicious or 0) >= VT_THRESHOLD or (abuse_score or 0) >= ABUSE_THRESHOLD


def send_discord_alert(webhook_url, report):
    vt = report["virustotal"]
    abuse = report["abuseipdb"]
    vt_line = (
        f"{vt['malicious']} / {vt['total']} engines flagged malicious"
        if "error" not in vt
        else "lookup failed"
    )
    abuse_line = (
        f"{abuse['score']}% confidence ({abuse['total_reports']} reports)"
        if "error" not in abuse
        else "lookup failed"
    )
    message = (
        "🚨 **Mini-SOAR Threat Alert** 🚨\n"
        f"**IP:** `{report['ip']}`\n"
        f"**VirusTotal:** {vt_line}\n"
        f"**AbuseIPDB:** {abuse_line}\n"
        f"**ISP:** {abuse.get('isp', 'N/A')} | **Country:** {abuse.get('country', 'N/A')}"
    )
    resp = requests.post(webhook_url, json={"content": message}, timeout=15)
    resp.raise_for_status()


def main():
    load_dotenv()
    webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
    if not webhook_url:
        raise SystemExit("DISCORD_WEBHOOK_URL must be set in .env")

    Base.metadata.create_all(bind=engine)  # ensure scan_history table exists

    try:
        ips = extract_ips(LOG_FILE)
    except FileNotFoundError:
        raise SystemExit(f"{LOG_FILE} not found.")

    print(f"[info] Found {len(ips)} unique IPs in {LOG_FILE}")

    scanned = 0
    for ip in sorted(ips):
        if is_non_routable(ip):
            print(f"[skip] Private IP ignored: {ip}")
            continue

        if scanned > 0:
            time.sleep(SLEEP_SECONDS)
        scanned += 1

        try:
            report = get_ip_report(ip)
        except ValueError as e:  # invalid IP or missing API keys
            print(f"[skip] {ip}: {e}")
            continue

        save_report(report)

        vt_malicious = report["virustotal"].get("malicious")
        abuse_score = report["abuseipdb"].get("score")
        print(f"[scan] {report['ip']}: VT={vt_malicious} Abuse={abuse_score}")

        if is_threat(vt_malicious, abuse_score):
            try:
                send_discord_alert(webhook_url, report)
                print(f"[alert] Discord alert sent for {report['ip']}")
            except requests.RequestException as e:
                print(f"[error] Discord alert failed for {report['ip']}: {e}")


if __name__ == "__main__":
    main()
