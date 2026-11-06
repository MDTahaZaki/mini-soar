"""Check an IP address's reputation against VirusTotal (v3) and AbuseIPDB (v2)."""

import ipaddress
import os

import requests
from dotenv import load_dotenv

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 15


def check_virustotal(ip, api_key):
    resp = requests.get(
        VT_URL.format(ip=ip),
        headers={"x-apikey": api_key, "accept": "application/json"},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total": sum(stats.values()) if stats else 0,
        "community_votes_malicious": attrs.get("total_votes", {}).get("malicious", 0),
        "owner": attrs.get("as_owner", "N/A"),
        "country": attrs.get("country", "N/A"),
    }


def check_abuseipdb(ip, api_key):
    resp = requests.get(
        ABUSE_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})
    return {
        "score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "isp": data.get("isp") or "N/A",
        "country": data.get("countryCode") or "N/A",
        "last_reported": data.get("lastReportedAt") or "Never",
    }


def describe_error(exc):
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        return f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
    return str(exc)


def get_ip_report(ip_address: str) -> dict:
    """Look up an IP on VirusTotal and AbuseIPDB and return the combined results.

    Raises ValueError if the IP is invalid or the API keys are missing.
    A failure in one source does not affect the other: the failed source's
    entry is {"error": "<message>"} instead of its result fields.
    """
    try:
        ip = str(ipaddress.ip_address(ip_address))
    except ValueError:
        raise ValueError(f"'{ip_address}' is not a valid IP address.") from None

    load_dotenv()
    vt_key = os.getenv("VT_API_KEY")
    abuse_key = os.getenv("ABUSE_API_KEY")
    if not vt_key or not abuse_key:
        raise ValueError("VT_API_KEY and ABUSE_API_KEY must be set in .env")

    report = {"ip": ip}

    try:
        report["virustotal"] = check_virustotal(ip, vt_key)
    except requests.RequestException as e:
        report["virustotal"] = {"error": describe_error(e)}

    try:
        report["abuseipdb"] = check_abuseipdb(ip, abuse_key)
    except requests.RequestException as e:
        report["abuseipdb"] = {"error": describe_error(e)}

    return report
