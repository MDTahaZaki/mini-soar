"""Check a file hash's reputation against VirusTotal (v3)."""

import os
import re

import requests
from dotenv import load_dotenv

VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{hash}"
TIMEOUT = 15
TOP_ENGINES = 3

# MD5 = 32 hex chars, SHA1 = 40, SHA256 = 64.
HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
HEX_RE = re.compile(r"^[0-9a-f]+$")


def describe_error(exc):
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        return f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
    return str(exc)


def get_hash_report(file_hash: str) -> dict:
    """Look up a file hash (MD5, SHA1, or SHA256) on VirusTotal.

    Returns {"hash", "hash_type", "found", "malicious", "total_engines",
    "top_detections"}, where top_detections is up to 3
    {"engine", "result"} entries for engines that flagged the file.
    If VirusTotal has never seen the hash, "found" is False and the counts are 0.
    If the request fails (rate limit, bad key, network), the dict carries
    {"error": "<message>"} instead of the result fields.

    Raises ValueError if the hash is malformed or VT_API_KEY is missing.
    """
    h = file_hash.strip().lower() if isinstance(file_hash, str) else ""
    hash_type = HASH_TYPES.get(len(h))
    if not hash_type or not HEX_RE.match(h):
        raise ValueError(f"'{file_hash}' is not a valid MD5, SHA1, or SHA256 hash.")

    load_dotenv()
    vt_key = os.getenv("VT_API_KEY")
    if not vt_key:
        raise ValueError("VT_API_KEY must be set in .env")

    report = {"hash": h, "hash_type": hash_type}

    try:
        resp = requests.get(
            VT_FILE_URL.format(hash=h),
            headers={"x-apikey": vt_key, "accept": "application/json"},
            timeout=TIMEOUT,
        )
        if resp.status_code == 404:
            report.update(found=False, malicious=0, total_engines=0, top_detections=[])
            return report
        resp.raise_for_status()
    except requests.RequestException as e:
        report["error"] = describe_error(e)
        return report

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})

    # Count only engines that returned a verdict (skip type-unsupported,
    # timeout, failure), matching the "X / Y" ratio shown on the VT website.
    total = sum(stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))

    flagged = sorted(
        (
            {"engine": r.get("engine_name", name), "result": r.get("result") or "malicious"}
            for name, r in results.items()
            if r.get("category") == "malicious"
        ),
        key=lambda d: d["engine"].lower(),
    )

    report.update(
        found=True,
        malicious=stats.get("malicious", 0),
        total_engines=total,
        top_detections=flagged[:TOP_ENGINES],
    )
    return report
