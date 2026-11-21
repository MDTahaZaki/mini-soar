"""Mini-SOAR HTTP API."""

from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, case, func, or_
from sqlalchemy.orm import Session

from check_hash import get_hash_report
from check_ip import get_ip_report
from database import get_db, init_db
from models import ScanHistory

# Create tables (e.g. scan_history) and add any newer columns if missing.
init_db()

app = FastAPI(title="Mini-SOAR API")

# Wide-open CORS so a browser frontend on any origin can call the API.
# Tighten allow_origins before exposing this beyond local development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    ip: str


@app.get("/")
def root():
    return {"status": "Mini-SOAR API is running"}


# Plain `def` (not async): get_ip_report makes blocking HTTP calls,
# so FastAPI runs it in a worker thread instead of blocking the event loop.
@app.post("/scan")
def scan(request: ScanRequest, db: Session = Depends(get_db)):
    try:
        report = get_ip_report(request.ip)

        # If a source failed, its entry is {"error": ...}, so .get() yields
        # None and that column is stored as NULL.
        record = ScanHistory(
            ip_address=report["ip"],
            vt_malicious=report["virustotal"].get("malicious"),
            abuse_score=report["abuseipdb"].get("score"),
        )
        db.add(record)
        db.commit()

        return report
    except ValueError as e:
        # Invalid IP address, or API keys missing from .env
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")


class HashScanRequest(BaseModel):
    hash: str


@app.post("/scan/hash")
def scan_hash(request: HashScanRequest, db: Session = Depends(get_db)):
    try:
        report = get_hash_report(request.hash)

        # On a VT request failure, report has "error" and no "malicious",
        # so vt_malicious is stored as NULL. abuse_score doesn't apply to hashes.
        record = ScanHistory(
            hash_value=report["hash"],
            vt_malicious=report.get("malicious"),
        )
        db.add(record)
        db.commit()

        return report
    except ValueError as e:
        # Malformed hash, or VT_API_KEY missing from .env
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")


class ScanHistoryOut(BaseModel):
    """Response shape for a ScanHistory row (read from ORM attributes)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str | None  # None for hash scans
    hash_value: str | None  # None for IP scans
    vt_malicious: int | None  # None if VirusTotal failed for that scan
    abuse_score: int | None  # None if AbuseIPDB failed for that scan
    scanned_at: datetime


@app.get("/analytics")
def analytics(db: Session = Depends(get_db)):
    """Aggregate counts over all ScanHistory rows, computed in one SQL query."""
    ip_len = func.length(ScanHistory.ip_address)
    # /scan/hash stores the hash in hash_value (ip_address NULL), so a row is a
    # hash scan if hash_value is set, or if a 40+ char value sits in ip_address.
    is_hash = or_(ScanHistory.hash_value.isnot(None), ip_len >= 40)
    is_ip = and_(ScanHistory.hash_value.is_(None), ip_len < 40)

    def count_where(condition):
        return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)

    row = db.query(
        func.count(ScanHistory.id),
        count_where(ScanHistory.vt_malicious >= 3),
        # NULL vt_malicious means VirusTotal failed, so it's neither clean nor malicious.
        count_where(ScanHistory.vt_malicious < 3),
        count_where(is_ip),
        count_where(is_hash),
    ).one()

    keys = ("total_scans", "malicious_scans", "clean_scans", "ip_scans", "hash_scans")
    return dict(zip(keys, (int(v) for v in row)))


@app.get("/history", response_model=list[ScanHistoryOut])
def history(
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
):
    return (
        db.query(ScanHistory)
        # id breaks ties between scans with identical timestamps
        .order_by(ScanHistory.scanned_at.desc(), ScanHistory.id.desc())
        .limit(limit)
        .all()
    )
