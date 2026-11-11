"""Mini-SOAR HTTP API."""

from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from check_ip import get_ip_report
from database import Base, engine, get_db
from models import ScanHistory

# Create tables (e.g. scan_history) if they don't exist yet.
Base.metadata.create_all(bind=engine)

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


class ScanHistoryOut(BaseModel):
    """Response shape for a ScanHistory row (read from ORM attributes)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    vt_malicious: int | None  # None if VirusTotal failed for that scan
    abuse_score: int | None  # None if AbuseIPDB failed for that scan
    scanned_at: datetime


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
