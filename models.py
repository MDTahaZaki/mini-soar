from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String

from database import Base


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String)
    vt_malicious = Column(Integer)
    abuse_score = Column(Integer)
    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
