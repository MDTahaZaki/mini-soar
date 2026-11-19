import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

# Local runs use ./threat_intel.db; docker-compose sets DATABASE_URL to the
# mounted /data volume so scan history survives container rebuilds.
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./threat_intel.db")

# check_same_thread=False: FastAPI's sync endpoints run in a threadpool,
# so a session may be used from a different thread than the one that created it.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def init_db():
    """Create missing tables, then add columns introduced after a DB was created.

    create_all() never alters existing tables, so an older threat_intel.db
    (or the Docker volume copy) needs columns added by hand.
    """
    import models  # noqa: F401  (registers ScanHistory on Base.metadata)

    Base.metadata.create_all(bind=engine)

    columns = {c["name"] for c in inspect(engine).get_columns("scan_history")}
    if "hash_value" not in columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE scan_history ADD COLUMN hash_value VARCHAR"))


def get_db():
    """FastAPI dependency: yields a DB session and closes it afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
