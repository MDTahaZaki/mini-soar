import os

from sqlalchemy import create_engine
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


def get_db():
    """FastAPI dependency: yields a DB session and closes it afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
