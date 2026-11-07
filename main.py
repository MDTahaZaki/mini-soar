"""Mini-SOAR HTTP API."""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from check_ip import get_ip_report

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
def scan(request: ScanRequest):
    try:
        return get_ip_report(request.ip)
    except ValueError as e:
        # Invalid IP address, or API keys missing from .env
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")
