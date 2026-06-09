"""
main.py — DNS Shield
FastAPI application: startup orchestration, REST endpoints, and dashboard.

Run with:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Endpoints:
    GET /           → Single-page HTML dashboard
    GET /logs       → Latest DNS query logs from MongoDB
    GET /blocked    → Current in-memory block list
    GET /stats      → Live counters from the sniffer
    POST /unblock   → Remove a domain from the block list (admin)
"""

import os
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import pymongo

import sniffer
from blocker import blocker

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("dns_shield.main")

# ──────────────────────────────────────────────────────────────────────────────
# Configuration (override via environment variables for production)
# ──────────────────────────────────────────────────────────────────────────────
MONGO_URI        = os.getenv("MONGO_URI",    "mongodb://localhost:27017")
MONGO_DB         = os.getenv("MONGO_DB",     "dns_shield")
MONGO_COLLECTION = os.getenv("MONGO_COL",    "query_logs")
MODEL_PATH       = os.getenv("MODEL_PATH",   "dns_model.pkl")
SNIFFER_IFACE    = os.getenv("SNIFFER_IFACE", None)   # None → auto-detect
LOG_LIMIT        = int(os.getenv("LOG_LIMIT", "200"))  # rows returned per /logs

TEMPLATE_PATH    = Path(__file__).parent / "templates" / "index.html"

# ──────────────────────────────────────────────────────────────────────────────
# FastAPI app
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="DNS Shield",
    description="Real-time DNS Intrusion Detection System",
    version="1.0.0",
)

# MongoDB client (module-level; initialised in startup)
_mongo_client: Optional[pymongo.MongoClient] = None
_log_col       = None


# ──────────────────────────────────────────────────────────────────────────────
# Startup / Shutdown
# ──────────────────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event() -> None:
    """
    Executed once when Uvicorn starts the application.

    Order of operations
    -------------------
    1. Connect to MongoDB (fail gracefully if unavailable).
    2. Load the Isolation Forest model into sniffer memory.
    3. Launch the Scapy sniffer as a background daemon thread.
    """
    global _mongo_client, _log_col

    # ── 1. MongoDB ────────────────────────────────────────────────────────────
    try:
        _mongo_client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        # Force a connection attempt
        _mongo_client.server_info()
        db       = _mongo_client[MONGO_DB]
        _log_col = db[MONGO_COLLECTION]

        # Index on timestamp for fast "latest N" queries
        _log_col.create_index([("timestamp", pymongo.DESCENDING)])

        # Inject the collection into the sniffer module
        sniffer.set_log_collection(_log_col)
        logger.info("MongoDB connected → %s/%s", MONGO_DB, MONGO_COLLECTION)

    except Exception as exc:
        logger.warning(
            "MongoDB unavailable (%s).  Logs will not be persisted.", exc
        )

    # ── 2. Load ML model ──────────────────────────────────────────────────────
    try:
        sniffer.load_model(MODEL_PATH)
    except FileNotFoundError as exc:
        logger.warning("%s", exc)

    # ── 3. Start sniffer daemon ───────────────────────────────────────────────
    sniffer.start_sniffer_thread(iface=SNIFFER_IFACE)
    logger.info("DNS Shield fully initialised.")


@app.on_event("shutdown")
async def shutdown_event() -> None:
    """Close MongoDB connection cleanly on server shutdown."""
    if _mongo_client:
        _mongo_client.close()
        logger.info("MongoDB connection closed.")


# ──────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ──────────────────────────────────────────────────────────────────────────────

class LogEntry(BaseModel):
    domain:    str
    length:    int
    entropy:   float
    status:    str     # "clean" | "blocked"
    timestamp: str     # ISO-8601


class StatsResponse(BaseModel):
    total:        int
    clean:        int
    new_blocked:  int
    blocked_fast: int
    block_list_size: int
    sniffer_running: bool


class UnblockRequest(BaseModel):
    domain: str


# ──────────────────────────────────────────────────────────────────────────────
# REST Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
async def dashboard() -> HTMLResponse:
    """
    Serve the single-page HTML dashboard.

    Reads templates/index.html from disk on every request so that UI
    changes are reflected without a server restart during development.
    """
    if not TEMPLATE_PATH.exists():
        raise HTTPException(
            status_code=500,
            detail=f"Dashboard template not found at {TEMPLATE_PATH}",
        )
    return HTMLResponse(content=TEMPLATE_PATH.read_text(encoding="utf-8"))


@app.get("/logs", response_model=List[LogEntry], tags=["Data"])
async def get_logs(limit: int = LOG_LIMIT) -> List[LogEntry]:
    """
    Return the latest `limit` DNS query log entries from MongoDB.

    Query parameters
    ----------------
    limit : int
        Maximum number of records to return (default: 200, max: 1000).
    """
    if _log_col is None:
        return []   # MongoDB not available — return empty list gracefully

    limit = min(max(1, limit), 1000)

    try:
        cursor = (
            _log_col
            .find({}, {"_id": 0})
            .sort("timestamp", pymongo.DESCENDING)
            .limit(limit)
        )
        logs = []
        for doc in cursor:
            ts = doc.get("timestamp", datetime.utcnow())
            logs.append(LogEntry(
                domain    = doc.get("domain",  ""),
                length    = doc.get("length",  0),
                entropy   = round(doc.get("entropy", 0.0), 4),
                status    = doc.get("status",  "clean"),
                timestamp = ts.isoformat() if isinstance(ts, datetime) else str(ts),
            ))
        return logs

    except Exception as exc:
        logger.error("Error fetching logs: %s", exc)
        raise HTTPException(status_code=500, detail="Database error.")


@app.get("/blocked", tags=["Data"])
async def get_blocked() -> JSONResponse:
    """
    Return the list of currently blocked domains held in memory.

    Response
    --------
    {
        "count":   <int>,
        "domains": ["evil.tunnel.io", …]
    }
    """
    domains = blocker.snapshot()
    return JSONResponse({"count": len(domains), "domains": domains})


@app.get("/stats", response_model=StatsResponse, tags=["Data"])
async def get_stats() -> StatsResponse:
    """
    Return live performance counters from the sniffer thread.
    Useful for the analytics summary row in the dashboard.
    """
    s = sniffer.stats
    return StatsResponse(
        total           = s["total"],
        clean           = s["clean"],
        new_blocked     = s["new_blocked"],
        blocked_fast    = s["blocked_fast"],
        block_list_size = blocker.size(),
        sniffer_running = sniffer.is_sniffer_running(),
    )


@app.post("/unblock", tags=["Admin"])
async def unblock_domain(body: UnblockRequest) -> JSONResponse:
    """
    Remove a domain from the in-memory block list.

    This does NOT delete historical log entries from MongoDB.
    Intended for admin use (e.g. false-positive remediation).
    """
    removed = blocker.remove(body.domain)
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"Domain '{body.domain}' not found in block list.",
        )
    logger.info("Admin unblocked domain: %s", body.domain)
    return JSONResponse({"unblocked": body.domain})


@app.get("/health", tags=["System"])
async def health_check() -> JSONResponse:
    """Lightweight liveness probe for load-balancers / Docker HEALTHCHECK."""
    return JSONResponse({
        "status":  "ok",
        "sniffer": sniffer.is_sniffer_running(),
        "db":      _log_col is not None,
    })
