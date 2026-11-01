"""
PhishGuard — Scan History & Admin Router
=========================================
Endpoints:
  GET /api/v1/history        → Recent scan history (in-memory, last N)
  GET /api/v1/admin/logs     → Full admin log dump
  GET /api/v1/allowlist      → View allowlist
  POST /api/v1/allowlist     → Add to allowlist
  POST /api/v1/blocklist     → Add to blocklist
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Query, HTTPException, status
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1", tags=["History & Admin"])

# ── In-memory stores (replace with DB in production) ──────────
SCAN_HISTORY: List[Dict[str, Any]] = []
BLOCKLIST:    List[str] = []
ALLOWLIST:    List[str] = []          # runtime additions (top-1M is in whitelist_service)

MAX_HISTORY = 2000


# ── Schema ────────────────────────────────────────────────────
class HistoryItem(BaseModel):
    url:         str
    risk_level:  str
    probability: float
    verdict:     str
    timestamp:   str
    latency_ms:  Optional[float] = None


class ListEntryRequest(BaseModel):
    url: str


# ── Helper called by predictor_service after each scan ────────
def record_scan(url: str, risk_level: str, probability: float,
                verdict: str, latency_ms: float = 0.0):
    entry = {
        "url":         url,
        "risk_level":  risk_level,
        "probability": probability,
        "verdict":     verdict,
        "latency_ms":  round(latency_ms, 2),
        "timestamp":   datetime.utcnow().isoformat() + "Z",
    }
    SCAN_HISTORY.append(entry)
    if len(SCAN_HISTORY) > MAX_HISTORY:
        del SCAN_HISTORY[:len(SCAN_HISTORY) - MAX_HISTORY]


# ── Endpoints ─────────────────────────────────────────────────
@router.get(
    "/history",
    summary="Get Scan History",
    description="Returns the N most recent URL scans with risk levels and scores.",
)
async def get_history(limit: int = Query(default=100, ge=1, le=500)):
    items = list(reversed(SCAN_HISTORY[-limit:]))
    return {"total": len(SCAN_HISTORY), "returned": len(items), "items": items}


@router.get(
    "/admin/logs",
    summary="Admin: Full Scan Log",
    description="Returns all stored scan logs for SOC analysis (max 2000 entries).",
)
async def admin_logs():
    return {"total": len(SCAN_HISTORY), "logs": list(reversed(SCAN_HISTORY))}


@router.get("/allowlist", summary="View Runtime Allowlist")
async def get_allowlist():
    return {"allowlist": ALLOWLIST, "count": len(ALLOWLIST)}


@router.post("/allowlist", summary="Add Domain to Allowlist", status_code=status.HTTP_201_CREATED)
async def add_allowlist(req: ListEntryRequest):
    domain = req.url.strip().lower().lstrip("https://").lstrip("http://").split("/")[0]
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")
    if domain not in ALLOWLIST:
        ALLOWLIST.append(domain)
    return {"success": True, "domain": domain, "allowlist_size": len(ALLOWLIST)}


@router.get("/blocklist", summary="View Runtime Blocklist")
async def get_blocklist():
    return {"blocklist": BLOCKLIST, "count": len(BLOCKLIST)}


@router.post("/blocklist", summary="Add Domain to Blocklist", status_code=status.HTTP_201_CREATED)
async def add_blocklist(req: ListEntryRequest):
    domain = req.url.strip().lower().lstrip("https://").lstrip("http://").split("/")[0]
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")
    if domain not in BLOCKLIST:
        BLOCKLIST.append(domain)
    return {"success": True, "domain": domain, "blocklist_size": len(BLOCKLIST)}

