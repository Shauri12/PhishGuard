"""
PhishGuard — System Health & Statistics Router
==============================================
Endpoints:
  GET /api/v1/health  -> Health, readiness probe, and model metadata
  GET /api/v1/stats   -> Live scan statistics
"""

import time
from datetime import datetime
from fastapi import APIRouter
from app.models.schemas import HealthResponse, StatsResponse
from app.services.predictor_service import predictor_service

router = APIRouter(prefix="/api/v1", tags=["System Health & Metrics"])

START_TIME = time.time()

@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System Health & Readiness Probe",
    description="Returns current service status, model load readiness, and uptime."
)
async def health_check():
    uptime = round(time.time() - START_TIME, 2)
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        model_loaded=(predictor_service.model is not None),
        features_count=len(predictor_service.feature_names) if predictor_service.feature_names else 0,
        uptime_seconds=uptime,
        timestamp=datetime.utcnow().isoformat() + "Z"
    )

@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Real-Time Detection Statistics",
    description="Returns aggregate counts of URLs scanned, threats detected, and safe sites cleared."
)
async def get_stats():
    from app.api.feedback import FEEDBACK_LOGS
    return StatsResponse(
        total_scans=predictor_service.total_scans,
        safe_count=predictor_service.safe_count,
        suspicious_count=predictor_service.suspicious_count,
        blocked_count=predictor_service.blocked_count,
        feedback_reports=len(FEEDBACK_LOGS)
    )
