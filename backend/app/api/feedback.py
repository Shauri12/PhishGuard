"""
PhishGuard — Feedback & Reporting Router
========================================
Endpoints:
  POST /api/v1/feedback  -> Submit user reporting for false alarms / missed attacks
  GET  /api/v1/feedback  -> Retrieve list of reported URLs
"""

import uuid
from datetime import datetime
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, status
from app.models.schemas import FeedbackRequest, FeedbackResponse

router = APIRouter(prefix="/api/v1", tags=["User Feedback & Threat Intelligence"])

# In-memory thread-safe store for feedback (can be backed by MongoDB / SQLite)
FEEDBACK_LOGS: List[Dict[str, Any]] = []

@router.post(
    "/feedback",
    response_model=FeedbackResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit Detection Feedback",
    description="Submits a report when a user believes a URL was misclassified (false positive or false negative)."
)
async def submit_feedback(req: FeedbackRequest):
    report_id = str(uuid.uuid4())[:8]
    reported_as = req.reported_as
    if req.correct_label is not None:
        reported_as = "false_positive" if req.correct_label == 0 else "false_negative"

    entry = {
        "report_id": report_id,
        "url": req.url,
        "reported_as": reported_as,
        "predicted_label": req.predicted_label,
        "correct_label": req.correct_label,
        "probability": req.probability,
        "user_comment": req.user_comment,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    FEEDBACK_LOGS.append(entry)
    return FeedbackResponse(
        success=True,
        message="Thank you! Feedback logged for model retraining.",
        report_id=report_id
    )

@router.get(
    "/feedback",
    response_model=List[Dict[str, Any]],
    summary="List Feedback Submissions",
    description="Lists recent feedback submissions for security review."
)
async def list_feedback():
    return FEEDBACK_LOGS[-50:]  # Return most recent 50 reports
