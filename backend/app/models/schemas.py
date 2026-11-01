"""
PhishGuard — Pydantic Request & Response Schemas
================================================
Defines structured API contracts for URL scanning, SHAP explanations,
user feedback, and system monitoring.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, HttpUrl
from datetime import datetime

class PredictionRequest(BaseModel):
    url: str = Field(..., description="The full URL to analyze for phishing risks", example="https://paypa1-security-update.xyz/login.php")
    page_title: Optional[str] = Field(None, description="Optional page <title> tag extracted by the extension", example="PayPal - Security Verification")
    nb_hyperlinks: Optional[int] = Field(None, description="Optional total number of links on the page", example=15)
    ratio_intHyperlinks: Optional[float] = Field(None, description="Optional ratio of internal links (0.0 to 1.0)", example=0.8)
    has_login_form: Optional[bool] = Field(None, description="Optional flag if a password/login field was detected", example=True)

class SHAPFactor(BaseModel):
    feature: str = Field(..., description="Name of the underlying feature")
    value: Any = Field(..., description="Extracted numerical or categorical value")
    impact: str = Field(..., description="Impact level: HIGH, MEDIUM, or LOW")
    direction: str = Field(..., description="Direction: 'phishing' (threat booster) or 'legitimate' (safety signal)")
    message: str = Field(..., description="Human-readable security explanation")

class PredictionResponse(BaseModel):
    url: str
    risk_score: float = Field(..., description="Phishing probability percentage (0.00% to 100.00%)", example=94.52)
    phishing_probability: float = Field(..., description="Raw probability score (0.0000 to 1.0000)", example=0.9452)
    verdict: str = Field(..., description="Security classification: SAFE, SUSPICIOUS, or DANGEROUS", example="DANGEROUS / BLOCK")
    action: str = Field(..., description="Recommended browser action: ALLOW, WARN, or BLOCK", example="BLOCK")
    is_whitelisted: bool = Field(False, description="True if domain was verified against top trusted list")
    explanation: List[SHAPFactor] = Field(default_factory=list, description="Top SHAP factors driving the decision")
    latency_ms: float = Field(..., description="Total analysis duration in milliseconds", example=1.84)
    timestamp: str = Field(..., description="ISO 8601 evaluation timestamp")

class FeedbackRequest(BaseModel):
    url: str = Field(..., description="URL reported by the user")
    reported_as: Optional[str] = Field("false_positive", description="Report category: 'false_positive' or 'false_negative'")
    predicted_label: Optional[int] = Field(None, description="Model prediction: 1 (phishing) or 0 (safe)")
    correct_label: Optional[int] = Field(None, description="User correction: 1 (phishing) or 0 (safe)")
    probability: Optional[float] = Field(None, description="Predicted phishing probability")
    user_comment: Optional[str] = Field(None, description="Optional user note or context")

class FeedbackResponse(BaseModel):
    success: bool = True
    message: str = "Feedback received and logged to security review queue"
    report_id: str

class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    model_loaded: bool = True
    features_count: int
    uptime_seconds: float
    timestamp: str

class StatsResponse(BaseModel):
    total_scans: int
    safe_count: int
    suspicious_count: int
    blocked_count: int
    feedback_reports: int
