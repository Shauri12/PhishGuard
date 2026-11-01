"""
PhishGuard — Prediction & Explainability Router
===============================================
Endpoints:
  POST /api/v1/predict  -> Analyze URL risk score + SHAP reasons
  POST /api/v1/explain  -> Get detailed SHAP explainability factors
"""

from fastapi import APIRouter, HTTPException, status
from app.models.schemas import PredictionRequest, PredictionResponse, SHAPFactor
from app.services.predictor_service import predictor_service
from typing import List

router = APIRouter(prefix="/api/v1", tags=["Phishing Detection & Explainability"])

@router.post(
    "/predict",
    response_model=PredictionResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze URL Phishing Risk",
    description="Evaluates an incoming URL against the trained XGBoost model and returns the phishing risk score, threat verdict, browser action, and top SHAP reasons."
)
async def predict_url(request: PredictionRequest):
    if not request.url or len(request.url.strip()) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL parameter cannot be empty."
        )

    try:
        response = predictor_service.analyze(request)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference failure: {str(e)}"
        )

@router.post(
    "/explain",
    response_model=List[SHAPFactor],
    status_code=status.HTTP_200_OK,
    summary="Get Detailed SHAP Factors",
    description="Returns the top SHAP explainability factors driving the security verdict for a given URL."
)
async def explain_url(request: PredictionRequest):
    try:
        response = predictor_service.analyze(request)
        return response.explanation
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Explanation failure: {str(e)}"
        )
