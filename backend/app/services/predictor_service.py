"""
PhishGuard — Model Prediction & Inference Service
=================================================
Loads the production XGBoost classifier, handles feature extraction,
checks trusted domain whitelists, runs inference, and coordinates SHAP explanations.
"""

import os
import time
import joblib
from datetime import datetime
from typing import Dict, Any, Optional

from app.models.schemas import PredictionRequest, PredictionResponse, SHAPFactor
from app.services.whitelist_service import is_domain_whitelisted
from app.services.feature_service import extract_features, get_feature_dataframe
from app.services.explainer_service import ExplainerService
from app.middleware.security import sanitize_url

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "ml", "models"))

class PredictorService:
    def __init__(self):
        self.model = None
        self.feature_names = None
        self.explainer_service = None
        self.cache: Dict[str, PredictionResponse] = {}
        self.total_scans = 0
        self.safe_count = 0
        self.suspicious_count = 0
        self.blocked_count = 0

    def load_artifacts(self):
        """Loads model artifacts from backend/ml/models/"""
        model_path = os.path.join(MODELS_DIR, "xgboost_model.pkl")
        features_path = os.path.join(MODELS_DIR, "feature_names.pkl")

        print(f"[+] Loading XGBoost model from: {model_path}")
        self.model = joblib.load(model_path)
        self.feature_names = joblib.load(features_path)
        print(f"[+] Loaded model with {len(self.feature_names)} features.")

        print("[+] Initializing SHAP Explainer...")
        self.explainer_service = ExplainerService(self.model, self.feature_names)
        print("[✓] Model & Explainer successfully loaded and ready.")

    def analyze(self, req: PredictionRequest) -> PredictionResponse:
        start_time = time.perf_counter()
        url = sanitize_url(req.url)   # strip control chars, truncate >2048
        timestamp = datetime.utcnow().isoformat() + "Z"

        # 1. Check in-memory cache
        if url in self.cache:
            cached = self.cache[url]
            latency = round((time.perf_counter() - start_time) * 1000, 2)
            return PredictionResponse(
                url=cached.url,
                risk_score=cached.risk_score,
                phishing_probability=cached.phishing_probability,
                verdict=cached.verdict,
                action=cached.action,
                is_whitelisted=cached.is_whitelisted,
                explanation=cached.explanation,
                latency_ms=latency,
                timestamp=timestamp
            )

        # 2. Check Trusted Domain Whitelist (<0.1ms clearance)
        if is_domain_whitelisted(url):
            latency = round((time.perf_counter() - start_time) * 1000, 2)
            res = PredictionResponse(
                url=url,
                risk_score=0.00,
                phishing_probability=0.0000,
                verdict="SAFE / ALLOW",
                action="ALLOW",
                is_whitelisted=True,
                explanation=[
                    SHAPFactor(
                        feature="trusted_domain_whitelist",
                        value="VERIFIED",
                        impact="HIGH",
                        direction="legitimate",
                        message="Domain belongs to verified top trusted global authority list"
                    )
                ],
                latency_ms=latency,
                timestamp=timestamp
            )
            self._update_stats("SAFE")
            self._cache_result(url, res)
            return res

        # 3. Extract 25 Features
        feat_dict = extract_features(
            url=url,
            page_title=req.page_title,
            nb_hyperlinks=req.nb_hyperlinks,
            ratio_intHyperlinks=req.ratio_intHyperlinks,
            has_login_form=req.has_login_form
        )
        X_df = get_feature_dataframe(feat_dict, self.feature_names)

        # 4. XGBoost Inference
        proba = float(self.model.predict_proba(X_df)[0, 1])
        risk_pct = round(proba * 100, 2)

        # 5. Determine Verdict & Browser Action
        if proba >= 0.70:
            verdict = "DANGEROUS / BLOCK"
            action = "BLOCK"
            category = "BLOCKED"
        elif proba >= 0.35:
            verdict = "SUSPICIOUS / WARN"
            action = "WARN"
            category = "SUSPICIOUS"
        else:
            verdict = "SAFE / ALLOW"
            action = "ALLOW"
            category = "SAFE"

        # 6. SHAP Explanations
        factors = self.explainer_service.explain(X_df, top_n=5)

        latency = round((time.perf_counter() - start_time) * 1000, 2)

        res = PredictionResponse(
            url=url,
            risk_score=risk_pct,
            phishing_probability=round(proba, 4),
            verdict=verdict,
            action=action,
            is_whitelisted=False,
            explanation=factors,
            latency_ms=latency,
            timestamp=timestamp
        )

        self._update_stats(category)
        self._cache_result(url, res)

        # ── Record to scan history ─────────────────────────────
        try:
            from app.api.history import record_scan
            risk_level = category.lower()  # "safe", "suspicious", "blocked"
            record_scan(url, risk_level, round(proba, 4), verdict, latency)
        except Exception:
            pass  # Never let logging break inference

        return res

    def _update_stats(self, category: str):
        self.total_scans += 1
        if category == "SAFE":
            self.safe_count += 1
        elif category == "SUSPICIOUS":
            self.suspicious_count += 1
        elif category == "BLOCKED":
            self.blocked_count += 1

    def _cache_result(self, url: str, res: PredictionResponse):
        # Cap cache size at 5,000 entries
        if len(self.cache) > 5000:
            self.cache.pop(next(iter(self.cache)))
        self.cache[url] = res

# Singleton instance
predictor_service = PredictorService()
