"""
PhishGuard — Core FastAPI Application Entrypoint
================================================
Serves the Explainable AI Phishing Detection REST API.
Handles CORS for Chrome Extension Manifest V3, loads XGBoost and SHAP on startup,
and exposes endpoints for URL analysis, explainability, feedback, and statistics.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.services.predictor_service import predictor_service
from app.api.predict  import router as predict_router
from app.api.feedback import router as feedback_router
from app.api.health   import router as health_router
from app.api.history  import router as history_router
from app.middleware.security import SecurityMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 60)
    print("[+] INITIALIZING PHISHGUARD FASTAPI BACKEND SERVER")
    print("=" * 60)
    predictor_service.load_artifacts()
    print("[✓] Server startup complete. Ready to receive requests.")
    yield
    print("[+] PhishGuard Server shutting down cleanly.")


app = FastAPI(
    title="PhishGuard — Explainable AI Phishing Detection API",
    description="""
    Real-Time AI-Powered Phishing URL Analysis Engine.

    ### Features:
    * **XGBoost Classifier**: 25 high-signal lexical, structural, and domain security features.
    * **SHAP Explainability**: Returns human-readable reasons explaining *why* a URL is safe, suspicious, or dangerous.
    * **Trusted Domain Whitelist**: Instant <0.1ms clearance for verified global domains.
    * **Rate Limiting**: 100 requests / 60 s per IP — prevents abuse.
    * **Chrome Extension Integration**: Designed for low-latency browser extension integration.
    * **React Dashboard**: SOC-style admin panel at http://localhost:5173
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Middleware ─────────────────────────────────────────────────
# Order matters: Security runs outermost, CORS innermost.
app.add_middleware(SecurityMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Allows chrome-extension:// and localhost origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────
app.include_router(predict_router)
app.include_router(feedback_router)
app.include_router(health_router)
app.include_router(history_router)


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")


@app.get("/health", include_in_schema=False)
async def root_health():
    from app.api.health import health_check
    return await health_check()
