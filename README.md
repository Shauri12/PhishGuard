# 🛡️ PhishGuard — Explainable AI Phishing Detection System

> **Real-time, XAI-powered URL security for the modern web.**  
> XGBoost + TreeSHAP · FastAPI · Chrome Extension MV3 · React SOC Dashboard

---

## 📑 Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Tech Stack](#tech-stack)
4. [Project Structure](#project-structure)
5. [Quick Start](#quick-start)
6. [Running Each Component](#running-each-component)
7. [API Reference](#api-reference)
8. [Chrome Extension Installation](#chrome-extension-installation)
9. [Security Features](#security-features)

---

## Overview

PhishGuard is a full-stack, production-ready **Explainable AI (XAI) phishing detection system**.  
Unlike blacklist-based tools, PhishGuard detects **zero-day phishing** by analyzing mathematical URL structure — and tells you **exactly why** a site is flagged using **TreeSHAP** local explanations.

### Key Innovations
| Feature | Detail |
|---|---|
| **Zero-execution URL triage** | 30+ lexical/structural features extracted from URL string alone — no DOM, no JS execution, no drive-by risk |
| **Real-time TreeSHAP** | Local Shapley values computed per prediction, identifying exact contributing features in <5ms |
| **99.9% ROC-AUC** | XGBoost trained on the PhiUSIIL phishing URL dataset |
| **MV3-compliant extension** | Chrome Manifest V3 compliant; no inline scripts, full CSP hardening |
| **Active learning loop** | User feedback → `/feedback` endpoint → model retraining pipeline |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    USER'S BROWSER                        │
│                                                          │
│  ┌──────────────────────────────────────────────┐       │
│  │        Chrome Extension (MV3)                │       │
│  │  background.js (Service Worker)              │       │
│  │  ├── Intercepts webNavigation.onCommitted    │       │
│  │  ├── In-memory LRU cache (0ms repeat scans) │       │
│  │  ├── Calls POST /api/v1/predict             │       │
│  │  └── Routes: SAFE→badge WARN→warning.html   │       │
│  │             BLOCK→blocked.html              │       │
│  │  popup.html → Risk gauge + SHAP chips        │       │
│  │  settings.html → Thresholds + History + CSV  │       │
│  └────────────────────┬─────────────────────────┘       │
└───────────────────────┼─────────────────────────────────┘
                        │ HTTP POST /api/v1/predict
                        ▼
┌─────────────────────────────────────────────────────────┐
│              FastAPI Backend (Python 3.14)               │
│                                                          │
│  SecurityMiddleware → Rate limit (100/60s) + Headers     │
│  CORSMiddleware     → chrome-extension:// + localhost    │
│                                                          │
│  POST /predict → feature_service → XGBoost → SHAP       │
│  GET  /history → scan history log (last 2000)            │
│  POST /feedback → user correction store                  │
│  GET  /health  → readiness + uptime probe                │
│  POST /allowlist, /blocklist → runtime list mgmt         │
│                                                          │
│  whitelist_service: <0.1ms bypass for top-1M domains     │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│           React SOC Dashboard (Vite + React 19)          │
│                                                          │
│  / Overview      → Metrics, trend, pie, recent scans     │
│  /scan           → Live URL scanner with SHAP viz        │
│  /history        → Paginated table + CSV export          │
│  /analytics      → Radar, bar, area, domain charts       │
│  /lists          → Allow/Block list management           │
│  /feedback       → Active learning review queue          │
└─────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Machine Learning** | XGBoost 2.x, Scikit-learn, SHAP (TreeExplainer) |
| **Feature Engineering** | 30+ lexical/structural URL features (pure Python, no requests) |
| **Backend API** | FastAPI, Uvicorn, Pydantic v2, Python 3.14 |
| **Chrome Extension** | Manifest V3, Vanilla JS, CSS, Web Extensions API |
| **React Dashboard** | Vite, React 19, React Router v7, Recharts, Axios |
| **Security** | Sliding-window rate limiter, input sanitisation, CSP headers |

---

## Project Structure

```
phishing-detector/
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI app + middleware registration
│   │   ├── api/
│   │   │   ├── predict.py             # POST /predict, /explain
│   │   │   ├── feedback.py            # POST/GET /feedback
│   │   │   ├── health.py              # GET /health, /stats
│   │   │   └── history.py             # GET /history, /admin/logs, /allowlist, /blocklist
│   │   ├── middleware/
│   │   │   └── security.py            # Rate limiter, security headers, input sanitisation
│   │   ├── models/
│   │   │   └── schemas.py             # Pydantic request/response schemas
│   │   └── services/
│   │       ├── predictor_service.py   # XGBoost inference + SHAP coordinator
│   │       ├── feature_service.py     # URL feature extraction (30+ features)
│   │       ├── explainer_service.py   # TreeSHAP local explanation service
│   │       └── whitelist_service.py   # Sub-0.1ms trusted domain bypass
│   ├── ml/
│   │   ├── train.py                   # XGBoost training pipeline
│   │   ├── evaluate.py                # Model evaluation (accuracy, AUC, F1)
│   │   ├── feature_engineering.py     # Feature definitions and dataset prep
│   │   └── models/
│   │       ├── xgboost_model.pkl      # Trained XGBoost classifier
│   │       └── feature_names.pkl      # Ordered feature name list
│   ├── run_server.py                  # Production server launcher
│   └── test_e2e.py                    # Full integration test suite (Phase 6)
│
├── extension/
│   ├── manifest.json                  # MV3 manifest with permissions + CSP
│   ├── background.js                  # Service worker: intercept, cache, route
│   ├── content.js                     # Injected warning banner for medium-risk
│   ├── popup/
│   │   ├── popup.html                 # Extension toolbar popup
│   │   ├── popup.js                   # Risk gauge, SHAP chips, feedback
│   │   └── popup.css                  # Dark SOC-style popup styling
│   ├── pages/
│   │   ├── blocked.html + blocked.js  # High-risk intercept page with SHAP
│   │   ├── warning.html + warning.js  # Medium-risk interstitial
│   │   └── settings.html + settings.js # User settings + history + CSV export
│   └── icons/
│
└── dashboard/
    ├── index.html
    ├── package.json
    └── src/
        ├── App.jsx                    # Router shell
        ├── index.css                  # Global dark SOC design system
        ├── api/client.js              # Axios API client
        ├── hooks/useFetch.js          # Generic async data hook
        ├── components/
        │   ├── Sidebar.jsx            # Nav + live backend status
        │   └── Shared.jsx             # RiskBadge, MetricCard, Spinner, etc.
        └── pages/
            ├── Overview.jsx           # Metrics + trend + pie + recent scans
            ├── ScanTool.jsx           # Live URL scanner with SHAP viz
            ├── DetectionHistory.jsx   # Paginated history + CSV export
            ├── Analytics.jsx          # Radar + bar + area + domain charts
            ├── Lists.jsx              # Allow/Block list management
            └── Feedback.jsx           # Active learning review queue
```

---

## Quick Start

### Prerequisites
- Python 3.10+ (tested on 3.14)
- Node.js 18+ (tested on 24)
- Google Chrome (for extension)

### 1. Install Python dependencies
```powershell
cd phishing-detector\backend
pip install -r requirements.txt
```

### 2. Start the FastAPI Backend
```powershell
python run_server.py
```
✅ API will be live at `http://127.0.0.1:8000`  
📚 Interactive docs at `http://127.0.0.1:8000/docs`

### 3. Start the React Dashboard
```powershell
cd phishing-detector\dashboard
npm install    # first time only
npm run dev
```
✅ Dashboard at `http://localhost:5173`

### 4. Install the Chrome Extension
1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** → select `phishing-detector\extension\`
4. The PhishGuard 🛡️ icon will appear in the toolbar

### 5. Run the End-to-End Test Suite
```powershell
cd phishing-detector\backend
python test_e2e.py
```

---

## Running Each Component

### Backend only (API server)
```powershell
python phishing-detector\backend\run_server.py
```

### CLI single-URL test (no server needed)
```powershell
python test_url.py "https://suspicious-domain.xyz/login"
```

### Full automated backend test suite
```powershell
python phishing-detector\backend\test_live_server.py   # original suite
python phishing-detector\backend\test_e2e.py           # full Phase 6 suite
```

### Dashboard dev server
```powershell
cd phishing-detector\dashboard
npm run dev
```

### Dashboard production build
```powershell
cd phishing-detector\dashboard
npm run build
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/predict` | Analyze URL → risk score + SHAP explanations |
| `POST` | `/api/v1/explain` | Get full SHAP factor list for a URL |
| `GET`  | `/api/v1/health` | Health/readiness probe + model metadata |
| `GET`  | `/api/v1/stats` | Live scan statistics counters |
| `GET`  | `/api/v1/history` | Recent scan history (default last 100, max 500) |
| `GET`  | `/api/v1/admin/logs` | Full admin scan log (max 2000) |
| `POST` | `/api/v1/feedback` | Submit user feedback / false-positive report |
| `GET`  | `/api/v1/feedback` | List recent feedback submissions |
| `POST` | `/api/v1/allowlist` | Add domain to runtime allowlist |
| `GET`  | `/api/v1/allowlist` | View runtime allowlist |
| `POST` | `/api/v1/blocklist` | Add domain to runtime blocklist |
| `GET`  | `/api/v1/blocklist` | View runtime blocklist |

### Example: Predict a URL
```bash
curl -X POST http://127.0.0.1:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-account-verify.xyz/login"}'
```

```json
{
  "url": "http://paypal-account-verify.xyz/login",
  "risk_score": 94.52,
  "phishing_probability": 0.9452,
  "verdict": "DANGEROUS / BLOCK",
  "action": "BLOCK",
  "is_whitelisted": false,
  "explanation": [
    {
      "feature": "phish_hints",
      "value": 2,
      "impact": "HIGH",
      "direction": "phishing",
      "message": "URL contains phishing keyword patterns ('verify', 'account')"
    }
  ],
  "latency_ms": 12.4,
  "timestamp": "2026-11-01T15:00:00Z"
}
```

---

## Chrome Extension Installation

1. Open `chrome://extensions/`
2. Toggle **Developer mode ON**
3. Click **Load unpacked**
4. Select folder: `phishing-detector\extension\`
5. Navigate to any URL — PhishGuard immediately begins scanning

### Extension Workflows
| Risk Level | Threshold | Behaviour |
|---|---|---|
| ✅ SAFE | < 50% | Green badge, no interruption |
| ⚠️ WARNING | 50%–84% | Warning interstitial, user can proceed |
| 🛑 PHISHING | ≥ 85% | Full redirect to blocked.html with SHAP breakdown |

---

## Security Features

| Feature | Implementation |
|---|---|
| Rate Limiting | Sliding-window 100 req/60s per IP (native, no external deps) |
| Input Sanitisation | Strip control characters, truncate URLs > 2048 chars |
| Request Size Guard | 8KB max body size on POST/PUT |
| Security Headers | X-Content-Type-Options, X-Frame-Options, XSS-Protection, Referrer-Policy, CSP |
| CSP Hardening | Extension pages: `script-src 'self'; object-src 'self'` (no inline scripts) |
| CORS | Configured for `chrome-extension://` and `localhost` origins |

---

*PhishGuard · Built with XGBoost + SHAP + FastAPI + Chrome MV3 + React*

