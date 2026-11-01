"""
PhishGuard — FastAPI Automated Integration Test Suite
=====================================================
Tests all REST endpoints using FastAPI TestClient:
  1. Health check & model metadata
  2. Whitelist instant clearance
  3. Safe site inference & SHAP explainability
  4. Phishing attack detection & BLOCK action
  5. User feedback submission & retrieval
  6. Statistics and scan counters
"""

import sys
import os

sys.stdout.reconfigure(encoding="utf-8")

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from fastapi.testclient import TestClient
from app.main import app

def run_tests():
    print("="*70)
    print("[*] RUNNING PHISHGUARD REST API INTEGRATION TESTS")
    print("="*70)

    with TestClient(app) as client:
        # Test 1: Health Check
        print("\n[TEST 1] GET /api/v1/health")
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        data = resp.json()
        print(f"  Status        : {data['status']}")
        print(f"  Model Loaded  : {data['model_loaded']}")
        print(f"  Features Count: {data['features_count']}")
        assert data["model_loaded"] is True
        print("  -> PASSED [OK]")

        # Test 2: Whitelisted Top Domain (Instant Clearance)
        print("\n[TEST 2] POST /api/v1/predict (Trusted Domain Whitelist)")
        payload = {"url": "https://www.google.com/search?q=cybersecurity"}
        resp = client.post("/api/v1/predict", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        print(f"  URL           : {data['url']}")
        print(f"  Risk Score    : {data['risk_score']}%")
        print(f"  Verdict       : {data['verdict']}")
        print(f"  Action        : {data['action']}")
        print(f"  Whitelisted   : {data['is_whitelisted']}")
        print(f"  Latency       : {data['latency_ms']} ms")
        assert data["action"] == "ALLOW"
        assert data["is_whitelisted"] is True
        print("  -> PASSED [OK]")

        # Test 3: Legitimate Complex Site (ML + SHAP)
        print("\n[TEST 3] POST /api/v1/predict (Legitimate Site via ML)")
        payload = {
            "url": "https://www.medicalnewstoday.com/articles/18893",
            "page_title": "Medical News Today - Health Articles",
            "nb_hyperlinks": 45,
            "has_login_form": False
        }
        resp = client.post("/api/v1/predict", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        print(f"  URL           : {data['url']}")
        print(f"  Risk Score    : {data['risk_score']}%")
        print(f"  Verdict       : {data['verdict']}")
        print(f"  Action        : {data['action']}")
        print(f"  SHAP Reasons  : {len(data['explanation'])} factors returned")
        assert data["action"] == "ALLOW"
        print("  -> PASSED [OK]")

        # Test 4: Phishing Attack Detection
        print("\n[TEST 4] POST /api/v1/predict (Phishing Attack Detection)")
        payload = {
            "url": "http://192.168.1.100/paypal-update/verification/login.php?token=99281aed",
            "page_title": "PayPal - Login Verification",
            "nb_hyperlinks": 2,
            "has_login_form": True
        }
        resp = client.post("/api/v1/predict", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        print(f"  URL           : {data['url']}")
        print(f"  Risk Score    : {data['risk_score']}%")
        print(f"  Verdict       : {data['verdict']}")
        print(f"  Action        : {data['action']}")
        assert data["action"] == "BLOCK"
        print("  Top SHAP Explanations:")
        for r in data["explanation"][:3]:
            print(f"    - [{r['impact']}] {r['message']} (value: {r['value']})")
        print("  -> PASSED [OK]")

        # Test 5: Explain Endpoint
        print("\n[TEST 5] POST /api/v1/explain")
        resp = client.post("/api/v1/explain", json={"url": "http://clubedemilhagem.com/home.php"})
        assert resp.status_code == 200
        reasons = resp.json()
        print(f"  Factors count : {len(reasons)}")
        assert len(reasons) > 0
        print("  -> PASSED [OK]")

        # Test 6: User Feedback Submission
        print("\n[TEST 6] POST /api/v1/feedback (False Positive/Negative Reporting)")
        fb_payload = {
            "url": "https://internal-company-portal.local",
            "reported_as": "false_positive",
            "user_comment": "Corporate intranet site"
        }
        resp = client.post("/api/v1/feedback", json=fb_payload)
        assert resp.status_code == 201
        fb_data = resp.json()
        print(f"  Success       : {fb_data['success']}")
        print(f"  Report ID     : {fb_data['report_id']}")
        assert fb_data["success"] is True
        print("  -> PASSED [OK]")

        # Test 7: System Statistics
        print("\n[TEST 7] GET /api/v1/stats")
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 200
        stats = resp.json()
        print(f"  Total Scans   : {stats['total_scans']}")
        print(f"  Safe Sites    : {stats['safe_count']}")
        print(f"  Blocked Sites : {stats['blocked_count']}")
        print(f"  Feedback Logs : {stats['feedback_reports']}")
        assert stats["total_scans"] >= 3
        print("  -> PASSED [OK]")

    print("\n" + "="*70)
    print("[SUCCESS] ALL REST API ENDPOINTS VALIDATED SUCCESSFULLY!")
    print("="*70)

if __name__ == "__main__":
    run_tests()
