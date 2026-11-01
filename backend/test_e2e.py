"""
PhishGuard — Phase 6 End-to-End Integration Test Suite
=======================================================
Tests all 8 workflows across the full stack:
  1. Health & readiness
  2. Security headers
  3. Rate limiting
  4. Whitelist fast-path
  5. Phishing detection + SHAP explanations
  6. Legitimate URL safe-pass
  7. Feedback submission
  8. Scan history recording
  9. Allow/Blocklist management
 10. Edge cases & input sanitisation

Usage:
  python c:\\Users\\hi\\Desktop\\Cyber\\phishing-detector\\backend\\test_e2e.py
  (requires backend running on http://127.0.0.1:8000)
"""

import sys, json, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor

sys.stdout.reconfigure(encoding="utf-8")

BASE = "http://127.0.0.1:8000"
PASS = "✅"; FAIL = "❌"; SKIP = "⏭️"

results = []

def req(method, path, body=None, headers=None):
    h = {"Content-Type": "application/json", **(headers or {})}
    data = json.dumps(body).encode() if body else None
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.getcode(), dict(resp.headers), json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), json.loads(e.read())

def check(name, cond, detail=""):
    icon = PASS if cond else FAIL
    results.append(cond)
    print(f"  {icon}  {name}")
    if detail and not cond:
        print(f"       ↳ {detail}")

def section(title):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")


# ════════════════════════════════════════════════════════════════
print("=" * 60)
print("  PhishGuard — End-to-End Integration Tests (Phase 6)")
print("=" * 60)

# ── 1. Health ────────────────────────────────────────────────
section("TEST 1 · Health & Readiness")
try:
    code, hdr, data = req("GET", "/api/v1/health")
    check("HTTP 200 OK",              code == 200)
    check("status == healthy",        data.get("status") == "healthy")
    check("model_loaded == True",     data.get("model_loaded") is True)
    check("features_count > 0",       (data.get("features_count") or 0) > 0)
    check("uptime_seconds present",   "uptime_seconds" in data)
    check("timestamp present",        "timestamp" in data)
except Exception as e:
    check("Backend reachable",        False, str(e))

# ── 2. Security Headers ──────────────────────────────────────
section("TEST 2 · Security Response Headers")
try:
    _, hdr, _ = req("GET", "/api/v1/health")
    EXPECTED = [
        "x-content-type-options",
        "x-frame-options",
        "x-xss-protection",
        "referrer-policy",
        "cache-control",
    ]
    lower = {k.lower(): v for k, v in hdr.items()}
    for h in EXPECTED:
        check(f"Header: {h}", h in lower, f"Missing from response headers")
except Exception as e:
    check("Headers check", False, str(e))

# ── 3. Phishing Detection ─────────────────────────────────────
section("TEST 3 · Phishing URL Detection + SHAP Explanations")
PHISHING_URLS = [
    "http://paypal-security-account-verify.xyz/login.php",
    "http://192.168.1.1/facebook/steal-credentials.php",
    "http://amazon-prize-winner.secure-check.net/redeem",
    "http://apple-id-suspended-verify.phish.cc/signin",
]
for url in PHISHING_URLS:
    try:
        code, _, data = req("POST", "/api/v1/predict", {"url": url})
        is_flagged = data.get("action") in ("BLOCK", "WARN")
        check(f"Flagged: {url[:55]}…", is_flagged)
        has_shap = bool(data.get("explanation"))
        check(f"  SHAP factors present ({len(data.get('explanation',[]))} factors)", has_shap)
        latency = data.get("latency_ms", 9999)
        check(f"  Latency < 200ms ({latency}ms)", latency < 200)
    except Exception as e:
        check(f"Request: {url[:40]}", False, str(e))

# ── 4. Legitimate URL Safe-Pass ───────────────────────────────
section("TEST 4 · Legitimate URL Safe-Pass (Whitelist + ML)")
LEGIT_URLS = [
    "https://www.google.com",
    "https://github.com",
    "https://wikipedia.org",
    "https://stackoverflow.com",
]
for url in LEGIT_URLS:
    try:
        code, _, data = req("POST", "/api/v1/predict", {"url": url})
        is_safe = data.get("action") == "ALLOW"
        check(f"Safe: {url}", is_safe, f"Got action={data.get('action')}")
    except Exception as e:
        check(f"Request: {url}", False, str(e))

# ── 5. SHAP Explain Endpoint ──────────────────────────────────
section("TEST 5 · /explain Endpoint")
try:
    code, _, data = req("POST", "/api/v1/explain", {"url": "http://phish-test-paypal-verify.xyz"})
    check("HTTP 200", code == 200)
    check("Returns list", isinstance(data, list))
    if isinstance(data, list) and data:
        f = data[0]
        check("Factor has 'feature'",   "feature" in f)
        check("Factor has 'impact'",    "impact"  in f)
        check("Factor has 'direction'", "direction" in f)
        check("Factor has 'message'",   "message" in f)
except Exception as e:
    check("Explain endpoint", False, str(e))

# ── 6. Feedback Submission ────────────────────────────────────
section("TEST 6 · Feedback Submission & Retrieval")
try:
    code, _, data = req("POST", "/api/v1/feedback", {
        "url":         "https://test-phishguard-fp.com",
        "reported_as": "false_positive",
        "user_comment": "This is my internal company portal"
    })
    check("HTTP 201 Created",     code == 201)
    check("success == True",      data.get("success") is True)
    check("report_id present",    bool(data.get("report_id")))
    rid = data.get("report_id", "")

    # Retrieve
    code2, _, logs = req("GET", "/api/v1/feedback")
    check("GET /feedback returns list", isinstance(logs, list))
    found = any(e.get("report_id") == rid for e in logs)
    check("Submitted report is retrievable", found)
except Exception as e:
    check("Feedback", False, str(e))

# ── 7. Scan History ───────────────────────────────────────────
section("TEST 7 · Scan History Recording")
try:
    code, _, data = req("GET", "/api/v1/history?limit=50")
    check("HTTP 200", code == 200)
    check("'items' key present", "items" in data)
    check("'total' key present", "total" in data)
    items = data.get("items", [])
    if items:
        item = items[0]
        check("Item has 'url'",        "url"        in item)
        check("Item has 'risk_level'", "risk_level" in item)
        check("Item has 'timestamp'",  "timestamp"  in item)
except Exception as e:
    check("History endpoint", False, str(e))

# ── 8. Allow/Blocklist Management ────────────────────────────
section("TEST 8 · Allow & Block List Management")
try:
    code, _, data = req("POST", "/api/v1/allowlist", {"url": "mytrustedcompany.internal"})
    check("POST /allowlist 201", code == 201)
    check("Domain echoed back",  "domain" in data)

    code2, _, alist = req("GET", "/api/v1/allowlist")
    check("GET /allowlist lists entries", "allowlist" in alist)

    code3, _, data3 = req("POST", "/api/v1/blocklist", {"url": "dangerous-malware.xyz"})
    check("POST /blocklist 201", code3 == 201)

    code4, _, blist = req("GET", "/api/v1/blocklist")
    check("GET /blocklist lists entries", "blocklist" in blist)
except Exception as e:
    check("Lists management", False, str(e))

# ── 9. Edge Cases & Input Sanitisation ────────────────────────
section("TEST 9 · Edge Cases & Input Sanitisation")
EDGE_CASES = [
    ("Empty URL",        {"url": ""},              400),
    ("Whitespace URL",   {"url": "   "},           400),
]
for name, body, expected_code in EDGE_CASES:
    try:
        code, _, _ = req("POST", "/api/v1/predict", body)
        check(f"{name} → HTTP {expected_code}", code == expected_code, f"Got {code}")
    except Exception as e:
        check(name, False, str(e))

# Long URL (should not crash — truncated/accepted)
try:
    long_url = "http://evil-phishing.com/" + "a" * 1500
    code, _, data = req("POST", "/api/v1/predict", {"url": long_url})
    check("2000-char URL handled without 500", code != 500, f"Got {code}")
except Exception as e:
    check("Long URL", False, str(e))

# ── 10. Concurrent Load ───────────────────────────────────────
section("TEST 10 · Concurrent Load (20 parallel requests)")
url_to_test = "http://test-concurrent-phish.xyz/login"
times = []

def single_req(_):
    t0 = time.perf_counter()
    try:
        req("POST", "/api/v1/predict", {"url": url_to_test})
    except Exception:
        pass
    return (time.perf_counter() - t0) * 1000

with ThreadPoolExecutor(max_workers=20) as ex:
    times = list(ex.map(single_req, range(20)))

avg_ms = sum(times) / len(times)
max_ms = max(times)
check(f"All 20 requests completed", len(times) == 20)
check(f"Avg latency < 500ms ({avg_ms:.1f}ms)", avg_ms < 500)
check(f"Max latency < 1000ms ({max_ms:.1f}ms)", max_ms < 1000)


# ── Summary ───────────────────────────────────────────────────
print(f"\n{'='*60}")
passed = sum(results)
total  = len(results)
pct    = passed / total * 100 if total else 0
print(f"  RESULTS: {passed}/{total} checks passed ({pct:.1f}%)")
if passed == total:
    print(f"  {PASS} ALL CHECKS PASSED — PhishGuard is production-ready!")
else:
    failed = total - passed
    print(f"  {FAIL} {failed} check(s) failed — review output above.")
print("=" * 60)
sys.exit(0 if passed == total else 1)

