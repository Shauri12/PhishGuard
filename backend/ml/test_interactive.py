"""
PhishGuard — Interactive URL Threat Classifier & SHAP Explainer
==============================================================
Extracts the 25 benchmark features, evaluates using the retrained XGBoost model,
and explains predictions using SHAP TreeExplainer.
"""

import sys
import os
import joblib
import pandas as pd
import numpy as np

sys.stdout.reconfigure(encoding="utf-8")

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR  = os.path.join(SCRIPT_DIR, "models")
BACKEND_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
ROOT_DIR    = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", ".."))
LOCAL_CSV   = os.path.join(BACKEND_DIR, "..", "Testing.csv")
TESTING_CSV = LOCAL_CSV if os.path.exists(LOCAL_CSV) else os.path.join(ROOT_DIR, "Testing.csv")

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.services.feature_service import extract_features, get_feature_dataframe
from app.services.whitelist_service import is_domain_whitelisted
from explainer import PhishGuardExplainer

# Load model and feature schema
model         = joblib.load(os.path.join(MODELS_DIR, "xgboost_model.pkl"))
feature_names = joblib.load(os.path.join(MODELS_DIR, "feature_names.pkl"))
explainer     = PhishGuardExplainer(model, feature_names)

def get_threat_badge(prob: float):
    if prob >= 0.70:
        return "🛑 DANGEROUS / BLOCK", "phishing"
    elif prob >= 0.35:
        return "⚠️  SUSPICIOUS / WARN", "suspicious"
    else:
        return "✅ SAFE / ALLOW", "legitimate"

def render_result(title: str, url_or_desc: str, prob: float, ground_truth=None, whitelisted: bool = False):
    badge, category = get_threat_badge(prob)
    print("\n" + "="*70)
    print(f"🎯 {title.upper()}")
    print("="*70)
    print(f" Target URL : {url_or_desc}")
    if whitelisted:
        print(f" Whitelist  : 🛡️  VERIFIED TRUSTED DOMAIN (Instant Allow)")
    print(f" Risk Score : {prob * 100:6.2f}% (Phishing Probability: {prob:.4f})")
    print(f" Verdict    : {badge}")
    if ground_truth is not None:
        gt_str = "PHISHING" if ground_truth == 1 else "LEGITIMATE"
        match = "✅ MATCH" if (prob >= 0.5 and ground_truth == 1) or (prob < 0.5 and ground_truth == 0) else "❌ MISMATCH"
        print(f" True Label : {gt_str} [{match}]")

def explain_row(row_df: pd.DataFrame, top_n: int = 5):
    res = explainer.explain(row_df, top_n=top_n)
    print("\n🔍 TOP SHAP CONTRIBUTING FACTORS (Explainability):")
    print(f"   {'Dir':<3} | {'Impact':<6} | {'Feature':<22} | {'Value':<10} | Reason")
    print("   " + "-"*68)
    for r in res["top_reasons"]:
        arrow = "🔴 +" if r["direction"] == "phishing" else "🟢 -"
        print(f"   {arrow:<3} | {r['impact']:<6} | {r['feature']:<22} | {str(r['value']):<10} | {r['message']}")
    print("="*70 + "\n")

def run_test_sample(sample_type="phishing"):
    print(f"\n[+] Fetching a random {sample_type.upper()} sample from Testing.csv...")
    if not os.path.exists(TESTING_CSV):
        print(f"[-] Benchmark test dataset not found at {TESTING_CSV}")
        return

    df = pd.read_csv(TESTING_CSV)
    sub_df = df[df["status"] == sample_type]
    sample = sub_df.sample(n=1, random_state=int(np.random.randint(1, 100000)))
    
    url = sample["url"].values[0] if "url" in sample.columns else f"Sample #{sample.index[0]}"
    X_sample = sample[[f for f in feature_names if f in sample.columns]]
    prob = float(model.predict_proba(X_sample)[0, 1])

    expected_threat = 1 if sample_type == "phishing" else 0
    render_result(f"Dataset Test Sample ({sample_type})", url, prob, ground_truth=expected_threat)
    explain_row(X_sample, top_n=5)

def run_custom_url(url: str):
    whitelisted = is_domain_whitelisted(url)
    feat_dict = extract_features(url)
    X_url = get_feature_dataframe(feat_dict, feature_names)
    prob = float(model.predict_proba(X_url)[0, 1])
    render_result("Live URL Prediction", url, prob, whitelisted=whitelisted)
    explain_row(X_url, top_n=5)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == "--sample-legit":
            run_test_sample("legitimate")
        elif arg == "--sample-phish":
            run_test_sample("phishing")
        else:
            run_custom_url(arg)
    else:
        print("\n" + "="*70)
        print("🚀 RUNNING AUTOMATED DEMO TEST (25 Benchmark Features)")
        print("="*70)
        run_custom_url("https://www.google.com")
        run_custom_url("https://www.wikipedia.org")
        run_custom_url("http://paypal-security-update.com/login")
        run_custom_url("http://192.168.1.1/update/login.php?user=admin&id=99281")
