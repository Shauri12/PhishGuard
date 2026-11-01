"""
PhishGuard — External Benchmark Validation on dataset_phishing.csv (11,430 URLs)
==============================================================================
Validates the trained 12-feature XGBoost model on the external Mendeley/Kaggle
benchmark dataset (5,715 legitimate + 5,715 phishing).
Generates a comprehensive multi-tab Excel report:
  - Sheet 1: Executive Summary & Metrics
  - Sheet 2: Detailed Predictions (all 11,430 URLs)
  - Sheet 3: Misclassified URLs Analysis
"""

import sys
import os
import re
import urllib.parse
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

sys.stdout.reconfigure(encoding="utf-8")

ROOT_DIR   = r"C:\Users\hi\Desktop\Cyber"
MODELS_DIR = os.path.join(ROOT_DIR, "phishing-detector", "backend", "ml", "models")
INPUT_CSV  = os.path.join(ROOT_DIR, "dataset_phishing.csv")
OUTPUT_XLS = os.path.join(ROOT_DIR, "phishing_validation_results.xlsx")

print("[+] Loading model and encoders...")
model         = joblib.load(os.path.join(MODELS_DIR, "xgboost_model.pkl"))
feature_names = joblib.load(os.path.join(MODELS_DIR, "feature_names.pkl"))
tld_encoder   = joblib.load(os.path.join(MODELS_DIR, "tld_encoder.pkl"))

print(f"[+] Loading test dataset: {INPUT_CSV}")
df = pd.read_csv(INPUT_CSV)
print(f"[+] Total URLs to evaluate: {len(df):,}")

# Ground truth recovery for Mendeley 11,430 dataset
# If 'status' is already in df, use it; otherwise fetch the reference labels
if "status" in df.columns:
    df["true_label"] = df["status"].map({"phishing": 1, "legitimate": 0})
else:
    print("[+] Merging ground-truth labels from verified benchmark index...")
    ref_url = "https://raw.githubusercontent.com/frangelbarrera/phishing-detection-rnn-cnn/main/dataset_phishing.csv"
    try:
        ref_df = pd.read_csv(ref_url, usecols=["url", "status"])
        df["status"] = ref_df["status"]
        df["true_label"] = df["status"].map({"phishing": 1, "legitimate": 0})
    except Exception as e:
        print(f"[!] Network fetch failed ({e}), checking local cache or using internal feature status...")
        # Fallback: the 11,430 benchmark is standard 50/50 split
        # rows 0-5714 are legitimate in some variants or interleaved
        pass

print(f"[+] Ground truth distribution:\n{df['status'].value_counts()}")

# ─── Feature Extraction ────────────────────────────────────────────────────────
print("\n[+] Extracting 12 URL structural features for all 11,430 URLs...")

ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
obf_pattern = re.compile(r"%[0-9a-fA-F]{2}")
tld_freq_map = {"com": 0.52, "org": 0.08, "net": 0.04, "edu": 0.01, "gov": 0.003, "de": 0.03, "uk": 0.02}

def extract_row(url_str):
    target = url_str if "://" in str(url_str) else "http://" + str(url_str)
    parsed = urllib.parse.urlparse(target)
    netloc = parsed.netloc.split(":")[0]

    is_ip = 1 if ip_pattern.match(netloc) else 0

    parts = netloc.split(".")
    tld = parts[-1].lower() if len(parts) > 1 and not is_ip else "unknown"
    tld_len = len(tld)
    try:
        tld_enc = tld_encoder.transform([tld])[0]
    except Exception:
        tld_enc = 0

    tld_prob = tld_freq_map.get(tld, 0.01)
    subdomains = max(0, len(parts) - 2) if not is_ip else 0

    s = str(url_str)
    digits = sum(c.isdigit() for c in s)
    eqs = s.count("=")
    qms = s.count("?")
    amps = s.count("&")
    obf = 1 if ("@" in s or obf_pattern.search(s)) else 0

    return {
        "URLLength": float(len(s)),
        "DomainLength": float(len(netloc)),
        "NoOfSubDomain": float(subdomains),
        "IsDomainIP": float(is_ip),
        "TLDLength": float(tld_len),
        "TLDLegitimateProb": float(tld_prob),
        "TLD_encoded": float(tld_enc),
        "NoOfDegitsInURL": float(digits),
        "NoOfEqualsInURL": float(eqs),
        "NoOfQMarkInURL": float(qms),
        "NoOfAmpersandInURL": float(amps),
        "HasObfuscation": float(obf),
    }

extracted_rows = [extract_row(u) for u in df["url"]]
X_eval = pd.DataFrame(extracted_rows)[feature_names]

# ─── Inference ─────────────────────────────────────────────────────────────────
print("[+] Running model predictions across all 11,430 URLs...")
proba = model.predict_proba(X_eval)[:, 1]
preds = (proba >= 0.50).astype(int)

df["phishing_probability"] = np.round(proba, 4)
df["predicted_label"] = preds
df["predicted_status"] = np.where(preds == 1, "phishing", "legitimate")

def assign_verdict(p):
    if p >= 0.70:
        return "🛑 DANGEROUS / BLOCK"
    elif p >= 0.35:
        return "⚠️ SUSPICIOUS / WARN"
    else:
        return "✅ SAFE / ALLOW"

df["verdict"] = [assign_verdict(p) for p in proba]
df["is_correct"] = np.where(df["predicted_label"] == df["true_label"], "YES", "NO")

# ─── Evaluation Metrics ────────────────────────────────────────────────────────
y_true = df["true_label"].values
acc  = accuracy_score(y_true, preds)
prec = precision_score(y_true, preds)
rec  = recall_score(y_true, preds)
f1   = f1_score(y_true, preds)
auc  = roc_auc_score(y_true, proba)
cm   = confusion_matrix(y_true, preds)
tn, fp, fn, tp = cm.ravel()

print("\n" + "="*70)
print("📊 EXTERNAL BENCHMARK VALIDATION RESULTS (11,430 URLs)")
print("="*70)
print(f"Total Test Samples     : {len(df):,}")
print(f"Accuracy               : {acc*100:6.2f}%")
print(f"Precision              : {prec*100:6.2f}%")
print(f"Recall (Sensitivity)   : {rec*100:6.2f}%")
print(f"Specificity            : {tn/(tn+fp)*100:6.2f}%")
print(f"F1 Score               : {f1*100:6.2f}%")
print(f"AUC-ROC                : {auc*100:6.2f}%")
print(f"False Positive Rate    : {fp/(tn+fp)*100:6.2f}% ({fp:,} false alarms)")
print(f"False Negative Rate    : {fn/(fn+tp)*100:6.2f}% ({fn:,} missed attacks)")

print("\nConfusion Matrix:")
print(f"               Predicted Legit    Predicted Phish")
print(f"Actual Legit :     {tn:>10,}         {fp:>10,}")
print(f"Actual Phish :     {fn:>10,}         {tp:>10,}")
print("="*70)

# ─── Generate Multi-Sheet Excel File ───────────────────────────────────────────
print(f"\n[+] Writing Excel results to: {OUTPUT_XLS}")

summary_df = pd.DataFrame([
    {"Metric": "Total URLs Evaluated", "Value": f"{len(df):,}"},
    {"Metric": "Model Architecture", "Value": "XGBoost (De-Biased 12 Features)"},
    {"Metric": "Accuracy", "Value": f"{acc*100:.2f}%"},
    {"Metric": "Precision (Catch Accuracy)", "Value": f"{prec*100:.2f}%"},
    {"Metric": "Recall (Threat Detection Rate)", "Value": f"{rec*100:.2f}%"},
    {"Metric": "Specificity (Safe Site Clearance)", "Value": f"{tn/(tn+fp)*100:.2f}%"},
    {"Metric": "F1-Score", "Value": f"{f1*100:.2f}%"},
    {"Metric": "AUC-ROC", "Value": f"{auc*100:.2f}%"},
    {"Metric": "True Negatives (Legit Cleaned)", "Value": f"{tn:,}"},
    {"Metric": "True Positives (Phish Blocked)", "Value": f"{tp:,}"},
    {"Metric": "False Positives (False Alarms)", "Value": f"{fp:,}"},
    {"Metric": "False Negatives (Missed Phish)", "Value": f"{fn:,}"},
    {"Metric": "Total Correct Classifications", "Value": f"{tp+tn:,} ({((tp+tn)/len(df))*100:.2f}%)"},
])

details_cols = [
    "url", "status", "predicted_status", "phishing_probability",
    "verdict", "is_correct", "URLLength", "DomainLength", "NoOfSubDomain",
    "IsDomainIP", "NoOfDegitsInURL", "NoOfEqualsInURL", "NoOfQMarkInURL"
]
for col in feature_names:
    if col not in df.columns:
        df[col] = X_eval[col]

details_df = df[details_cols]
errors_df = df[df["is_correct"] == "NO"][details_cols]

with pd.ExcelWriter(OUTPUT_XLS, engine="openpyxl") as writer:
    summary_df.to_excel(writer, sheet_name="Summary_Metrics", index=False)
    details_df.to_excel(writer, sheet_name="Detailed_Predictions", index=False)
    errors_df.to_excel(writer, sheet_name="Misclassified_Analysis", index=False)

print(f"[✓] Excel file created successfully with {len(details_df):,} rows and 3 sheets.")
