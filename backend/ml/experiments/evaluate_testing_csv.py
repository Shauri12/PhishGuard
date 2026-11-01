"""
PhishGuard — Evaluation on Testing.csv (3,772 URLs)
===================================================
Evaluates the trained 25-feature XGBoost model on the new Testing.csv dataset.
Generates comprehensive results exported directly to Testing_results.csv.
"""

import sys
import os
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
INPUT_CSV  = os.path.join(ROOT_DIR, "Testing.csv")
OUTPUT_CSV = os.path.join(ROOT_DIR, "Testing_results.csv")

print("[+] Loading trained model and features...")
model       = joblib.load(os.path.join(MODELS_DIR, "xgboost_model.pkl"))
feat_names  = joblib.load(os.path.join(MODELS_DIR, "feature_names.pkl"))

print(f"[+] Loading {INPUT_CSV}...")
df = pd.read_csv(INPUT_CSV)
print(f"[+] Total samples: {len(df):,}")
print(f"[+] Class breakdown:\n{df['status'].value_counts()}")

# Extract features
X = df[feat_names]
y_true = (df["status"] == "phishing").astype(int)

# Inference
print("[+] Running predictions...")
proba = model.predict_proba(X)[:, 1]
preds = (proba >= 0.50).astype(int)

df["phishing_probability"] = np.round(proba, 4)
df["predicted_status"] = np.where(preds == 1, "phishing", "legitimate")

def assign_verdict(p):
    if p >= 0.70:
        return "🛑 DANGEROUS / BLOCK"
    elif p >= 0.35:
        return "⚠️ SUSPICIOUS / WARN"
    else:
        return "✅ SAFE / ALLOW"

df["verdict"] = [assign_verdict(p) for p in proba]
df["is_correct"] = np.where(df["predicted_status"] == df["status"], "YES", "NO")

# Metrics calculation
acc  = accuracy_score(y_true, preds)
prec = precision_score(y_true, preds)
rec  = recall_score(y_true, preds)
f1   = f1_score(y_true, preds)
auc  = roc_auc_score(y_true, proba)
cm   = confusion_matrix(y_true, preds)
tn, fp, fn, tp = cm.ravel()
specificity = tn / (tn + fp)
fpr = fp / (tn + fp)
fnr = fn / (fn + tp)

print("\n" + "="*70)
print("📊 EVALUATION RESULTS ON Testing.csv (3,772 URLs)")
print("="*70)
print(f"Total Test Samples     : {len(df):,}")
print(f"Accuracy               : {acc*100:6.2f}%")
print(f"Precision              : {prec*100:6.2f}%")
print(f"Recall (Catch Rate)    : {rec*100:6.2f}%")
print(f"Specificity            : {specificity*100:6.2f}%")
print(f"F1-Score               : {f1*100:6.2f}%")
print(f"AUC-ROC                : {auc*100:6.2f}%")
print(f"False Positive Rate    : {fpr*100:6.2f}% ({fp:,} false alarms)")
print(f"False Negative Rate    : {fnr*100:6.2f}% ({fn:,} missed attacks)")

print("\nConfusion Matrix:")
print(f"               Predicted Legit    Predicted Phish")
print(f"Actual Legit :     {tn:>10,}         {fp:>10,}")
print(f"Actual Phish :     {fn:>10,}         {tp:>10,}")
print("="*70)

# Export Summary Metrics to CSV
METRICS_CSV = os.path.join(ROOT_DIR, "Testing_metrics.csv")
REPORTS_DIR = os.path.join(ROOT_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

metrics_summary = pd.DataFrame([
    {"Metric": "Total Test Samples", "Value": str(len(df)), "Percentage": "100.00%"},
    {"Metric": "Accuracy", "Value": f"{acc:.4f}", "Percentage": f"{acc*100:.2f}%"},
    {"Metric": "Precision", "Value": f"{prec:.4f}", "Percentage": f"{prec*100:.2f}%"},
    {"Metric": "Recall / Sensitivity", "Value": f"{rec:.4f}", "Percentage": f"{rec*100:.2f}%"},
    {"Metric": "Specificity", "Value": f"{specificity:.4f}", "Percentage": f"{specificity*100:.2f}%"},
    {"Metric": "F1-Score", "Value": f"{f1:.4f}", "Percentage": f"{f1*100:.2f}%"},
    {"Metric": "AUC-ROC", "Value": f"{auc:.4f}", "Percentage": f"{auc*100:.2f}%"},
    {"Metric": "True Positives (TP - Caught Phishing)", "Value": str(tp), "Percentage": f"{(tp/(fn+tp))*100:.2f}%"},
    {"Metric": "True Negatives (TN - Allowed Legitimate)", "Value": str(tn), "Percentage": f"{(tn/(tn+fp))*100:.2f}%"},
    {"Metric": "False Positives (FP - False Alarms)", "Value": str(fp), "Percentage": f"{fpr*100:.2f}%"},
    {"Metric": "False Negatives (FN - Missed Attacks)", "Value": str(fn), "Percentage": f"{fnr*100:.2f}%"},
])

metrics_summary.to_csv(METRICS_CSV, index=False, encoding="utf-8")
metrics_summary.to_csv(os.path.join(REPORTS_DIR, "Testing_metrics.csv"), index=False, encoding="utf-8")
print(f"\n[+] Saved metrics summary CSV to: {METRICS_CSV}")

# Export per-sample prediction results to CSV
output_cols = [
    "url", "status", "predicted_status", "phishing_probability",
    "verdict", "is_correct", "length_url", "length_hostname", "ip",
    "nb_dots", "nb_qm", "nb_slash", "phish_hints", "google_index", "page_rank"
]
remaining_cols = [c for c in df.columns if c not in output_cols]
final_df = df[output_cols + remaining_cols]

print(f"[+] Saving full per-sample results to CSV: {OUTPUT_CSV}...")
final_df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")
final_df.to_csv(os.path.join(REPORTS_DIR, "Testing_results.csv"), index=False, encoding="utf-8")
print(f"[✓] Saved successfully! ({len(final_df):,} rows)")
