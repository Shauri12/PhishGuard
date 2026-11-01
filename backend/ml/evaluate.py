"""
PhishGuard — Model Evaluation Script
======================================
Run this AFTER training to:
  - Print detailed classification metrics
  - Generate all evaluation plots (ROC, PR, confusion matrix)
  - Generate SHAP summary + waterfall plots
  - Test the explanation pipeline end-to-end
  - Uses clean feature set (leaky features removed)

Usage:
  python evaluate.py
"""

import sys
sys.stdout.reconfigure(encoding="utf-8")

import os
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import shap

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report, roc_curve,
    precision_recall_curve, average_precision_score
)

# ─── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
PLOTS_DIR  = os.path.join(BASE_DIR, "plots")
DATASET    = os.path.join(
    BASE_DIR, "..", "..", "..",
    "phiusiil+phishing+url+dataset",
    "PhiUSIIL_Phishing_URL_Dataset.csv"
)
os.makedirs(PLOTS_DIR, exist_ok=True)

# Features and encoders are dynamically loaded from saved artifacts below


def section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ─── Load artifacts ────────────────────────────────────────────────────────────
section("Loading Model Artifacts")
model         = joblib.load(os.path.join(MODELS_DIR, "xgboost_model.pkl"))
tld_encoder   = joblib.load(os.path.join(MODELS_DIR, "tld_encoder.pkl"))
feature_names = joblib.load(os.path.join(MODELS_DIR, "feature_names.pkl"))

with open(os.path.join(MODELS_DIR, "metrics.json")) as f:
    saved_metrics = json.load(f)

print("[+] All artifacts loaded.")
print(f"[+] Model type    : {type(model).__name__}")
print(f"[+] Features      : {len(feature_names)}")
print(f"[+] Saved Accuracy: {saved_metrics['accuracy']*100:.4f}%")


# ─── Load & Prepare data ───────────────────────────────────────────────────────
section("Loading Dataset for Re-evaluation")
df = pd.read_csv(DATASET, encoding="utf-8-sig")
df["TLD_encoded"] = tld_encoder.transform(df["TLD"].astype(str))
df.drop(columns=[c for c in ["FILENAME","URL","Domain","Title","TLD"] if c in df.columns], inplace=True)

y = df["label"].astype(int)
X = df[[f for f in feature_names if f in df.columns]]

_, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)


# ─── Full Evaluation ───────────────────────────────────────────────────────────
section("Classification Report")
y_pred  = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec  = recall_score(y_test, y_pred)
f1   = f1_score(y_test, y_pred)
auc  = roc_auc_score(y_test, y_proba)
ap   = average_precision_score(y_test, y_proba)
cm   = confusion_matrix(y_test, y_pred)

print(f"  Accuracy          : {acc*100:.4f}%")
print(f"  Precision         : {prec*100:.4f}%")
print(f"  Recall            : {rec*100:.4f}%")
print(f"  F1 Score          : {f1*100:.4f}%")
print(f"  AUC-ROC           : {auc*100:.4f}%")
print(f"  Avg Precision     : {ap*100:.4f}%")
print(f"  False Positive %  : {cm[0,1]/(cm[0,0]+cm[0,1])*100:.2f}%")
print(f"  False Negative %  : {cm[1,0]/(cm[1,0]+cm[1,1])*100:.2f}%")
print(f"\n{classification_report(y_test, y_pred, target_names=['Legitimate','Phishing'])}")


# ─── Threshold Analysis ────────────────────────────────────────────────────────
section("Threshold Sensitivity Analysis")
thresholds = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
print(f"  {'Threshold':>10}  {'Accuracy':>10}  {'Precision':>10}  {'Recall':>10}  {'F1':>10}")
for t in thresholds:
    yp = (y_proba >= t).astype(int)
    print(f"  {t:>10.1f}  "
          f"{accuracy_score(y_test, yp)*100:>9.2f}%  "
          f"{precision_score(y_test, yp)*100:>9.2f}%  "
          f"{recall_score(y_test, yp)*100:>9.2f}%  "
          f"{f1_score(y_test, yp)*100:>9.2f}%")


# ─── Plots ─────────────────────────────────────────────────────────────────────
section("Generating Evaluation Plots")

# ROC Curve
fpr_v, tpr_v, _ = roc_curve(y_test, y_proba)
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

axes[0].plot(fpr_v, tpr_v, color="#3b82f6", lw=2, label=f"XGBoost AUC={auc:.4f}")
axes[0].plot([0,1],[0,1],"k--",alpha=0.4, label="Random")
axes[0].fill_between(fpr_v, tpr_v, alpha=0.08, color="#3b82f6")
axes[0].set(title="ROC Curve", xlabel="FPR", ylabel="TPR")
axes[0].legend(); axes[0].grid(alpha=0.3)

# Precision-Recall
prec_c, rec_c, _ = precision_recall_curve(y_test, y_proba)
axes[1].plot(rec_c, prec_c, color="#22c55e", lw=2, label=f"AP={ap:.4f}")
axes[1].fill_between(rec_c, prec_c, alpha=0.08, color="#22c55e")
axes[1].set(title="Precision-Recall Curve", xlabel="Recall", ylabel="Precision")
axes[1].legend(); axes[1].grid(alpha=0.3)

plt.suptitle("PhishGuard — XGBoost Evaluation", fontsize=14, y=1.02)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "roc_pr_curves.png"), dpi=150, bbox_inches="tight")
plt.close()
print("[+] Saved: roc_pr_curves.png")

# Confusion Matrix styled
fig, ax = plt.subplots(figsize=(7,5))
sns.heatmap(cm, annot=True, fmt=",d", cmap="RdYlGn",
            xticklabels=["Legitimate","Phishing"],
            yticklabels=["Legitimate","Phishing"], ax=ax,
            annot_kws={"size": 14, "weight": "bold"})
ax.set(title="Confusion Matrix — PhishGuard", xlabel="Predicted", ylabel="Actual")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "confusion_matrix_eval.png"), dpi=150, bbox_inches="tight")
plt.close()
print("[+] Saved: confusion_matrix_eval.png")


# ─── SHAP Analysis ─────────────────────────────────────────────────────────────
section("SHAP Global Feature Analysis")
X_shap = X_test.sample(500, random_state=42)
explainer_shap = shap.TreeExplainer(model)
shap_vals      = explainer_shap(X_shap)

# SHAP Summary Beeswarm
plt.figure(figsize=(12, 8))
shap.summary_plot(shap_vals, X_shap, show=False, max_display=20)
plt.title("SHAP Feature Impact — PhishGuard (n=500 test samples)", fontsize=13)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "shap_summary.png"), dpi=150, bbox_inches="tight")
plt.close()
print("[+] Saved: shap_summary.png")

# SHAP Bar Summary
plt.figure(figsize=(10, 7))
shap.summary_plot(shap_vals, X_shap, plot_type="bar", show=False, max_display=20)
plt.title("SHAP Mean |SHAP| — Top Feature Importance", fontsize=13)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "shap_bar.png"), dpi=150, bbox_inches="tight")
plt.close()
print("[+] Saved: shap_bar.png")


# ─── Test Single Prediction Explanation ───────────────────────────────────────
section("Sample Prediction + Explanation Test")
from explainer import PhishGuardExplainer

pg_explainer = PhishGuardExplainer(model, feature_names)
test_sample  = X_test.iloc[[0]]
prob         = float(model.predict_proba(test_sample)[0, 1])
label        = "PHISHING" if prob >= 0.5 else "LEGITIMATE"

print(f"\n  Risk Score : {prob:.4f}")
print(f"  Label      : {label}")

explanation = pg_explainer.explain(test_sample, top_n=5)
print("\n  Top Reasons:")
for r in explanation["top_reasons"]:
    direction_icon = "🔴" if r["direction"] == "phishing" else "🟢"
    print(f"    {direction_icon} [{r['impact']:6}] {r['feature']}: {r['message']}")

print(f"\n[✓] Evaluation complete. All plots in: {PLOTS_DIR}")
