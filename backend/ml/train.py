"""
PhishGuard — XGBoost Model Training Script
===========================================
Trains an XGBoost classifier on the PhiUSIIL Phishing URL dataset.
Outputs:
  - models/xgboost_model.pkl   (trained model)
  - models/tld_encoder.pkl     (LabelEncoder for TLD)
  - models/feature_names.pkl   (ordered feature list)
  - models/training_report.txt (metrics summary)

Usage:
  python train.py
"""

import os
import sys
import time
import json
import joblib
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
    classification_report, roc_curve
)
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATASET     = os.path.join(BASE_DIR, "..", "..", "..", "phiusiil+phishing+url+dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")
MODELS_DIR  = os.path.join(BASE_DIR, "models")
PLOTS_DIR   = os.path.join(BASE_DIR, "plots")
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(PLOTS_DIR,  exist_ok=True)

# ─── Feature config ────────────────────────────────────────────────────────────
DROP_COLS = ["FILENAME", "URL", "Domain", "Title"]
TARGET    = "label"

# Clean feature list — URLSimilarityIndex & IsHTTPS excluded (dataset artifacts)
FEATURES = [
    "URLLength", "DomainLength", "IsDomainIP",
    "CharContinuationRate", "TLDLegitimateProb", "URLCharProb", "TLDLength",
    "NoOfSubDomain", "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
    "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL",
    "LineOfCode", "LargestLineLength", "HasTitle", "DomainTitleMatchScore",
    "URLTitleMatchScore", "HasFavicon", "Robots", "IsResponsive",
    "NoOfURLRedirect", "NoOfSelfRedirect", "HasDescription", "NoOfPopup",
    "NoOfiFrame", "HasExternalFormSubmit", "HasSocialNet", "HasSubmitButton",
    "HasHiddenFields", "HasPasswordField", "Bank", "Pay", "Crypto",
    "HasCopyrightInfo", "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef",
    "NoOfEmptyRef", "NoOfExternalRef", "TLD_encoded",
]


def banner(msg: str):
    width = 60
    print("\n" + "=" * width)
    print(f"  {msg}")
    print("=" * width)


# ─── 1. Load & Prepare ─────────────────────────────────────────────────────────
banner("STEP 1 — Loading Dataset")
print(f"[+] Dataset path: {DATASET}")
df = pd.read_csv(DATASET, encoding="utf-8-sig")
print(f"[+] Raw shape: {df.shape}")

# Encode TLD
tld_encoder = LabelEncoder()
df["TLD_encoded"] = tld_encoder.fit_transform(df["TLD"].astype(str))

# Drop non-feature columns
df.drop(columns=[c for c in DROP_COLS + ["TLD"] if c in df.columns], inplace=True)

y = df[TARGET].astype(int)
X = df[[f for f in FEATURES if f in df.columns]]

print(f"[+] Feature matrix: {X.shape}")
print(f"[+] Phishing (1): {(y==1).sum():,}  |  Legitimate (0): {(y==0).sum():,}")


# ─── 2. Train/Test Split ───────────────────────────────────────────────────────
banner("STEP 2 — Train/Test Split (80/20 Stratified)")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"[+] Train: {X_train.shape[0]:,} rows  |  Test: {X_test.shape[0]:,} rows")


# ─── 3. Train XGBoost ─────────────────────────────────────────────────────────
banner("STEP 3 — Training XGBoost Classifier")
model = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    min_child_weight=5,
    gamma=0.1,
    reg_alpha=0.1,
    reg_lambda=1.0,
    scale_pos_weight=(y_train == 0).sum() / (y_train == 1).sum(),
    use_label_encoder=False,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1,
    verbosity=1,
    early_stopping_rounds=20,
)

t0 = time.time()
model.fit(
    X_train, y_train,
    eval_set=[(X_test, y_test)],
    verbose=50,
)
train_time = time.time() - t0
print(f"\n[+] Training complete in {train_time:.1f}s")


# ─── 4. Evaluate ──────────────────────────────────────────────────────────────
banner("STEP 4 — Evaluation Metrics")
y_pred      = model.predict(X_test)
y_proba     = model.predict_proba(X_test)[:, 1]

acc       = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall    = recall_score(y_test, y_pred)
f1        = f1_score(y_test, y_pred)
auc       = roc_auc_score(y_test, y_proba)
cm        = confusion_matrix(y_test, y_pred)

print(f"\n  Accuracy   : {acc*100:.4f}%")
print(f"  Precision  : {precision*100:.4f}%")
print(f"  Recall     : {recall*100:.4f}%")
print(f"  F1 Score   : {f1*100:.4f}%")
print(f"  AUC-ROC    : {auc*100:.4f}%")
print(f"\n  Confusion Matrix:")
print(f"    TN={cm[0,0]:6,}  FP={cm[0,1]:6,}")
print(f"    FN={cm[1,0]:6,}  TP={cm[1,1]:6,}")
print(f"\n  False Positive Rate : {cm[0,1]/(cm[0,0]+cm[0,1])*100:.2f}%")
print(f"  False Negative Rate : {cm[1,0]/(cm[1,0]+cm[1,1])*100:.2f}%")
print(f"\n{classification_report(y_test, y_pred, target_names=['Legitimate','Phishing'])}")


# ─── 5. Cross-Validation ──────────────────────────────────────────────────────
banner("STEP 5 — 5-Fold Cross-Validation")
cv_model = XGBClassifier(
    n_estimators=300, max_depth=6, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8, min_child_weight=5,
    gamma=0.1, reg_alpha=0.1, reg_lambda=1.0,
    use_label_encoder=False, eval_metric="logloss",
    random_state=42, n_jobs=-1, verbosity=0,
)
cv_scores = cross_val_score(cv_model, X, y, cv=5, scoring="f1", n_jobs=-1)
print(f"  CV F1 scores: {[f'{s:.4f}' for s in cv_scores]}")
print(f"  Mean F1     : {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")


# ─── 6. Save Model & Artifacts ────────────────────────────────────────────────
banner("STEP 6 — Saving Model Artifacts")

joblib.dump(model,       os.path.join(MODELS_DIR, "xgboost_model.pkl"))
joblib.dump(tld_encoder, os.path.join(MODELS_DIR, "tld_encoder.pkl"))
joblib.dump(X.columns.tolist(), os.path.join(MODELS_DIR, "feature_names.pkl"))

print("[+] Saved: xgboost_model.pkl")
print("[+] Saved: tld_encoder.pkl")
print("[+] Saved: feature_names.pkl")

# Save metrics to JSON
metrics = {
    "accuracy":        round(acc, 6),
    "precision":       round(precision, 6),
    "recall":          round(recall, 6),
    "f1_score":        round(f1, 6),
    "auc_roc":         round(auc, 6),
    "cv_f1_mean":      round(float(cv_scores.mean()), 6),
    "cv_f1_std":       round(float(cv_scores.std()), 6),
    "false_positive_rate": round(cm[0,1]/(cm[0,0]+cm[0,1]), 6),
    "false_negative_rate": round(cm[1,0]/(cm[1,0]+cm[1,1]), 6),
    "train_samples":   int(X_train.shape[0]),
    "test_samples":    int(X_test.shape[0]),
    "num_features":    int(X.shape[1]),
    "training_time_s": round(train_time, 2),
}
with open(os.path.join(MODELS_DIR, "metrics.json"), "w") as f:
    json.dump(metrics, f, indent=2)
print("[+] Saved: metrics.json")


# ─── 7. Generate Plots ────────────────────────────────────────────────────────
banner("STEP 7 — Generating Evaluation Plots")

# -- Confusion Matrix
fig, ax = plt.subplots(figsize=(7, 5))
sns.heatmap(cm, annot=True, fmt=",d", cmap="Blues",
            xticklabels=["Legitimate", "Phishing"],
            yticklabels=["Legitimate", "Phishing"], ax=ax)
ax.set_xlabel("Predicted", fontsize=13)
ax.set_ylabel("Actual",    fontsize=13)
ax.set_title("Confusion Matrix — XGBoost PhishGuard", fontsize=14, pad=15)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "confusion_matrix.png"), dpi=150, bbox_inches="tight")
plt.close()
print("[+] Saved: plots/confusion_matrix.png")

# -- ROC Curve
fpr_vals, tpr_vals, _ = roc_curve(y_test, y_proba)
fig, ax = plt.subplots(figsize=(7, 5))
ax.plot(fpr_vals, tpr_vals, color="#3b82f6", lw=2, label=f"XGBoost (AUC = {auc:.4f})")
ax.plot([0, 1], [0, 1], "k--", lw=1.5, alpha=0.5, label="Random (AUC = 0.50)")
ax.fill_between(fpr_vals, tpr_vals, alpha=0.1, color="#3b82f6")
ax.set_xlabel("False Positive Rate", fontsize=13)
ax.set_ylabel("True Positive Rate",  fontsize=13)
ax.set_title("ROC Curve — XGBoost PhishGuard", fontsize=14, pad=15)
ax.legend(fontsize=12)
ax.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "roc_curve.png"), dpi=150, bbox_inches="tight")
plt.close()
print("[+] Saved: plots/roc_curve.png")

# -- Feature Importance (Top 20)
importance = pd.Series(model.feature_importances_, index=X.columns)
top20 = importance.nlargest(20).sort_values()
fig, ax = plt.subplots(figsize=(10, 7))
colors = ["#ef4444" if v > top20.quantile(0.75) else "#3b82f6" for v in top20.values]
top20.plot(kind="barh", ax=ax, color=colors)
ax.set_xlabel("Feature Importance (Gain)", fontsize=13)
ax.set_title("Top 20 Feature Importances — XGBoost PhishGuard", fontsize=14, pad=15)
ax.grid(axis="x", alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "feature_importance.png"), dpi=150, bbox_inches="tight")
plt.close()
print("[+] Saved: plots/feature_importance.png")


# ─── Done ─────────────────────────────────────────────────────────────────────
banner("TRAINING COMPLETE")
print(f"  Model accuracy  : {acc*100:.4f}%")
print(f"  AUC-ROC         : {auc*100:.4f}%")
print(f"  F1 Score        : {f1*100:.4f}%")
print(f"  All artifacts saved to: {MODELS_DIR}")
print(f"  All plots saved to    : {PLOTS_DIR}")
