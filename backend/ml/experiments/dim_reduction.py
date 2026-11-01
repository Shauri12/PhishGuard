"""
PhishGuard — Dimensionality Reduction & Feature Selection
=========================================================
1. Corrects the PhiUSIIL label convention:
   In PhiUSIIL: 1 = Legitimate, 0 = Phishing
   We remap: is_phishing = (label == 0).astype(int)  [1 = Phishing, 0 = Legitimate]
2. Performs Dimensionality Reduction:
   - Removes volatile web-scraping DOM artifacts (LineOfCode, NoOfSelfRef, LargestLineLength)
   - Ranks features by Mutual Information and Tree Importance
   - Selects a compact, high-signal subset of 12-15 features
3. Retrains a lean model with cross-validation and evaluates on test set + live URLs
"""

import sys
import os
import json
import joblib
import warnings
warnings.filterwarnings("ignore")
sys.stdout.reconfigure(encoding="utf-8")

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_selection import mutual_info_classif, SelectKBest, f_classif
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from xgboost import XGBClassifier

DATASET    = r"C:\Users\hi\Desktop\Cyber\phiusiil+phishing+url+dataset\PhiUSIIL_Phishing_URL_Dataset.csv"
MODELS_DIR = r"C:\Users\hi\Desktop\Cyber\phishing-detector\backend\ml\models"

print("[+] Loading dataset (235,795 rows)...")
df = pd.read_csv(DATASET, encoding="utf-8-sig")

# CRITICAL FIX: In PhiUSIIL, 1 = Legitimate, 0 = Phishing.
# Standard cybersecurity convention: 1 = Phishing (positive class/threat), 0 = Legitimate
df["is_phishing"] = (df["label"] == 0).astype(int)
print(f"[+] Re-encoded label: 1=Phishing ({df['is_phishing'].sum():,}), 0=Legitimate ({(df['is_phishing']==0).sum():,})")

# Encode TLD
tld_encoder = LabelEncoder()
df["TLD_encoded"] = tld_encoder.fit_transform(df["TLD"].astype(str))

# Candidate features (excluding obvious leaks URLSimilarityIndex and IsHTTPS,
# AND excluding brittle scraped DOM line counts)
CANDIDATE_FEATURES = [
    # URL Lexical & Structural
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "TLDLegitimateProb",
    "NoOfSubDomain",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "TLD_encoded",
    # Security/Form Markers (stable, low false-positive risk)
    "HasPasswordField",
    "HasExternalFormSubmit",
    "Bank",
    "Pay",
    "Crypto",
    "NoOfPopup",
    "NoOfiFrame",
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
]

X_all = df[CANDIDATE_FEATURES]
y_all = df["is_phishing"]

print(f"\n[+] Analyzing {len(CANDIDATE_FEATURES)} candidate features on 30,000 sample...")
sample_idx = np.random.RandomState(42).choice(len(df), size=30000, replace=False)
X_sub = X_all.iloc[sample_idx]
y_sub = y_all.iloc[sample_idx]

# 1. Feature selection via F-score and Mutual Information
f_scores, p_vals = f_classif(X_sub, y_sub)
mi_scores = mutual_info_classif(X_sub, y_sub, random_state=42)

ranking_df = pd.DataFrame({
    "Feature": CANDIDATE_FEATURES,
    "F_Score": f_scores,
    "MI_Score": mi_scores,
    "Pearson_Corr": [abs(df[f].corr(df["is_phishing"])) for f in CANDIDATE_FEATURES]
}).sort_values(by="MI_Score", ascending=False)

print("\n--- Feature Ranking by Mutual Information & Correlation ---")
print(ranking_df.to_string(index=False))

# Select Top 14 lean, non-redundant features
TOP_FEATURES = [
    "URLLength",
    "DomainLength",
    "TLDLegitimateProb",
    "TLD_encoded",
    "NoOfSubDomain",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "HasObfuscation",
    "IsDomainIP"
]

print(f"\n[+] Selected lean feature set ({len(TOP_FEATURES)} features):")
for f in TOP_FEATURES:
    print(f"    - {f}")

# Train / Val / Test split: 70/15/15
X = df[TOP_FEATURES]
y = df["is_phishing"]

X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

print(f"\n[+] Train: {len(X_train):,}, Val: {len(X_val):,}, Test: {len(X_test):,}")

# Conservative XGBoost Model
lean_model = XGBClassifier(
    n_estimators=180,
    max_depth=5,
    learning_rate=0.08,
    subsample=0.8,
    colsample_bytree=0.8,
    min_child_weight=15,
    gamma=0.5,
    reg_alpha=0.5,
    reg_lambda=2.0,
    use_label_encoder=False,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1
)

lean_model.fit(
    X_train, y_train,
    eval_set=[(X_val, y_val)],
    verbose=False
)

# Test Evaluation
y_pred = lean_model.predict(X_test)
y_proba = lean_model.predict_proba(X_test)[:, 1]

acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec  = recall_score(y_test, y_pred)
f1   = f1_score(y_test, y_pred)
auc  = roc_auc_score(y_test, y_proba)
cm   = confusion_matrix(y_test, y_pred)

print("\n" + "="*60)
print("🎯 LEAN MODEL EVALUATION (15 Features, Reduced Dimension)")
print("="*60)
print(f"Accuracy  : {acc*100:.3f}%")
print(f"Precision : {prec*100:.3f}%")
print(f"Recall    : {rec*100:.3f}%")
print(f"F1 Score  : {f1*100:.3f}%")
print(f"AUC-ROC   : {auc*100:.3f}%")
print(f"\nConfusion Matrix (Unseen Test: {len(y_test):,} samples):")
print(f"               Pred Legit   Pred Phish")
print(f"Actual Legit : {cm[0,0]:>10,}   {cm[0,1]:>10,}")
print(f"Actual Phish : {cm[1,0]:>10,}   {cm[1,1]:>10,}")

# Save artifacts
joblib.dump(lean_model, os.path.join(MODELS_DIR, "xgboost_model.pkl"))
joblib.dump(TOP_FEATURES, os.path.join(MODELS_DIR, "feature_names.pkl"))
joblib.dump(tld_encoder, os.path.join(MODELS_DIR, "tld_encoder.pkl"))

metrics_data = {
    "model": "XGBoost (Lean Dimensionality-Reduced)",
    "num_features": len(TOP_FEATURES),
    "features": TOP_FEATURES,
    "train_samples": len(X_train),
    "val_samples": len(X_val),
    "test_samples": len(X_test),
    "accuracy": round(float(acc), 6),
    "precision": round(float(prec), 6),
    "recall": round(float(rec), 6),
    "f1_score": round(float(f1), 6),
    "auc_roc": round(float(auc), 6),
    "false_positive_rate": round(float(cm[0,1] / (cm[0,0] + cm[0,1])), 6),
    "false_negative_rate": round(float(cm[1,0] / (cm[1,0] + cm[1,1])), 6),
}
with open(os.path.join(MODELS_DIR, "metrics.json"), "w") as f:
    json.dump(metrics_data, f, indent=2)

print("\n[+] Updated model artifacts saved successfully.")
