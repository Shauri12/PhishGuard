"""
PhishGuard — Final Lean 12-Feature Model Training
================================================
Train and save the 12 robust URL-structural features model.
Eliminates all DOM scraping and ratio skew.
"""

import sys
import os
import json
import joblib
import warnings
warnings.filterwarnings("ignore")
sys.stdout.reconfigure(encoding="utf-8")

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from xgboost import XGBClassifier

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATASET    = os.path.join(
    BASE_DIR, "..", "..", "..",
    "phiusiil+phishing+url+dataset",
    "PhiUSIIL_Phishing_URL_Dataset.csv"
)

print("[+] Loading dataset...")
df = pd.read_csv(DATASET, encoding="utf-8-sig")

# 1 = Phishing (threat), 0 = Legitimate (safe)
df["is_phishing"] = (df["label"] == 0).astype(int)

# Encode TLD
tld_encoder = LabelEncoder()
df["TLD_encoded"] = tld_encoder.fit_transform(df["TLD"].astype(str))

ROBUST_12_FEATURES = [
    "URLLength",
    "DomainLength",
    "NoOfSubDomain",
    "IsDomainIP",
    "TLDLength",
    "TLDLegitimateProb",
    "TLD_encoded",
    "NoOfDegitsInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "HasObfuscation",
]

X = df[ROBUST_12_FEATURES]
y = df["is_phishing"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

print(f"[+] Training lean XGBoost model with {len(ROBUST_12_FEATURES)} features...")
model = XGBClassifier(
    n_estimators=120,
    max_depth=4,
    learning_rate=0.08,
    subsample=0.8,
    colsample_bytree=0.8,
    min_child_weight=20,
    reg_alpha=1.0,
    reg_lambda=3.0,
    use_label_encoder=False,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

preds = model.predict(X_test)
proba = model.predict_proba(X_test)[:, 1]

acc  = accuracy_score(y_test, preds)
prec = precision_score(y_test, preds)
rec  = recall_score(y_test, preds)
f1   = f1_score(y_test, preds)
auc  = roc_auc_score(y_test, proba)
cm   = confusion_matrix(y_test, preds)

print("\n" + "="*50)
print(f"Accuracy  : {acc*100:.2f}%")
print(f"Precision : {prec*100:.2f}%")
print(f"Recall    : {rec*100:.2f}%")
print(f"F1 Score  : {f1*100:.2f}%")
print(f"AUC-ROC   : {auc*100:.2f}%")
print("="*50)

# Save artifacts
joblib.dump(model, os.path.join(MODELS_DIR, "xgboost_model.pkl"))
joblib.dump(ROBUST_12_FEATURES, os.path.join(MODELS_DIR, "feature_names.pkl"))
joblib.dump(tld_encoder, os.path.join(MODELS_DIR, "tld_encoder.pkl"))

metrics_data = {
    "model": "XGBoost (Lean 12 Features)",
    "num_features": len(ROBUST_12_FEATURES),
    "features": ROBUST_12_FEATURES,
    "train_samples": len(X_train),
    "test_samples": len(X_test),
    "accuracy": round(float(acc), 4),
    "precision": round(float(prec), 4),
    "recall": round(float(rec), 4),
    "f1_score": round(float(f1), 4),
    "auc_roc": round(float(auc), 4),
}
with open(os.path.join(MODELS_DIR, "metrics.json"), "w") as f:
    json.dump(metrics_data, f, indent=2)

print("[+] Clean 12-feature artifacts saved.")
