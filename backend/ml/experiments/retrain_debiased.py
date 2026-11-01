"""
PhishGuard — Production Robust Retrain (De-Biased WWW & Apex Domains)
====================================================================
Fixes the synthetic selection bias in PhiUSIIL where 100% of legitimate
websites contained 'www.', causing apex domains (github.com, stackoverflow.com)
to be falsely flagged as phishing.

Features: 12 clean URL structural features.
Dataset Augmentation: Balanced representation of both 'www.' and apex domains.
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
DATASET    = os.path.join(BASE_DIR, "..", "..", "..", "phiusiil+phishing+url+dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")

print("[+] Loading PhiUSIIL dataset...")
df = pd.read_csv(DATASET, encoding="utf-8-sig")

# 1 = Phishing, 0 = Legitimate
df["is_phishing"] = (df["label"] == 0).astype(int)

# TLD Encoder
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

# De-bias: 50% of legitimate sites in PhiUSIIL had synthetic 'www.' stripped to teach apex domains
np.random.seed(42)
mask = (df["is_phishing"] == 0) & (np.random.rand(len(df)) < 0.5)
df.loc[mask, "URLLength"] = np.maximum(5, df.loc[mask, "URLLength"] - 4)
df.loc[mask, "DomainLength"] = np.maximum(3, df.loc[mask, "DomainLength"] - 4)
df.loc[mask, "NoOfSubDomain"] = np.maximum(0, df.loc[mask, "NoOfSubDomain"] - 1)

X = df[ROBUST_12_FEATURES]
y = df["is_phishing"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

print(f"[+] Training de-biased XGBoost model with {len(ROBUST_12_FEATURES)} features...")
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
    "model": "XGBoost (De-Biased 12 Features)",
    "num_features": len(ROBUST_12_FEATURES),
    "features": ROBUST_12_FEATURES,
    "accuracy": round(float(acc), 4),
    "precision": round(float(prec), 4),
    "recall": round(float(rec), 4),
    "f1_score": round(float(f1), 4),
    "auc_roc": round(float(auc), 4),
}
with open(os.path.join(MODELS_DIR, "metrics.json"), "w") as f:
    json.dump(metrics_data, f, indent=2)

print("[+] De-biased model artifacts saved successfully.")
