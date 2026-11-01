"""
PhishGuard — Clean Retrain (leaky features removed)
Dropped: URLSimilarityIndex (constant=100 for ALL phishing rows)
         IsHTTPS (constant=1 for ALL phishing rows in this dataset)
These are dataset-specific artifacts, not generalizable real-world signals.
"""
import os, sys, time, json, joblib, warnings
warnings.filterwarnings("ignore")

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report, roc_curve
)
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

DATASET    = r"C:\Users\hi\Desktop\Cyber\phiusiil+phishing+url+dataset\PhiUSIIL_Phishing_URL_Dataset.csv"
MODELS_DIR = r"C:\Users\hi\Desktop\Cyber\phishing-detector\backend\ml\models"
PLOTS_DIR  = r"C:\Users\hi\Desktop\Cyber\phishing-detector\backend\ml\plots"
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(PLOTS_DIR,  exist_ok=True)

# Clean feature list — leaky features removed
FEATURES = [
    "URLLength","DomainLength","IsDomainIP",
    "CharContinuationRate","TLDLegitimateProb","URLCharProb","TLDLength",
    "NoOfSubDomain","HasObfuscation","NoOfObfuscatedChar","ObfuscationRatio",
    "NoOfLettersInURL","LetterRatioInURL","NoOfDegitsInURL","DegitRatioInURL",
    "NoOfEqualsInURL","NoOfQMarkInURL","NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL","SpacialCharRatioInURL",
    "LineOfCode","LargestLineLength","HasTitle","DomainTitleMatchScore",
    "URLTitleMatchScore","HasFavicon","Robots","IsResponsive",
    "NoOfURLRedirect","NoOfSelfRedirect","HasDescription","NoOfPopup",
    "NoOfiFrame","HasExternalFormSubmit","HasSocialNet","HasSubmitButton",
    "HasHiddenFields","HasPasswordField","Bank","Pay","Crypto",
    "HasCopyrightInfo","NoOfImage","NoOfCSS","NoOfJS","NoOfSelfRef",
    "NoOfEmptyRef","NoOfExternalRef","TLD_encoded",
]

print("[+] Loading dataset...")
df = pd.read_csv(DATASET, encoding="utf-8-sig")
tld_encoder = LabelEncoder()
df["TLD_encoded"] = tld_encoder.fit_transform(df["TLD"].astype(str))

y = df["label"].astype(int)
X = df[[f for f in FEATURES if f in df.columns]]
print(f"[+] Features: {X.shape[1]}  |  Rows: {X.shape[0]:,}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"[+] Train: {len(X_train):,}  |  Test: {len(X_test):,}")

model = XGBClassifier(
    n_estimators=300, max_depth=6, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8, min_child_weight=5,
    gamma=0.1, reg_alpha=0.1, reg_lambda=1.0,
    scale_pos_weight=(y_train==0).sum()/(y_train==1).sum(),
    use_label_encoder=False, eval_metric="logloss",
    random_state=42, n_jobs=-1, verbosity=0,
    early_stopping_rounds=20,
)

t0 = time.time()
model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)
elapsed = time.time() - t0
print(f"[+] Training time: {elapsed:.1f}s")

y_pred  = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec  = recall_score(y_test, y_pred)
f1   = f1_score(y_test, y_pred)
auc  = roc_auc_score(y_test, y_proba)
cm   = confusion_matrix(y_test, y_pred)

print(f"\n  Accuracy  : {acc*100:.4f}%")
print(f"  Precision : {prec*100:.4f}%")
print(f"  Recall    : {rec*100:.4f}%")
print(f"  F1 Score  : {f1*100:.4f}%")
print(f"  AUC-ROC   : {auc*100:.4f}%")
print(f"  FP Rate   : {cm[0,1]/(cm[0,0]+cm[0,1])*100:.2f}%")
print(f"  FN Rate   : {cm[1,0]/(cm[1,0]+cm[1,1])*100:.2f}%")
print(f"\n{classification_report(y_test, y_pred, target_names=['Legitimate','Phishing'])}")

print("[+] Running 5-fold cross-validation...")
cv_model = XGBClassifier(
    n_estimators=300, max_depth=6, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8,
    use_label_encoder=False, eval_metric="logloss",
    random_state=42, n_jobs=-1, verbosity=0,
)
cv_scores = cross_val_score(cv_model, X, y, cv=5, scoring="f1", n_jobs=-1)
print(f"  CV F1: {[f'{s:.4f}' for s in cv_scores]}")
print(f"  Mean: {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")

# Save
joblib.dump(model,                    os.path.join(MODELS_DIR, "xgboost_model.pkl"))
joblib.dump(tld_encoder,              os.path.join(MODELS_DIR, "tld_encoder.pkl"))
joblib.dump(X.columns.tolist(),       os.path.join(MODELS_DIR, "feature_names.pkl"))

metrics = {
    "accuracy": round(acc,6), "precision": round(prec,6),
    "recall": round(rec,6), "f1_score": round(f1,6),
    "auc_roc": round(auc,6),
    "cv_f1_mean": round(float(cv_scores.mean()),6),
    "cv_f1_std":  round(float(cv_scores.std()),6),
    "false_positive_rate": round(cm[0,1]/(cm[0,0]+cm[0,1]),6),
    "false_negative_rate": round(cm[1,0]/(cm[1,0]+cm[1,1]),6),
    "num_features": int(X.shape[1]),
    "dropped_leaky": ["URLSimilarityIndex","IsHTTPS"],
    "note": "Clean model — dataset-artifact features removed"
}
with open(os.path.join(MODELS_DIR, "metrics.json"), "w") as f:
    json.dump(metrics, f, indent=2)

print("[+] Model artifacts saved.")

# Feature importance plot
imp = pd.Series(model.feature_importances_, index=X.columns).nlargest(20).sort_values()
fig, ax = plt.subplots(figsize=(10,7))
colors = ["#ef4444" if v > imp.quantile(0.75) else "#3b82f6" for v in imp.values]
imp.plot(kind="barh", ax=ax, color=colors)
ax.set_xlabel("Feature Importance (Gain)", fontsize=13)
ax.set_title("Top 20 Features — PhishGuard XGBoost (Clean Model)", fontsize=13, pad=12)
ax.grid(axis="x", alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "feature_importance.png"), dpi=150, bbox_inches="tight")
plt.close()
print("[+] Saved: feature_importance.png")

# ROC curve
fpr_v, tpr_v, _ = roc_curve(y_test, y_proba)
fig, ax = plt.subplots(figsize=(7,5))
ax.plot(fpr_v, tpr_v, color="#3b82f6", lw=2, label=f"XGBoost (AUC={auc:.4f})")
ax.plot([0,1],[0,1],"k--",alpha=0.4,label="Random")
ax.fill_between(fpr_v, tpr_v, alpha=0.1, color="#3b82f6")
ax.set(title="ROC Curve — PhishGuard Clean Model", xlabel="FPR", ylabel="TPR")
ax.legend(); ax.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "roc_curve.png"), dpi=150, bbox_inches="tight")
plt.close()
print("[+] Saved: roc_curve.png")

# Confusion matrix
fig, ax = plt.subplots(figsize=(7,5))
sns.heatmap(cm, annot=True, fmt=",d", cmap="Blues",
    xticklabels=["Legitimate","Phishing"],
    yticklabels=["Legitimate","Phishing"], ax=ax,
    annot_kws={"size":14,"weight":"bold"})
ax.set(title="Confusion Matrix — PhishGuard Clean Model", xlabel="Predicted", ylabel="Actual")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "confusion_matrix.png"), dpi=150, bbox_inches="tight")
plt.close()
print("[+] Saved: confusion_matrix.png")
print("\n[DONE] Clean model ready.")
