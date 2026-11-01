"""
PhishGuard — Realistic Model Retrain
======================================
Why the previous model was unrealistically accurate (99.96%):
  - 14 features had |correlation| >= 0.40 with the label
  - Features like HasSocialNet (0.78), HasCopyrightInfo (0.74),
    HasDescription (0.69) are DATASET-SPECIFIC web-scraping artifacts
    that may not generalize to live phishing pages in the wild.
  - These are rendered page properties, not stable URL signals.

Strategy for realistic model:
  1. REMOVE high-correlation rendered-page features (corr >= 0.40)
  2. KEEP only URL-structural + mild content features
  3. Add feature NOISE to prevent overfitting to dataset quirks
  4. Use STRICTER regularization (lower max_depth, higher min_child_weight)
  5. Evaluate on 60/20/20 train/val/test split (not just 80/20)
  6. Report per-threshold metrics, confusion matrix, and SHAP

Dropped high-sep features:
  HasSocialNet, HasCopyrightInfo, HasDescription, DomainTitleMatchScore,
  HasSubmitButton, IsResponsive, URLTitleMatchScore, SpacialCharRatioInURL,
  HasHiddenFields, HasFavicon, URLCharProb, CharContinuationRate,
  HasTitle, DegitRatioInURL
"""

import sys, os, time, json, joblib, warnings
sys.stdout.reconfigure(encoding="utf-8")
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
    roc_curve, precision_recall_curve, average_precision_score,
    matthews_corrcoef
)
from xgboost import XGBClassifier

# ─── Paths ─────────────────────────────────────────────────────────────────────
DATASET    = r"C:\Users\hi\Desktop\Cyber\phiusiil+phishing+url+dataset\PhiUSIIL_Phishing_URL_Dataset.csv"
MODELS_DIR = r"C:\Users\hi\Desktop\Cyber\phishing-detector\backend\ml\models"
PLOTS_DIR  = r"C:\Users\hi\Desktop\Cyber\phishing-detector\backend\ml\plots"
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(PLOTS_DIR,  exist_ok=True)

# ─── Realistic Feature Set ─────────────────────────────────────────────────────
# Removed: URLSimilarityIndex (constant=100 for phishing, pure leak)
#          IsHTTPS (constant=1 for all phishing in this dataset)
#          14 high-corr rendered-page features (dataset-specific artifacts)
FEATURES = [
    # --- URL structural features (always extractable) ---
    "URLLength",           # corr=0.23 — URL length
    "DomainLength",        # corr=0.28 — Domain name length
    "IsDomainIP",          # corr=0.06 — IP-based domain
    "TLDLength",           # corr=0.08 — TLD length
    "TLDLegitimateProb",   # corr=0.10 — TLD legitimacy score
    "NoOfSubDomain",       # corr=0.01 — Number of subdomains
    "NoOfLettersInURL",    # corr=0.26 — Letter count in URL
    "LetterRatioInURL",    # corr=0.37 — Letter ratio
    "NoOfDegitsInURL",     # corr=0.18 — Digit count
    "NoOfEqualsInURL",     # corr=0.08 — '=' signs
    "NoOfQMarkInURL",      # corr=0.18 — '?' signs
    "NoOfAmpersandInURL",  # corr=0.03 — '&' signs
    "NoOfOtherSpecialCharsInURL",  # corr=0.36 — special chars
    "TLD_encoded",         # corr=0.04 — encoded TLD category

    # --- Obfuscation signals ---
    "HasObfuscation",      # corr=0.05
    "NoOfObfuscatedChar",  # corr=0.02
    "ObfuscationRatio",    # corr=0.04

    # --- Page content (mild correlation only) ---
    "NoOfURLRedirect",     # corr=0.05
    "NoOfSelfRedirect",    # corr=0.08
    "NoOfPopup",           # corr=0.05
    "NoOfiFrame",          # corr=0.23
    "HasExternalFormSubmit", # corr=0.17
    "HasPasswordField",    # corr=0.14
    "Bank",                # corr=0.19
    "Pay",                 # corr=0.36
    "Crypto",              # corr=0.10
    "NoOfImage",           # corr=0.27
    "NoOfCSS",             # corr=0.07
    "NoOfJS",              # corr=0.37
    "NoOfSelfRef",         # corr=0.32
    "NoOfEmptyRef",        # corr=0.11
    "NoOfExternalRef",     # corr=0.26
    "LineOfCode",          # corr=0.27
    "LargestLineLength",   # corr=0.04
    "Robots",              # corr=0.39
]

NUM_FEATURES = len(FEATURES)


def section(title):
    print(f"\n{'='*65}")
    print(f"  {title}")
    print(f"{'='*65}")


# ─── 1. Load & Prepare ─────────────────────────────────────────────────────────
section("STEP 1 — Loading & Preparing Data")
df = pd.read_csv(DATASET, encoding="utf-8-sig")
tld_encoder = LabelEncoder()
df["TLD_encoded"] = tld_encoder.fit_transform(df["TLD"].astype(str))

y = df["label"].astype(int)
X = df[[f for f in FEATURES if f in df.columns]].copy()

print(f"  Dataset rows    : {len(X):,}")
print(f"  Features used   : {X.shape[1]}")
print(f"  Phishing (1)    : {(y==1).sum():,}  ({(y==1).mean()*100:.1f}%)")
print(f"  Legitimate (0)  : {(y==0).sum():,}  ({(y==0).mean()*100:.1f}%)")


# ─── 2. Add Gaussian noise to continuous features ──────────────────────────────
section("STEP 2 — Adding Noise (simulate real-world variance)")
NOISE_SCALE = 0.03   # 3% Gaussian noise on continuous cols
rng = np.random.RandomState(42)

continuous = X.select_dtypes(include=[float]).columns.tolist()
for col in continuous:
    std = X[col].std()
    if std > 0:
        X[col] = X[col] + rng.normal(0, NOISE_SCALE * std, size=len(X))

print(f"  Applied 3% Gaussian noise to {len(continuous)} continuous features")
print(f"  This simulates measurement variance in real-world URLs")


# ─── 3. 60 / 20 / 20 Split ─────────────────────────────────────────────────────
section("STEP 3 — 60 / 20 / 20 Train / Validation / Test Split")
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.40, random_state=42, stratify=y
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
)
print(f"  Train : {len(X_train):>7,} rows  ({len(X_train)/len(X)*100:.1f}%)")
print(f"  Val   : {len(X_val):>7,} rows  ({len(X_val)/len(X)*100:.1f}%)")
print(f"  Test  : {len(X_test):>7,} rows  ({len(X_test)/len(X)*100:.1f}%)")


# ─── 4. Train — Conservative XGBoost ──────────────────────────────────────────
section("STEP 4 — Training Conservative XGBoost")
print("  Hyperparameters designed to prevent overfitting:")
print("    max_depth=4 (down from 6)")
print("    n_estimators=200 (down from 300)")
print("    min_child_weight=20 (up from 5)")
print("    subsample=0.7, colsample_bytree=0.6")
print("    reg_alpha=1.0, reg_lambda=5.0 (strong L1+L2)")
print()

model = XGBClassifier(
    n_estimators        = 200,
    max_depth           = 4,          # shallower trees — less overfit
    learning_rate       = 0.05,       # slower learning
    subsample           = 0.7,        # row sampling
    colsample_bytree    = 0.6,        # feature sampling per tree
    min_child_weight    = 20,         # require more samples per leaf
    gamma               = 1.0,        # minimum split gain
    reg_alpha           = 1.0,        # L1 regularization
    reg_lambda          = 5.0,        # L2 regularization
    scale_pos_weight    = (y_train==0).sum() / (y_train==1).sum(),
    use_label_encoder   = False,
    eval_metric         = "logloss",
    random_state        = 42,
    n_jobs              = -1,
    verbosity           = 0,
    early_stopping_rounds = 15,
)

t0 = time.time()
model.fit(
    X_train, y_train,
    eval_set    = [(X_val, y_val)],
    verbose     = False,
)
train_time = time.time() - t0
best_iter  = model.best_iteration
print(f"  Training time   : {train_time:.1f}s")
print(f"  Best iteration  : {best_iter} (early stopped from 200)")


# ─── 5. Validation Metrics ─────────────────────────────────────────────────────
section("STEP 5 — Validation Set Metrics")
yv_pred  = model.predict(X_val)
yv_proba = model.predict_proba(X_val)[:, 1]
print(f"  Val Accuracy    : {accuracy_score(y_val, yv_pred)*100:.4f}%")
print(f"  Val AUC-ROC     : {roc_auc_score(y_val, yv_proba)*100:.4f}%")
print(f"  Val F1          : {f1_score(y_val, yv_pred)*100:.4f}%")


# ─── 6. Test Set Metrics (FINAL — unseen data) ────────────────────────────────
section("STEP 6 — TEST SET RESULTS (Final Unseen Evaluation)")
y_pred  = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec  = recall_score(y_test, y_pred)
f1   = f1_score(y_test, y_pred)
auc  = roc_auc_score(y_test, y_proba)
ap   = average_precision_score(y_test, y_proba)
mcc  = matthews_corrcoef(y_test, y_pred)
cm   = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()

print(f"\n  {'Metric':<28} {'Value':>10}")
print(f"  {'-'*40}")
print(f"  {'Accuracy':<28} {acc*100:>9.4f}%")
print(f"  {'Precision':<28} {prec*100:>9.4f}%")
print(f"  {'Recall (Sensitivity)':<28} {rec*100:>9.4f}%")
print(f"  {'Specificity':<28} {tn/(tn+fp)*100:>9.4f}%")
print(f"  {'F1 Score':<28} {f1*100:>9.4f}%")
print(f"  {'AUC-ROC':<28} {auc*100:>9.4f}%")
print(f"  {'Avg Precision (PR-AUC)':<28} {ap*100:>9.4f}%")
print(f"  {'Matthews Corr Coef':<28} {mcc:>10.4f}")
print(f"\n  {'False Positive Rate':<28} {fp/(tn+fp)*100:>9.2f}%")
print(f"  {'False Negative Rate':<28} {fn/(fn+tp)*100:>9.2f}%")
print(f"\n  Confusion Matrix (Test Set):")
print(f"  {'':15}  Predicted Legit  Predicted Phish")
print(f"  {'Actual Legit':15}  {tn:>15,}  {fp:>15,}")
print(f"  {'Actual Phish':15}  {fn:>15,}  {tp:>15,}")
print(f"\n  Total test samples: {len(y_test):,}")
print(f"  Correctly classified: {tp+tn:,}")
print(f"  Misclassified: {fp+fn:,}")
print(f"\n{classification_report(y_test, y_pred, target_names=['Legitimate','Phishing'])}")


# ─── 7. Cross-Validation ──────────────────────────────────────────────────────
section("STEP 7 — 5-Fold Stratified Cross-Validation (Full Dataset)")
cv_model = XGBClassifier(
    n_estimators=200, max_depth=4, learning_rate=0.05,
    subsample=0.7, colsample_bytree=0.6, min_child_weight=20,
    gamma=1.0, reg_alpha=1.0, reg_lambda=5.0,
    use_label_encoder=False, eval_metric="logloss",
    random_state=42, n_jobs=-1, verbosity=0,
)
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

cv_acc  = cross_val_score(cv_model, X, y, cv=skf, scoring="accuracy",  n_jobs=-1)
cv_f1   = cross_val_score(cv_model, X, y, cv=skf, scoring="f1",        n_jobs=-1)
cv_auc  = cross_val_score(cv_model, X, y, cv=skf, scoring="roc_auc",   n_jobs=-1)

print(f"\n  {'Metric':<15}  {'Fold 1':>8}  {'Fold 2':>8}  {'Fold 3':>8}  {'Fold 4':>8}  {'Fold 5':>8}  {'Mean':>8}  {'Std':>8}")
print(f"  {'-'*85}")
print(f"  {'Accuracy':<15}  " + "  ".join(f"{v*100:>7.3f}%" for v in cv_acc) + f"  {cv_acc.mean()*100:>7.3f}%  {cv_acc.std()*100:>7.3f}%")
print(f"  {'F1 Score':<15}  " + "  ".join(f"{v*100:>7.3f}%" for v in cv_f1)  + f"  {cv_f1.mean()*100:>7.3f}%  {cv_f1.std()*100:>7.3f}%")
print(f"  {'AUC-ROC':<15}  " + "  ".join(f"{v*100:>7.3f}%" for v in cv_auc) + f"  {cv_auc.mean()*100:>7.3f}%  {cv_auc.std()*100:>7.3f}%")


# ─── 8. Threshold Sensitivity ─────────────────────────────────────────────────
section("STEP 8 — Threshold Sensitivity Analysis")
print(f"\n  {'Threshold':>10}  {'Accuracy':>10}  {'Precision':>10}  {'Recall':>10}  {'F1':>10}  {'FPR':>8}  {'FNR':>8}")
print(f"  {'-'*75}")
for t in [0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]:
    yp  = (y_proba >= t).astype(int)
    c   = confusion_matrix(y_test, yp).ravel()
    tn_, fp_, fn_, tp_ = c[0], c[1], c[2], c[3]
    fpr_ = fp_/(tn_+fp_) if (tn_+fp_) > 0 else 0
    fnr_ = fn_/(fn_+tp_) if (fn_+tp_) > 0 else 0
    print(f"  {t:>10.2f}  "
          f"{accuracy_score(y_test,yp)*100:>9.2f}%  "
          f"{precision_score(y_test,yp,zero_division=0)*100:>9.2f}%  "
          f"{recall_score(y_test,yp,zero_division=0)*100:>9.2f}%  "
          f"{f1_score(y_test,yp,zero_division=0)*100:>9.2f}%  "
          f"{fpr_*100:>7.2f}%  "
          f"{fnr_*100:>7.2f}%")


# ─── 9. Save Model Artifacts ──────────────────────────────────────────────────
section("STEP 9 — Saving Artifacts")
joblib.dump(model,                  os.path.join(MODELS_DIR, "xgboost_model.pkl"))
joblib.dump(tld_encoder,            os.path.join(MODELS_DIR, "tld_encoder.pkl"))
joblib.dump(X.columns.tolist(),     os.path.join(MODELS_DIR, "feature_names.pkl"))

metrics = {
    "model":               "XGBoostClassifier (conservative)",
    "num_features":        int(X.shape[1]),
    "train_samples":       int(len(X_train)),
    "val_samples":         int(len(X_val)),
    "test_samples":        int(len(X_test)),
    "noise_applied":       "3% Gaussian on continuous features",
    "split":               "60/20/20 train/val/test",
    "accuracy":            round(acc, 6),
    "precision":           round(prec, 6),
    "recall":              round(rec, 6),
    "f1_score":            round(f1, 6),
    "auc_roc":             round(auc, 6),
    "avg_precision":       round(ap, 6),
    "matthews_corrcoef":   round(mcc, 6),
    "false_positive_rate": round(fp/(tn+fp), 6),
    "false_negative_rate": round(fn/(fn+tp), 6),
    "cv_accuracy_mean":    round(float(cv_acc.mean()), 6),
    "cv_f1_mean":          round(float(cv_f1.mean()), 6),
    "cv_auc_mean":         round(float(cv_auc.mean()), 6),
    "best_iteration":      int(best_iter),
    "training_time_s":     round(train_time, 2),
    "dropped_features": [
        "URLSimilarityIndex","IsHTTPS",          # constant in phishing class
        "HasSocialNet","HasCopyrightInfo",        # corr >= 0.70
        "HasDescription","DomainTitleMatchScore", # corr >= 0.58
        "HasSubmitButton","IsResponsive",         # corr >= 0.54
        "URLTitleMatchScore","SpacialCharRatioInURL",
        "HasHiddenFields","HasFavicon",
        "URLCharProb","CharContinuationRate",
        "HasTitle","DegitRatioInURL"
    ]
}
with open(os.path.join(MODELS_DIR, "metrics.json"), "w") as f:
    json.dump(metrics, f, indent=2)
print("  [+] Saved: xgboost_model.pkl")
print("  [+] Saved: tld_encoder.pkl")
print("  [+] Saved: feature_names.pkl")
print("  [+] Saved: metrics.json")


# ─── 10. Generate Plots ───────────────────────────────────────────────────────
section("STEP 10 — Generating Evaluation Plots")

# -- Confusion Matrix
fig, ax = plt.subplots(figsize=(7, 5))
sns.heatmap([[tn, fp],[fn, tp]], annot=True, fmt=",d", cmap="Blues",
            xticklabels=["Predicted Legit","Predicted Phish"],
            yticklabels=["Actual Legit","Actual Phish"],
            ax=ax, annot_kws={"size":14, "weight":"bold"})
ax.set_title(f"Confusion Matrix — PhishGuard Realistic Model\n"
             f"Accuracy={acc*100:.2f}%  FPR={fp/(tn+fp)*100:.2f}%  FNR={fn/(fn+tp)*100:.2f}%",
             fontsize=12, pad=12)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "confusion_matrix.png"), dpi=150, bbox_inches="tight")
plt.close()
print("  [+] Saved: confusion_matrix.png")

# -- ROC + PR side by side
fpr_v, tpr_v, _  = roc_curve(y_test, y_proba)
prec_c, rec_c, _ = precision_recall_curve(y_test, y_proba)
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

axes[0].plot(fpr_v, tpr_v, color="#3b82f6", lw=2, label=f"AUC={auc*100:.3f}%")
axes[0].plot([0,1],[0,1],"k--", alpha=0.4, label="Random")
axes[0].fill_between(fpr_v, tpr_v, alpha=0.08, color="#3b82f6")
axes[0].set(title="ROC Curve", xlabel="False Positive Rate", ylabel="True Positive Rate")
axes[0].legend(fontsize=11); axes[0].grid(alpha=0.3)

axes[1].plot(rec_c, prec_c, color="#22c55e", lw=2, label=f"AP={ap*100:.3f}%")
axes[1].fill_between(rec_c, prec_c, alpha=0.08, color="#22c55e")
axes[1].set(title="Precision-Recall Curve", xlabel="Recall", ylabel="Precision")
axes[1].legend(fontsize=11); axes[1].grid(alpha=0.3)

fig.suptitle("PhishGuard — Realistic XGBoost Model Evaluation", fontsize=14, y=1.01)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "roc_pr_curves.png"), dpi=150, bbox_inches="tight")
plt.close()
print("  [+] Saved: roc_pr_curves.png")

# -- Feature Importance
imp = pd.Series(model.feature_importances_, index=X.columns).nlargest(20).sort_values()
fig, ax = plt.subplots(figsize=(10, 7))
colors = ["#ef4444" if v > imp.quantile(0.75) else
          "#f59e0b" if v > imp.quantile(0.50) else "#3b82f6"
          for v in imp.values]
imp.plot(kind="barh", ax=ax, color=colors)
ax.set_xlabel("Feature Importance (Gain)", fontsize=12)
ax.set_title("Top 20 Feature Importances — PhishGuard Realistic Model", fontsize=12, pad=12)
ax.grid(axis="x", alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "feature_importance.png"), dpi=150, bbox_inches="tight")
plt.close()
print("  [+] Saved: feature_importance.png")

# -- Cross-Validation comparison bar chart
cv_metrics = {"Accuracy": cv_acc*100, "F1 Score": cv_f1*100, "AUC-ROC": cv_auc*100}
fig, ax = plt.subplots(figsize=(9, 5))
positions = np.arange(len(cv_metrics))
colors_cv = ["#3b82f6", "#22c55e", "#f59e0b"]
for i, (name, scores) in enumerate(cv_metrics.items()):
    ax.bar(i, scores.mean(), color=colors_cv[i], alpha=0.8, label=f"{name}: {scores.mean():.2f}%")
    ax.errorbar(i, scores.mean(), yerr=scores.std(), fmt="none",
                color="black", capsize=6, linewidth=2)
    for j, s in enumerate(scores):
        ax.scatter(i + (j-2)*0.08, s, color="white", edgecolors=colors_cv[i], s=40, zorder=5)
ax.set_xticks(positions)
ax.set_xticklabels(cv_metrics.keys(), fontsize=12)
ax.set_ylabel("Score (%)", fontsize=12)
ax.set_title("5-Fold Cross-Validation Results — PhishGuard Realistic Model", fontsize=12, pad=12)
ax.set_ylim(min(cv_auc.min(), cv_acc.min(), cv_f1.min())*100 - 2, 100.5)
ax.legend(fontsize=11); ax.grid(axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "cross_validation.png"), dpi=150, bbox_inches="tight")
plt.close()
print("  [+] Saved: cross_validation.png")

# -- SHAP
import shap
section("STEP 11 — SHAP Global Explanations")
X_shap = X_test.sample(500, random_state=42)
shap_exp = shap.TreeExplainer(model)
shap_vals = shap_exp(X_shap)

plt.figure(figsize=(12, 8))
shap.summary_plot(shap_vals, X_shap, show=False, max_display=20)
plt.title("SHAP Feature Impact — PhishGuard Realistic Model (n=500)", fontsize=12)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "shap_summary.png"), dpi=150, bbox_inches="tight")
plt.close()
print("  [+] Saved: shap_summary.png")

plt.figure(figsize=(10, 7))
shap.summary_plot(shap_vals, X_shap, plot_type="bar", show=False, max_display=20)
plt.title("SHAP Mean |Value| — Feature Importance", fontsize=12)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "shap_bar.png"), dpi=150, bbox_inches="tight")
plt.close()
print("  [+] Saved: shap_bar.png")


# ─── FINAL SUMMARY ────────────────────────────────────────────────────────────
section("FINAL SUMMARY")
print(f"""
  Model          : XGBoost (Conservative — Realistic)
  Features       : {X.shape[1]} (removed 16 leaky/high-sep features)
  Noise Applied  : 3% Gaussian on continuous features
  Split          : 60/20/20 train/val/test

  ┌─────────────────────────────────────────────────┐
  │              TEST SET RESULTS                   │
  ├─────────────────────────────────────────────────┤
  │  Accuracy          : {acc*100:>8.4f}%               │
  │  Precision         : {prec*100:>8.4f}%               │
  │  Recall            : {rec*100:>8.4f}%               │
  │  F1 Score          : {f1*100:>8.4f}%               │
  │  AUC-ROC           : {auc*100:>8.4f}%               │
  │  False Positive %  : {fp/(tn+fp)*100:>8.2f}%               │
  │  False Negative %  : {fn/(fn+tp)*100:>8.2f}%               │
  │  Matthews CC       : {mcc:>8.4f}                │
  ├─────────────────────────────────────────────────┤
  │  CV Accuracy (mean): {cv_acc.mean()*100:>8.4f}%               │
  │  CV F1 (mean)      : {cv_f1.mean()*100:>8.4f}%               │
  │  CV AUC (mean)     : {cv_auc.mean()*100:>8.4f}%               │
  └─────────────────────────────────────────────────┘
""")
print(f"  All plots saved to : {PLOTS_DIR}")
print(f"  All models saved to: {MODELS_DIR}")
