"""
PhishGuard — Feature Separation Analysis
==========================================
Identifies features with extreme class separation that may not
generalize to real-world data outside this specific dataset.
Outputs a correlation table and suggests a realistic feature subset.
"""
import sys, os
sys.stdout.reconfigure(encoding="utf-8")
import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import LabelEncoder

DATASET    = r"C:\Users\hi\Desktop\Cyber\phiusiil+phishing+url+dataset\PhiUSIIL_Phishing_URL_Dataset.csv"
MODELS_DIR = r"C:\Users\hi\Desktop\Cyber\phishing-detector\backend\ml\models"
PLOTS_DIR  = r"C:\Users\hi\Desktop\Cyber\phishing-detector\backend\ml\plots"

df = pd.read_csv(DATASET, encoding="utf-8-sig")
tld_enc = LabelEncoder()
df["TLD_encoded"] = tld_enc.fit_transform(df["TLD"].astype(str))

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

print("=" * 70)
print("  FEATURE SEPARATION ANALYSIS")
print("=" * 70)
print(f"\n{'Feature':<35} {'Corr':>7}  {'Legit Mean':>12}  {'Phish Mean':>12}  {'Legit Std':>10}")
print("-" * 80)

rows = []
for feat in FEATURES:
    if feat not in df.columns:
        continue
    g0   = df[df["label"] == 0][feat]
    g1   = df[df["label"] == 1][feat]
    corr = abs(df[feat].corr(df["label"]))
    rows.append({
        "feature":    feat,
        "corr":       corr,
        "legit_mean": g0.mean(),
        "phish_mean": g1.mean(),
        "legit_std":  g0.std(),
        "phish_std":  g1.std(),
    })

report = pd.DataFrame(rows).sort_values("corr", ascending=False)

HIGH    = report[report["corr"] >= 0.40]
MEDIUM  = report[(report["corr"] >= 0.15) & (report["corr"] < 0.40)]
LOW     = report[report["corr"] < 0.15]

for _, r in report.iterrows():
    flag = "*** HIGH ***" if r["corr"] >= 0.40 else ("  MEDIUM" if r["corr"] >= 0.15 else "  low")
    print(f"  {r['feature']:<33} {r['corr']:>7.4f}  {r['legit_mean']:>12.3f}  {r['phish_mean']:>12.3f}  {r['legit_std']:>10.3f}  {flag}")

print(f"\n  HIGH separation features (|corr| >= 0.40): {len(HIGH)}")
for _, r in HIGH.iterrows():
    print(f"    - {r['feature']} (corr={r['corr']:.4f})")

print(f"\n  MEDIUM separation (0.15-0.40): {len(MEDIUM)}")
print(f"  LOW separation   (<0.15):      {len(LOW)}")

# Correlation heatmap (top 20 by correlation)
top20 = report.head(20)
fig, ax = plt.subplots(figsize=(10, 6))
bars = ax.barh(top20["feature"][::-1], top20["corr"][::-1],
               color=["#ef4444" if v >= 0.40 else "#f59e0b" if v >= 0.15 else "#3b82f6"
                      for v in top20["corr"][::-1]])
ax.axvline(0.40, color="#ef4444", linestyle="--", linewidth=1.5, label="High threshold (0.40)")
ax.axvline(0.15, color="#f59e0b", linestyle="--", linewidth=1.5, label="Medium threshold (0.15)")
ax.set_xlabel("|Pearson Correlation with Label|", fontsize=12)
ax.set_title("Feature-Label Correlation — PhishGuard Dataset", fontsize=13, pad=12)
ax.legend(fontsize=10)
ax.grid(axis="x", alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, "feature_correlation.png"), dpi=150, bbox_inches="tight")
plt.close()
print(f"\n[+] Saved: feature_correlation.png")
print("\n[DONE] Separation analysis complete.")
