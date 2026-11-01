"""Quick end-to-end test of the PhishGuardExplainer."""
import sys, os, joblib
sys.stdout.reconfigure(encoding="utf-8")
import pandas as pd
from sklearn.model_selection import train_test_split

MODELS_DIR = r"C:\Users\hi\Desktop\Cyber\phishing-detector\backend\ml\models"
DATASET    = r"C:\Users\hi\Desktop\Cyber\phiusiil+phishing+url+dataset\PhiUSIIL_Phishing_URL_Dataset.csv"

model         = joblib.load(os.path.join(MODELS_DIR, "xgboost_model.pkl"))
feature_names = joblib.load(os.path.join(MODELS_DIR, "feature_names.pkl"))
tld_encoder   = joblib.load(os.path.join(MODELS_DIR, "tld_encoder.pkl"))

df = pd.read_csv(DATASET, encoding="utf-8-sig")
df["TLD_encoded"] = tld_encoder.transform(df["TLD"].astype(str))
y = df["label"].astype(int)
X = df[[f for f in feature_names if f in df.columns]]
_, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

sys.path.insert(0, r"C:\Users\hi\Desktop\Cyber\phishing-detector\backend\ml")
from explainer import PhishGuardExplainer

explainer = PhishGuardExplainer(model, feature_names)

def print_explanation(title, row, expected):
    result = explainer.explain(row, top_n=5)
    prob   = result["model_score"]
    label  = "PHISHING" if prob >= 0.5 else "LEGITIMATE"
    status = "CORRECT" if label == expected else "WRONG"
    print(f"\n=== {title} ===")
    print(f"  Score : {prob:.4f}  |  Label: {label}  [{status}]")
    for r in result["top_reasons"]:
        arrow = ">>" if r["direction"] == "phishing" else "<<"
        print(f"  {arrow} [{r['impact']:6}] {r['feature']}")
        print(f"         {r['message']}")

print_explanation("LEGITIMATE SITE", X_test[y_test==0].iloc[[0]], "LEGITIMATE")
print_explanation("PHISHING SITE",   X_test[y_test==1].iloc[[0]], "PHISHING")

print("\n[OK] End-to-end explainer test passed.")
