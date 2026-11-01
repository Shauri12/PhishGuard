"""
PhishGuard — SHAP Explainer
============================
Generates human-readable SHAP explanations for any XGBoost prediction.
Used by both the offline evaluation pipeline and the live FastAPI server.

Output format:
{
  "top_reasons": [
    {
      "feature":     "HasPasswordField",
      "value":       1,
      "shap_value":  0.823,
      "impact":      "HIGH",
      "direction":   "phishing",
      "message":     "Page has a password field (phishing login form)"
    },
    ...
  ],
  "base_score":  0.572,
  "model_score": 0.948
}
"""

import os
import json
import numpy as np
import pandas as pd
import joblib
import shap
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ─── Feature descriptions (mirrors feature_engineering.py & benchmark dataset) ───
FEATURE_DESCRIPTIONS = {
    # 25 Production Benchmark Features
    "length_url":                  "URL length is abnormally long (common in obfuscated phishing attacks)",
    "length_hostname":             "Domain name length is unusually long",
    "ip":                          "Domain uses a raw IP address instead of a verified domain name",
    "nb_dots":                     "Excessive number of subdomains and dots",
    "nb_hyphens":                  "High number of hyphens in URL structure",
    "nb_at":                       "URL contains '@' symbol (used for HTTP basic auth spoofing)",
    "nb_qm":                       "Query string parameters present in URL",
    "nb_and":                      "Multiple query parameters chained together in URL",
    "nb_eq":                       "Multiple assignment parameters passing data in URL",
    "nb_slash":                    "Deep directory paths and redirection chains",
    "nb_www":                      "Standard domain naming convention ('www')",
    "ratio_digits_url":            "Abnormally high ratio of digits in URL (auto-generated campaigns)",
    "ratio_digits_host":           "High proportion of numbers in domain name",
    "tld_in_subdomain":            "Subdomain embeds a deceptive top-level domain (e.g. paypal.com.evil.xyz)",
    "prefix_suffix":               "Domain uses hyphens to impersonate brand names (typosquatting)",
    "shortest_word_host":          "Domain contains unusually short or fragmented character tokens",
    "longest_words_raw":           "URL contains an unusually long continuous token (hex/base64 payload)",
    "phish_hints":                 "URL contains credential-harvesting keywords (login, verify, auth, security)",
    "nb_hyperlinks":               "Webpage link count and density",
    "ratio_intHyperlinks":         "Ratio of internal vs. external hyperlinks",
    "empty_title":                 "Webpage lacks an HTML title tag (fake login template indicator)",
    "domain_in_title":             "Webpage title matches hosting domain name",
    "domain_age":                  "Domain registration maturity / longevity",
    "google_index":                "Domain search engine indexing status (0 = Indexed, 1 = Unindexed)",
    "page_rank":                   "Global domain page rank and authority score",

    # Legacy / PhiUSIIL Feature Descriptions
    "URLLength":                   "URL length is unusually long",
    "DomainLength":                "Domain name is abnormally long",
    "IsDomainIP":                  "Domain is a raw IP address instead of a name",
    "URLSimilarityIndex":          "URL is suspiciously similar to a known phishing pattern",
    "CharContinuationRate":        "Unusual character continuation patterns detected",
    "TLDLegitimateProb":          "Top-level domain has low legitimacy probability",
    "URLCharProb":                 "URL character distribution is abnormal",
    "TLDLength":                   "Top-level domain length is suspicious",
    "NoOfSubDomain":               "Excessive number of subdomains (e.g. paypal.login.evil.com)",
    "HasObfuscation":              "URL contains obfuscated/encoded characters",
    "NoOfObfuscatedChar":          "High number of obfuscated characters in URL",
    "ObfuscationRatio":            "High ratio of obfuscated characters",
    "NoOfLettersInURL":            "Unusual letter count in URL",
    "LetterRatioInURL":            "Abnormal ratio of letters in URL",
    "NoOfDegitsInURL":             "Suspicious number of digits in URL",
    "DegitRatioInURL":             "High digit ratio suggests auto-generated domain",
    "NoOfEqualsInURL":             "Multiple '=' signs suggest parameter tampering",
    "NoOfQMarkInURL":              "Multiple '?' signs suggest suspicious query structure",
    "NoOfAmpersandInURL":          "Excessive parameters via '&' in URL",
    "NoOfOtherSpecialCharsInURL":  "Unusual special characters found in URL",
    "SpacialCharRatioInURL":       "High ratio of special characters in URL",
    "IsHTTPS":                     "Site does not use HTTPS (insecure connection)",
    "LineOfCode":                  "Unusually few/many lines of HTML code",
    "LargestLineLength":           "Single very long line of code (common in obfuscated pages)",
    "HasTitle":                    "Page has no title tag",
    "DomainTitleMatchScore":       "Page title does not match the domain name",
    "URLTitleMatchScore":          "Page title does not match the URL",
    "HasFavicon":                  "Site lacks a favicon (unusual for legitimate sites)",
    "Robots":                      "Suspicious robots.txt configuration",
    "IsResponsive":                "Page is not responsive (uncommon for modern legit sites)",
    "NoOfURLRedirect":             "Multiple URL redirects detected",
    "NoOfSelfRedirect":            "Self-redirecting behaviour detected",
    "HasDescription":              "Page lacks a meta description",
    "NoOfPopup":                   "Page has popup windows (common in phishing)",
    "NoOfiFrame":                  "Page uses iFrames (used to embed malicious content)",
    "HasExternalFormSubmit":       "Form submits data to an external domain",
    "HasSocialNet":                "Page lacks social network links (unusual for legit sites)",
    "HasSubmitButton":             "Page has a submit button (credential harvesting risk)",
    "HasHiddenFields":             "Page contains hidden form fields",
    "HasPasswordField":            "Page has a password field (phishing login form)",
    "Bank":                        "Page contains banking-related keywords",
    "Pay":                         "Page contains payment-related keywords",
    "Crypto":                      "Page contains cryptocurrency-related keywords",
    "HasCopyrightInfo":            "Page lacks copyright information",
    "NoOfImage":                   "Unusual number of images",
    "NoOfCSS":                     "Unusual number of CSS files",
    "NoOfJS":                      "High number of JavaScript files (obfuscation risk)",
    "NoOfSelfRef":                 "Unusual number of self-referencing links",
    "NoOfEmptyRef":                "Page has empty href links (common in phishing templates)",
    "NoOfExternalRef":             "High number of external references",
    "TLD_encoded":                 "Top-level domain is associated with high phishing rate",
}


class PhishGuardExplainer:
    """
    Wraps a trained XGBoost model with a SHAP TreeExplainer.
    Provides both raw SHAP values and structured, human-readable explanations.
    """

    def __init__(self, model, feature_names: list[str]):
        self.model         = model
        self.feature_names = feature_names
        print("[+] Building SHAP TreeExplainer (this may take a moment)...")
        self.explainer     = shap.TreeExplainer(model)
        self.base_score    = 0.5  # binary classification base score
        print("[+] SHAP Explainer ready.")

    def explain(self, X_row: pd.DataFrame, top_n: int = 5) -> dict:
        """
        Generate a human-readable explanation for a single prediction row.

        Args:
            X_row  : DataFrame with a single row (same columns as training)
            top_n  : Number of top reasons to include

        Returns:
            dict with top_reasons, base_score, model_score
        """
        shap_values  = self.explainer.shap_values(X_row)
        # For binary classification, shap_values is shape (1, n_features)
        sv = np.array(shap_values[0]) if isinstance(shap_values, list) else np.array(shap_values[0])

        prob   = float(self.model.predict_proba(X_row)[0, 1])
        values = X_row.iloc[0]

        # Pair features with their SHAP contributions
        pairs = sorted(
            [(self.feature_names[i], float(sv[i]), float(values.iloc[i]))
             for i in range(len(self.feature_names))],
            key=lambda x: abs(x[1]),
            reverse=True,
        )

        top_reasons = []
        for feat, shap_val, feat_val in pairs[:top_n]:
            abs_sv    = abs(shap_val)
            impact    = "HIGH" if abs_sv > 0.3 else ("MEDIUM" if abs_sv > 0.1 else "LOW")
            direction = "phishing"  if shap_val > 0 else "legitimate"
            message   = FEATURE_DESCRIPTIONS.get(feat, feat)

            top_reasons.append({
                "feature":    feat,
                "value":      round(feat_val, 4),
                "shap_value": round(shap_val, 4),
                "impact":     impact,
                "direction":  direction,
                "message":    message,
            })

        return {
            "top_reasons": top_reasons,
            "model_score": round(prob, 4),
        }

    def batch_explain(self, X: pd.DataFrame, top_n: int = 5) -> list[dict]:
        """Generate explanations for a DataFrame of rows."""
        return [self.explain(X.iloc[[i]], top_n=top_n) for i in range(len(X))]

    def plot_waterfall(self, X_row: pd.DataFrame, save_path: str = None):
        """Save a SHAP waterfall plot for a single prediction."""
        shap_values = self.explainer(X_row)
        fig, ax = plt.subplots(figsize=(10, 6))
        shap.waterfall_plot(shap_values[0], max_display=15, show=False)
        plt.title("SHAP Feature Contributions — PhishGuard", fontsize=13, pad=10)
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches="tight")
            plt.close()
            print(f"[+] SHAP waterfall saved: {save_path}")

    def plot_summary(self, X_sample: pd.DataFrame, save_path: str = None):
        """Save a SHAP summary (beeswarm) plot for a sample of rows."""
        shap_values = self.explainer(X_sample)
        fig = plt.figure(figsize=(12, 8))
        shap.summary_plot(shap_values, X_sample, show=False, max_display=20)
        plt.title("SHAP Global Feature Impact — PhishGuard", fontsize=13, pad=10)
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches="tight")
            plt.close()
            print(f"[+] SHAP summary saved: {save_path}")


def load_explainer(models_dir: str) -> PhishGuardExplainer:
    """Load model + feature names and return a ready PhishGuardExplainer."""
    model         = joblib.load(os.path.join(models_dir, "xgboost_model.pkl"))
    feature_names = joblib.load(os.path.join(models_dir, "feature_names.pkl"))
    return PhishGuardExplainer(model, feature_names)


# ─── Standalone: generate SHAP plots after training ──────────────────────────
if __name__ == "__main__":
    import sys
    BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
    MODELS_DIR = os.path.join(BASE_DIR, "models")
    PLOTS_DIR  = os.path.join(BASE_DIR, "plots")
    os.makedirs(PLOTS_DIR, exist_ok=True)

    DATASET = os.path.join(
        BASE_DIR, "..", "..", "..",
        "phiusiil+phishing+url+dataset",
        "PhiUSIIL_Phishing_URL_Dataset.csv"
    )

    print("[+] Loading trained model...")
    model         = joblib.load(os.path.join(MODELS_DIR, "xgboost_model.pkl"))
    feature_names = joblib.load(os.path.join(MODELS_DIR, "feature_names.pkl"))
    tld_encoder   = joblib.load(os.path.join(MODELS_DIR, "tld_encoder.pkl"))

    print("[+] Loading sample data for SHAP plots...")
    df = pd.read_csv(DATASET, encoding="utf-8-sig")
    df["TLD_encoded"] = tld_encoder.transform(df["TLD"].astype(str))
    df.drop(columns=[c for c in ["FILENAME","URL","Domain","Title","TLD","label"] if c in df.columns], inplace=True)
    X_sample = df[[f for f in feature_names if f in df.columns]].sample(500, random_state=42)

    explainer = PhishGuardExplainer(model, feature_names)

    # Summary plot
    explainer.plot_summary(X_sample, save_path=os.path.join(PLOTS_DIR, "shap_summary.png"))

    # Waterfall for one phishing example
    explainer.plot_waterfall(X_sample.iloc[[0]], save_path=os.path.join(PLOTS_DIR, "shap_waterfall.png"))

    # Test single explanation
    sample_row = X_sample.iloc[[0]]
    result     = explainer.explain(sample_row, top_n=5)
    print("\n=== Sample Explanation ===")
    print(json.dumps(result, indent=2))
