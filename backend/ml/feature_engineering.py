"""
PhishGuard — Feature Engineering
=================================
Maps the PhiUSIIL dataset columns to our feature set,
handles encoding of TLD and other categorical columns,
and defines the canonical feature list used across
training, evaluation, and the live prediction API.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder

# ─── Columns to DROP (non-predictive or text-heavy) ───────────────────────────
DROP_COLS = ["FILENAME", "URL", "Domain", "Title"]

# ─── Target column ─────────────────────────────────────────────────────────────
TARGET_COL = "label"

# ─── Categorical columns to encode ─────────────────────────────────────────────
CATEGORICAL_COLS = ["TLD"]

# ─── Final numeric feature list (in order used during training) ────────────────
NUMERIC_FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "URLSimilarityIndex",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
    "LineOfCode",
    "LargestLineLength",
    "HasTitle",
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "HasFavicon",
    "Robots",
    "IsResponsive",
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasDescription",
    "NoOfPopup",
    "NoOfiFrame",
    "HasExternalFormSubmit",
    "HasSocialNet",
    "HasSubmitButton",
    "HasHiddenFields",
    "HasPasswordField",
    "Bank",
    "Pay",
    "Crypto",
    "HasCopyrightInfo",
    "NoOfImage",
    "NoOfCSS",
    "NoOfJS",
    "NoOfSelfRef",
    "NoOfEmptyRef",
    "NoOfExternalRef",
    "TLD_encoded",
]

# ─── Human-readable feature descriptions (for SHAP explanation UI) ────────────
FEATURE_DESCRIPTIONS = {
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


def load_and_prepare(csv_path: str):
    """
    Load the PhiUSIIL dataset, encode categoricals,
    and return (X, y, tld_encoder).
    """
    print(f"[+] Loading dataset from: {csv_path}")
    df = pd.read_csv(csv_path, encoding="utf-8-sig")
    print(f"[+] Raw shape: {df.shape}")

    # Encode TLD
    tld_encoder = LabelEncoder()
    df["TLD_encoded"] = tld_encoder.fit_transform(df["TLD"].astype(str))

    # Drop non-feature columns
    drop = [c for c in DROP_COLS + CATEGORICAL_COLS if c in df.columns]
    df.drop(columns=drop, inplace=True)

    # Separate features and target
    y = df[TARGET_COL].astype(int)
    X = df[[f for f in NUMERIC_FEATURES if f in df.columns]]

    print(f"[+] Feature matrix shape: {X.shape}")
    print(f"[+] Class distribution:\n{y.value_counts()}")

    return X, y, tld_encoder


def get_feature_names():
    return NUMERIC_FEATURES


def describe_feature(feature_name: str) -> str:
    """Return a human-readable explanation for a feature."""
    return FEATURE_DESCRIPTIONS.get(feature_name, feature_name)
