"""
PhishGuard — SHAP Explainability Service
========================================
Generates human-readable, cybersecurity-oriented explanations for each prediction.
Uses SHAP TreeExplainer to break down the exact log-odds contributions of features.
"""

from typing import List, Dict, Any
import numpy as np
import pandas as pd
import shap
from app.models.schemas import SHAPFactor

FEATURE_EXPLANATIONS = {
    "ip": "Domain uses a raw IP address instead of a verified domain name",
    "phish_hints": "URL contains sensitive credential-harvesting keywords (e.g., login, verify, auth, security)",
    "tld_in_subdomain": "Subdomain embeds a deceptive top-level domain (e.g., paypal.com.evil.xyz)",
    "prefix_suffix": "Domain uses hyphens to impersonate a brand name (typosquatting)",
    "ratio_digits_url": "Abnormally high number of digits in URL (indicative of auto-generated attack campaigns)",
    "ratio_digits_host": "High proportion of numbers in domain name",
    "length_url": "URL length is abnormally long (common in obfuscated phishing attacks)",
    "length_hostname": "Domain name length is unusually long",
    "nb_dots": "Excessive number of subdomains and dots",
    "nb_slash": "Unusually deep directory paths and redirection chains",
    "nb_qm": "Query string parameters present in URL",
    "nb_and": "Multiple query parameters chained together",
    "nb_eq": "Multiple assignment parameters passing data in URL",
    "nb_at": "URL contains '@' symbol (used for HTTP basic auth spoofing)",
    "nb_www": "Domain does not follow standard web conventions",
    "shortest_word_host": "Domain contains unusually short or fragmented character tokens",
    "longest_words_raw": "URL contains an unusually long continuous token (common in hex/base64 payloads)",
    "nb_hyperlinks": "Webpage has an abnormally sparse or dense link distribution",
    "ratio_intHyperlinks": "Abnormal ratio of internal vs. external hyperlinks",
    "empty_title": "Webpage lacks an HTML title tag (frequently seen in fake login templates)",
    "domain_in_title": "Webpage title does not match the actual hosting domain",
    "domain_age": "Domain registration age indicates a freshly registered malicious host",
    "google_index": "Domain lacks standard search engine indexing",
    "page_rank": "Domain has low global page rank and inbound link authority",
}

class ExplainerService:
    def __init__(self, model, feature_names: list[str]):
        self.model = model
        self.feature_names = feature_names
        self.explainer = shap.TreeExplainer(model)

    def explain(self, X_row: pd.DataFrame, top_n: int = 5) -> List[SHAPFactor]:
        """
        Calculates SHAP values for a single row and returns the top human-readable factors.
        """
        shap_vals = self.explainer.shap_values(X_row)
        sv = np.array(shap_vals[0]) if isinstance(shap_vals, list) else np.array(shap_vals[0])

        values = X_row.iloc[0]

        pairs = sorted(
            [(self.feature_names[i], float(sv[i]), values.iloc[i])
             for i in range(len(self.feature_names))],
            key=lambda x: abs(x[1]),
            reverse=True
        )

        factors: List[SHAPFactor] = []
        for feat, shap_val, feat_val in pairs[:top_n]:
            abs_sv = abs(shap_val)
            impact = "HIGH" if abs_sv > 0.4 else ("MEDIUM" if abs_sv > 0.15 else "LOW")
            direction = "phishing" if shap_val > 0 else "legitimate"
            
            # Format message
            msg = FEATURE_EXPLANATIONS.get(feat, f"Feature {feat} contributed to risk calculation")
            if direction == "legitimate" and "instead" not in msg:
                msg = f"Normal / safe indicator: {msg.lower()}"

            factors.append(SHAPFactor(
                feature=feat,
                value=round(float(feat_val), 4) if isinstance(feat_val, (int, float)) else str(feat_val),
                impact=impact,
                direction=direction,
                message=msg
            ))

        return factors
