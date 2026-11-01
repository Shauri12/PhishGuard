"""
PhishGuard — URL & DOM Feature Extraction Service
=================================================
Extracts the 25 high-signal features required by the production XGBoost classifier.
Supports raw URL analysis and merges optional DOM telemetry sent by the Chrome extension.
"""

import re
import urllib.parse
from typing import Dict, Any, Optional
import pandas as pd
from app.services.whitelist_service import is_domain_whitelisted

# Phishing hint keywords often found in fraudulent URL paths/queries
PHISH_HINT_WORDS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "billing", "confirm", "wallet",
    "ebayisapi", "webscr", "auth", "credential", "suspend", "unusual"
}

IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
WORD_REGEX = re.compile(r"[a-zA-Z0-9]+")

# Frequently abused / disposable / low-cost TLDs heavily correlated with phishing, spam & malware
SUSPICIOUS_TLDS = {
    "cc", "xyz", "top", "club", "tk", "ml", "ga", "cf", "gq",
    "buzz", "work", "click", "rest", "fit", "surf", "monster",
    "vip", "icu", "cam", "live", "bar", "sbs", "cfd", "online",
    "site", "fun", "space", "stream", "bid", "loan", "win"
}

def extract_features(
    url: str,
    page_title: Optional[str] = None,
    nb_hyperlinks: Optional[int] = None,
    ratio_intHyperlinks: Optional[float] = None,
    has_login_form: Optional[bool] = None
) -> Dict[str, float]:
    """
    Extracts all 25 features matching the production XGBoost model specification.
    """
    target = url if "://" in url else "https://" + url
    parsed = urllib.parse.urlparse(target)
    hostname = parsed.netloc.split(":")[0].lower()
    path = parsed.path
    query = parsed.query

    url_str = str(url)
    url_len = len(url_str)
    host_len = len(hostname)

    is_ip = 1 if IP_REGEX.match(hostname) else 0

    nb_dots = url_str.count(".")
    nb_hyphens = url_str.count("-")
    nb_at = url_str.count("@")
    nb_qm = url_str.count("?")
    nb_and = url_str.count("&")
    nb_eq = url_str.count("=")
    nb_slash = url_str.count("/")
    nb_www = 1 if "www" in hostname else 0

    digits_url = sum(c.isdigit() for c in url_str)
    digits_host = sum(c.isdigit() for c in hostname)
    ratio_digits_url = digits_url / max(url_len, 1)
    ratio_digits_host = digits_host / max(host_len, 1)

    # Prefix/suffix: check for hyphen in domain name (common in typosquatting)
    prefix_suffix = 1 if "-" in hostname else 0

    # TLD in subdomain check (e.g. paypal.com.evil.com)
    host_parts = hostname.split(".")
    common_tlds = {"com", "net", "org", "co", "io", "gov", "edu"}
    tld_in_sub = 0
    if len(host_parts) > 2:
        subdomain_part = ".".join(host_parts[:-2])
        if any(t in subdomain_part for t in common_tlds):
            tld_in_sub = 1

    # Word length statistics
    host_words = WORD_REGEX.findall(hostname)
    shortest_word_host = min((len(w) for w in host_words), default=0)

    all_words = WORD_REGEX.findall(url_str)
    longest_words_raw = max((len(w) for w in all_words), default=0)

    # Phish hints count
    low_url = url_str.lower()
    phish_hints_count = sum(1 for w in PHISH_HINT_WORDS if w in low_url)

    whitelisted = is_domain_whitelisted(url)

    # Domain reputation & search index heuristics aligned with benchmark dataset:
    # In the dataset:
    # - google_index: 0 = indexed by Google (legitimate), 1 = unindexed / phishing
    # - page_rank: 0 to 10 scale (legitimate avg ~ 4.5 to 10, phishing avg ~ 0.0)
    # - domain_age: days since registration (legitimate avg ~ 5165 days, phishing avg low/negative)
    tld = host_parts[-1] if len(host_parts) > 1 else ""
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    has_high_digits = ratio_digits_host >= 0.15

    if whitelisted:
        google_index = 0.0
        page_rank = 8.0
        domain_age = 5500.0
        default_hyperlinks = 120.0
    elif is_ip:
        google_index = 1.0
        page_rank = 0.0
        domain_age = -1.0
        default_hyperlinks = 2.0
    elif phish_hints_count > 0 or tld_in_sub == 1:
        # High-confidence Phishing Attack Indicators
        google_index = 1.0
        page_rank = 0.0
        domain_age = 60.0
        default_hyperlinks = 8.0
    elif is_suspicious_tld or has_high_digits or prefix_suffix == 1:
        # Suspicious Domain Tier (Untrusted ccTLDs like .cc, numeric hosts, or typosquatting hyphens)
        google_index = 0.0
        page_rank = 3.0
        domain_age = 500.0
        default_hyperlinks = 45.0
    else:
        # Standard Clean / Established Domain
        google_index = 0.0
        page_rank = 4.0
        domain_age = 3500.0
        default_hyperlinks = 65.0

    # DOM / Extension signals (or defaults if only URL was submitted)
    hyperlinks = float(nb_hyperlinks) if nb_hyperlinks is not None else default_hyperlinks
    int_hyperlinks_ratio = float(ratio_intHyperlinks) if ratio_intHyperlinks is not None else 0.70

    # Title heuristics
    if page_title:
        title_clean = page_title.strip()
        empty_title = 1.0 if len(title_clean) == 0 else 0.0
        domain_name = host_parts[-2] if len(host_parts) >= 2 else hostname
        domain_in_title = 1.0 if domain_name in title_clean.lower() else 0.0
    else:
        empty_title = 0.0
        domain_in_title = 1.0

    return {
        "length_url": float(url_len),
        "length_hostname": float(host_len),
        "ip": float(is_ip),
        "nb_dots": float(nb_dots),
        "nb_hyphens": float(nb_hyphens),
        "nb_at": float(nb_at),
        "nb_qm": float(nb_qm),
        "nb_and": float(nb_and),
        "nb_eq": float(nb_eq),
        "nb_slash": float(nb_slash),
        "nb_www": float(nb_www),
        "ratio_digits_url": float(ratio_digits_url),
        "ratio_digits_host": float(ratio_digits_host),
        "tld_in_subdomain": float(tld_in_sub),
        "prefix_suffix": float(prefix_suffix),
        "shortest_word_host": float(shortest_word_host),
        "longest_words_raw": float(longest_words_raw),
        "phish_hints": float(phish_hints_count),
        "nb_hyperlinks": float(hyperlinks),
        "ratio_intHyperlinks": float(int_hyperlinks_ratio),
        "empty_title": float(empty_title),
        "domain_in_title": float(domain_in_title),
        "domain_age": float(domain_age),
        "google_index": float(google_index),
        "page_rank": float(page_rank),
    }

def get_feature_dataframe(features_dict: Dict[str, float], feature_order: list[str]) -> pd.DataFrame:
    """Converts the extracted dictionary to an ordered DataFrame ready for model input."""
    return pd.DataFrame([features_dict])[feature_order]
