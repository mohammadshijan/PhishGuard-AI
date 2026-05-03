# =============================================================================
# PhishGuard AI — Feature Extraction & Data Preprocessing Engine
# Author: PhishGuard AI Team
# Description: Extracts security-relevant features from URLs and text messages.
#              Designed for low-memory, high-speed operation on Windows 11.
# =============================================================================

import re                          # Regular expressions for pattern matching
import pandas as pd                # DataFrame operations
import numpy as np                 # Numerical computing
import tldextract                  # Accurate domain/TLD parsing
from urllib.parse import urlparse  # URL component breakdown

# ──────────────────────────────────────────────────────────────────────────────
# SECTION 1: URGENCY VOCABULARY
# These are psychological manipulation keywords commonly used in phishing.
# ──────────────────────────────────────────────────────────────────────────────

URGENCY_KEYWORDS = [
    "immediately", "urgent", "verify", "account suspended", "click here",
    "confirm now", "limited time", "act now", "your account", "login",
    "update required", "security alert", "unusual activity", "expire",
    "reset password", "validate", "suspended", "blocked", "unauthorized",
    "free gift", "congratulations", "winner", "claim now", "prize"
]

# ──────────────────────────────────────────────────────────────────────────────
# SECTION 2: SINGLE URL FEATURE EXTRACTOR
# Extracts 20+ numerical features from a raw URL string.
# ──────────────────────────────────────────────────────────────────────────────

def extract_url_features(url: str) -> dict:
    """
    Takes a single URL string and returns a dictionary of numeric features.
    All features are designed to be computable offline (no API calls).
    
    Args:
        url (str): Raw URL input from the user.
    
    Returns:
        dict: Feature dictionary compatible with the ML model.
    """
    features = {}

    # ── Basic sanity check ──
    url = str(url).strip()

    # ── Parse URL into components ──
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
    except Exception:
        # Return zero-vector if parsing fails
        return {key: 0 for key in _feature_keys()}

    # ── Feature 1: Total URL length (longer URLs are more suspicious) ──
    features["url_length"] = len(url)

    # ── Feature 2: Domain length ──
    features["domain_length"] = len(ext.domain)

    # ── Feature 3: Path length ──
    features["path_length"] = len(parsed.path)

    # ── Feature 4: Count of dots in the full URL ──
    features["dot_count"] = url.count(".")

    # ── Feature 5: Count of hyphens (used in fake domains like paypa1-login.com) ──
    features["hyphen_count"] = url.count("-")

    # ── Feature 6: Count of '@' symbols (used to redirect before the @ symbol) ──
    features["at_sign_count"] = url.count("@")

    # ── Feature 7: Count of '?' symbols (query parameters) ──
    features["question_mark_count"] = url.count("?")

    # ── Feature 8: Count of '=' symbols (form fields in URL) ──
    features["equals_count"] = url.count("=")

    # ── Feature 9: Count of slashes in path ──
    features["slash_count"] = url.count("/")

    # ── Feature 10: Number of subdomains (paypal.evil-site.com = 2 subdomains) ──
    subdomain = ext.subdomain
    features["subdomain_count"] = len(subdomain.split(".")) if subdomain else 0

    # ── Feature 11: HTTPS present (1 = safe indicator, 0 = no HTTPS) ──
    features["is_https"] = 1 if parsed.scheme == "https" else 0

    # ── Feature 12: IP address used instead of domain name ──
    ip_pattern = re.compile(
        r"(\d{1,3}\.){3}\d{1,3}"  # Matches IPv4 patterns
    )
    features["has_ip_address"] = 1 if ip_pattern.search(url) else 0

    # ── Feature 13: Presence of suspicious TLD (top-level domain) ──
    suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".click"]
    features["suspicious_tld"] = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0

    # ── Feature 14: Digit ratio in the URL (lots of numbers = suspicious) ──
    digit_count = sum(c.isdigit() for c in url)
    features["digit_ratio"] = round(digit_count / max(len(url), 1), 4)

    # ── Feature 15: Special character count ──
    special_chars = re.findall(r"[!#$%^&*(),?\":{}|<>]", url)
    features["special_char_count"] = len(special_chars)

    # ── Feature 16: Presence of 'login', 'secure', 'bank' in URL (credential phishing) ──
    sensitive_words = ["login", "secure", "banking", "account", "verify", "update", "signin"]
    features["has_sensitive_word"] = 1 if any(word in url.lower() for word in sensitive_words) else 0

    # ── Feature 17: URL contains hex encoding (used to obfuscate malicious content) ──
    features["has_hex_encoding"] = 1 if re.search(r"%[0-9a-fA-F]{2}", url) else 0

    # ── Feature 18: Double slashes in path (abnormal redirect technique) ──
    features["has_double_slash"] = 1 if "//" in parsed.path else 0

    # ── Feature 19: Query string length ──
    features["query_length"] = len(parsed.query)

    # ── Feature 20: Fragment presence (#section — can hide malicious redirects) ──
    features["has_fragment"] = 1 if parsed.fragment else 0

    return features


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 3: TEXT MESSAGE FEATURE EXTRACTOR
# Analyzes raw message text for social engineering patterns.
# ──────────────────────────────────────────────────────────────────────────────

def extract_text_features(text: str) -> dict:
    """
    Extracts features from raw message/email text.
    Detects urgency language, embedded URLs, and manipulation patterns.
    
    Args:
        text (str): Raw message or email body text.
    
    Returns:
        dict: Feature dictionary for the ML model.
    """
    features = {}
    text_lower = text.lower()

    # ── Feature 1: Total text length ──
    features["text_length"] = len(text)

    # ── Feature 2: Urgency keyword count (core social engineering signal) ──
    urgency_matches = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
    features["urgency_keyword_count"] = urgency_matches

    # ── Feature 3: Uppercase word ratio (SHOUTING = pressure tactic) ──
    words = text.split()
    upper_words = [w for w in words if w.isupper() and len(w) > 2]
    features["uppercase_ratio"] = round(len(upper_words) / max(len(words), 1), 4)

    # ── Feature 4: Exclamation mark count (creates false excitement) ──
    features["exclamation_count"] = text.count("!")

    # ── Feature 5: Number of URLs embedded in the text ──
    url_pattern = re.compile(r"https?://\S+|www\.\S+")
    embedded_urls = url_pattern.findall(text)
    features["embedded_url_count"] = len(embedded_urls)

    # ── Feature 6: Presence of phone numbers (smishing indicator) ──
    phone_pattern = re.compile(r"\+?\d[\d\s\-().]{7,}\d")
    features["has_phone_number"] = 1 if phone_pattern.search(text) else 0

    # ── Feature 7: Impersonation keywords (brand spoofing) ──
    brand_keywords = ["paypal", "amazon", "netflix", "google", "microsoft",
                      "apple", "bank", "irs", "fedex", "dhl", "whatsapp"]
    features["brand_impersonation"] = sum(1 for b in brand_keywords if b in text_lower)

    # ── Feature 8: Request for personal information ──
    personal_info_patterns = ["social security", "credit card", "password",
                               "pin number", "cvv", "date of birth", "ssn"]
    features["requests_personal_info"] = 1 if any(p in text_lower for p in personal_info_patterns) else 0

    return features


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 4: COMBINED FEATURE VECTOR
# Merges URL + Text features into a single flat vector for the model.
# ──────────────────────────────────────────────────────────────────────────────

def extract_combined_features(url: str = "", text: str = "") -> pd.DataFrame:
    """
    Produces a single-row DataFrame with all features combined.
    This is the input format expected by the trained ML model.
    
    Args:
        url  (str): The URL to analyze (optional).
        text (str): The message text to analyze (optional).
    
    Returns:
        pd.DataFrame: Single-row DataFrame with all feature columns.
    """
    url_feats = extract_url_features(url) if url else {k: 0 for k in extract_url_features("http://x.com")}
    text_feats = extract_text_features(text) if text else {k: 0 for k in extract_text_features("x")}

    # Merge both feature dictionaries
    combined = {**url_feats, **text_feats}
    return pd.DataFrame([combined])


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 5: DATASET PREPROCESSOR
# Loads a CSV dataset and applies feature extraction to every row.
# ──────────────────────────────────────────────────────────────────────────────

def preprocess_dataset(csv_path: str, url_col: str = "url", label_col: str = "label") -> tuple:
    """
    Loads a phishing dataset CSV and returns feature matrix X and labels y.
    
    Expected CSV format:
        url        | label
        --------   | -----
        http://... | 1        (1 = phishing, 0 = legitimate)
    
    Args:
        csv_path (str): Path to the CSV file.
        url_col  (str): Column name containing URLs.
        label_col(str): Column name containing binary labels.
    
    Returns:
        tuple: (X: pd.DataFrame, y: pd.Series)
    """
    print(f"[PhishGuard] Loading dataset from: {csv_path}")
    df = pd.read_csv(csv_path)

    # Validate required columns exist
    if url_col not in df.columns:
        raise ValueError(f"Column '{url_col}' not found. Available: {list(df.columns)}")
    if label_col not in df.columns:
        raise ValueError(f"Column '{label_col}' not found. Available: {list(df.columns)}")

    print(f"[PhishGuard] Dataset loaded: {len(df)} rows")
    print(f"[PhishGuard] Label distribution:\n{df[label_col].value_counts()}\n")

    # Apply URL feature extraction to every row
    print("[PhishGuard] Extracting features (this may take a moment)...")
    feature_rows = df[url_col].apply(extract_url_features)

    # Convert list of dicts to DataFrame
    X = pd.DataFrame(list(feature_rows))

    # Fill any NaN values with 0 (defensive coding)
    X = X.fillna(0)

    # Extract labels
    y = df[label_col].astype(int)

    print(f"[PhishGuard] Feature extraction complete. Shape: {X.shape}")
    return X, y


def _feature_keys():
    """Returns default feature key list for zero-vector generation."""
    dummy = extract_url_features("http://example.com")
    return list(dummy.keys())


# ──────────────────────────────────────────────────────────────────────────────
# QUICK TEST — Run this file directly to validate feature extraction
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_url = "http://paypa1-login.verify-account.xyz/update?user=admin&token=abc123"
    test_text = "URGENT! Your PayPal account has been suspended. Verify immediately or lose access!"

    print("=== URL Feature Extraction Test ===")
    url_features = extract_url_features(test_url)
    for k, v in url_features.items():
        print(f"  {k:30s}: {v}")

    print("\n=== Text Feature Extraction Test ===")
    text_features = extract_text_features(test_text)
    for k, v in text_features.items():
        print(f"  {k:30s}: {v}")

    print("\n=== Combined Feature Vector ===")
    combined_df = extract_combined_features(url=test_url, text=test_text)
    print(combined_df.T)