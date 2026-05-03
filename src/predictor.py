# =============================================================================
# PhishGuard AI — Prediction Utility Module
# Description: Loads the saved ML model and provides a clean prediction API.
#              Called by main.py (Streamlit) for real-time scanning.
# =============================================================================

import os
import joblib
import numpy as np
import pandas as pd

# Import feature extraction from our preprocessing module
import sys
sys.path.insert(0, os.path.dirname(__file__))
from data_preprocessing import extract_combined_features

# ──────────────────────────────────────────────────────────────────────────────
# MODEL PATHS — must match train_model.py CONFIG
# ──────────────────────────────────────────────────────────────────────────────

MODEL_PATH    = "models/phishguard_model.pkl"
SCALER_PATH   = "models/phishguard_scaler.pkl"
FEATURES_PATH = "models/feature_names.pkl"


def load_model():
    """
    Loads the trained XGBoost model, scaler, and feature names from disk.
    Returns None if model files don't exist yet (triggers demo mode in UI).
    
    Returns:
        tuple: (model, scaler, feature_names) or (None, None, None)
    """
    if not all(os.path.exists(p) for p in [MODEL_PATH, SCALER_PATH, FEATURES_PATH]):
        return None, None, None

    model         = joblib.load(MODEL_PATH)
    scaler        = joblib.load(SCALER_PATH)
    feature_names = joblib.load(FEATURES_PATH)

    return model, scaler, feature_names


def predict(url: str = "", text: str = "", model=None, scaler=None, feature_names=None) -> dict:
    """
    Analyzes a URL and/or text message for phishing indicators.
    
    Args:
        url          (str): URL to analyze.
        text         (str): Message text to analyze.
        model        : Loaded XGBoost model (pass to avoid reloading).
        scaler       : Fitted StandardScaler.
        feature_names: List of expected feature columns.
    
    Returns:
        dict with keys:
          - risk_score   (float): 0.0 to 1.0 phishing probability
          - risk_level   (str)  : "SAFE", "SUSPICIOUS", or "DANGEROUS"
          - risk_color   (str)  : Hex color for UI display
          - risk_emoji   (str)  : Emoji indicator
          - features     (dict) : Extracted feature values
          - top_signals  (list) : Human-readable top risk factors
    """

    # ── Load model if not provided ──
    if model is None:
        model, scaler, feature_names = load_model()

    # ── If no model trained yet, run heuristic fallback ──
    if model is None:
        return heuristic_predict(url, text)

    # ── Extract features from URL + text input ──
    feature_df = extract_combined_features(url=url, text=text)

    # ── Align columns to match training feature order ──
    for col in feature_names:
        if col not in feature_df.columns:
            feature_df[col] = 0  # Add missing columns with zero

    feature_df = feature_df[feature_names]  # Enforce column order

    # ── Scale features ──
    X_scaled = scaler.transform(feature_df)

    # ── Get phishing probability (second class = phishing) ──
    risk_score = float(model.predict_proba(X_scaled)[0][1])

    # ── Classify risk level with thresholds ──
    risk_level, risk_color, risk_emoji = classify_risk(risk_score)

    # ── Generate human-readable risk signals ──
    features_dict = feature_df.iloc[0].to_dict()
    top_signals   = extract_risk_signals(features_dict, url, text)

    return {
        "risk_score"  : risk_score,
        "risk_level"  : risk_level,
        "risk_color"  : risk_color,
        "risk_emoji"  : risk_emoji,
        "features"    : features_dict,
        "top_signals" : top_signals,
    }


def classify_risk(score: float) -> tuple:
    """
    Maps a 0-1 probability score to a risk level label.
    
    Thresholds:
      0.0 - 0.35 → SAFE
      0.35 - 0.65 → SUSPICIOUS
      0.65 - 1.0 → DANGEROUS
    """
    if score < 0.35:
        return "SAFE",       "#00c853", "✅"
    elif score < 0.65:
        return "SUSPICIOUS", "#ff9100", "⚠️"
    else:
        return "DANGEROUS",  "#d50000", "🚨"


def extract_risk_signals(features: dict, url: str, text: str) -> list:
    """
    Converts numeric features into human-readable risk explanations.
    Returns a list of warning strings for display in the UI.
    
    Args:
        features (dict): Extracted feature values.
        url      (str) : Original URL.
        text     (str) : Original text.
    
    Returns:
        list: Up to 6 human-readable warning messages.
    """
    signals = []

    # ── URL-based signals ──
    if features.get("url_length", 0) > 75:
        signals.append(f"🔗 Suspicious URL length ({int(features['url_length'])} characters)")

    if features.get("at_sign_count", 0) > 0:
        signals.append("⚠️ '@' symbol in URL — classic redirect attack technique")

    if features.get("has_ip_address", 0) == 1:
        signals.append("🖥️ IP address used instead of domain name")

    if features.get("suspicious_tld", 0) == 1:
        signals.append("🌐 High-risk top-level domain (e.g. .xyz, .tk, .ml)")

    if features.get("is_https", 1) == 0:
        signals.append("🔓 No HTTPS — connection is not encrypted")

    if features.get("has_sensitive_word", 0) == 1:
        signals.append("🔑 Sensitive word in URL (login, verify, secure, account)")

    if features.get("subdomain_count", 0) > 2:
        signals.append(f"📡 Excessive subdomains ({int(features['subdomain_count'])}) — common in phishing")

    if features.get("has_hex_encoding", 0) == 1:
        signals.append("🔒 Hex encoding detected — obfuscation technique")

    if features.get("hyphen_count", 0) > 3:
        signals.append(f"➖ Multiple hyphens in domain ({int(features['hyphen_count'])})")

    # ── Text-based signals ──
    if features.get("urgency_keyword_count", 0) > 0:
        signals.append(f"⚡ {int(features['urgency_keyword_count'])} urgency keywords detected (pressure tactic)")

    if features.get("uppercase_ratio", 0) > 0.3:
        signals.append("📢 High uppercase ratio — psychological pressure tactic")

    if features.get("brand_impersonation", 0) > 0:
        signals.append("🏢 Brand impersonation detected (PayPal, Amazon, Google, etc.)")

    if features.get("requests_personal_info", 0) == 1:
        signals.append("🆔 Requests sensitive personal information (SSN, credit card, password)")

    # Return top 6 signals maximum
    return signals[:6] if signals else ["✅ No major risk indicators detected"]


def heuristic_predict(url: str, text: str) -> dict:
    """
    Fallback rule-based prediction when ML model isn't trained yet.
    Used for demo mode so the UI always works even before training.
    
    Returns a basic risk assessment using hand-crafted rules.
    """
    score = 0.0
    signals = []

    url_lower  = url.lower()
    text_lower = text.lower()

    # ── Heuristic checks on URL ──
    if url and not url.startswith("https"):
        score += 0.15
        signals.append("🔓 No HTTPS encryption")

    if "@" in url:
        score += 0.20
        signals.append("⚠️ '@' symbol in URL")

    if len(url) > 75:
        score += 0.10
        signals.append(f"🔗 Very long URL ({len(url)} chars)")

    for tld in [".xyz", ".tk", ".ml", ".ga", ".cf"]:
        if url_lower.endswith(tld):
            score += 0.20
            signals.append(f"🌐 Suspicious TLD: {tld}")

    # ── Heuristic checks on text ──
    urgency_words = ["urgent", "immediately", "verify", "suspended", "click here", "act now"]
    hits = sum(1 for w in urgency_words if w in text_lower)
    if hits:
        score += min(hits * 0.08, 0.30)
        signals.append(f"⚡ {hits} urgency keyword(s) in message")

    score = min(score, 1.0)  # Cap at 1.0
    risk_level, risk_color, risk_emoji = classify_risk(score)

    return {
        "risk_score"  : score,
        "risk_level"  : risk_level,
        "risk_color"  : risk_color,
        "risk_emoji"  : risk_emoji,
        "features"    : {},
        "top_signals" : signals or ["✅ No major risk indicators detected"],
    }