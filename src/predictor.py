import os, joblib, numpy as np, pandas as pd, re
from urllib.parse import urlparse

MODEL_PATH    = "models/phishguard_model.pkl"
SCALER_PATH   = "models/phishguard_scaler.pkl"
FEATURES_PATH = "models/feature_names.pkl"

URGENCY_KEYWORDS = ["immediately","urgent","verify","account suspended","click here","confirm now","limited time","act now","suspended","blocked","unauthorized","free gift","winner","claim now","tax refund","last chance","account locked"]
SENSITIVE_WORDS  = ["login","secure","banking","account","verify","update","signin","password"]
SUSPICIOUS_TLDS  = [".xyz",".tk",".ml",".ga",".cf",".gq",".pw",".top",".click"]
BRAND_KEYWORDS   = ["paypal","amazon","netflix","google","microsoft","apple","bank","irs","fedex","dhl","whatsapp","facebook"]

def load_model():
    if not all(os.path.exists(p) for p in [MODEL_PATH, SCALER_PATH, FEATURES_PATH]):
        return None, None, None
    return joblib.load(MODEL_PATH), joblib.load(SCALER_PATH), joblib.load(FEATURES_PATH)

def classify_risk(score):
    if score < 0.30:   return "SAFE",       "#00ff88", "✅"
    elif score < 0.70: return "SUSPICIOUS", "#ffcc00", "⚠️"
    else:              return "DANGEROUS",  "#ff2d55", "🚨"

def extract_risk_signals(url, text):
    signals = []
    url_lower  = url.lower()  if url  else ""
    text_lower = text.lower() if text else ""
    if url and not url.startswith("https"):       signals.append("🔓 No HTTPS — connection is not encrypted")
    if "@" in url:                                signals.append("⚠️ '@' symbol in URL — redirect attack")
    if len(url) > 75:                             signals.append(f"🔗 Suspicious URL length ({len(url)} chars)")
    if any(t in url_lower for t in SUSPICIOUS_TLDS): signals.append("🌐 High-risk TLD (.xyz .tk .ml etc)")
    if re.search(r"(\d{1,3}\.){3}\d{1,3}", url): signals.append("🖥️ IP address used instead of domain")
    if any(s in url_lower for s in ["bit.ly","tinyurl","goo.gl","t.co"]): signals.append("🔀 Shortened URL detected")
    if any(w in url_lower for w in SENSITIVE_WORDS): signals.append("🔑 Sensitive word in URL (login/verify/account)")
    if url.count("-") > 3:                        signals.append(f"➖ Excessive hyphens ({url.count('-')})")
    if url.count(".") > 5:                        signals.append(f"📡 Excessive dots ({url.count('.')})")
    if text:
        hits = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
        if hits: signals.append(f"⚡ {hits} urgency keyword(s) detected")
        brands = sum(1 for b in BRAND_KEYWORDS if b in text_lower)
        if brands: signals.append(f"🏢 Brand impersonation ({brands} brand name(s))")
    return signals[:6] if signals else ["✅ No major risk indicators detected"]

def predict(url="", text="", model=None, scaler=None, feature_names=None):
    if model is None:
        model, scaler, feature_names = load_model()
    if model is None:
        return heuristic_predict(url, text)
    try:
        import tldextract
        parsed = urlparse(url) if url else urlparse("http://x.com")
        ext    = tldextract.extract(url) if url else tldextract.extract("http://x.com")
        url_lower = url.lower() if url else ""
        row = {}
        for f in feature_names:
            row[f] = 0
        if url:
            row["qty_dot_url"]           = url.count(".")
            row["qty_hyphen_url"]        = url.count("-")
            row["qty_underline_url"]     = url.count("_")
            row["qty_slash_url"]         = url.count("/")
            row["qty_questionmark_url"]  = url.count("?")
            row["qty_equal_url"]         = url.count("=")
            row["qty_at_url"]            = url.count("@")
            row["qty_and_url"]           = url.count("&")
            row["qty_exclamation_url"]   = url.count("!")
            row["qty_percent_url"]       = url.count("%")
            row["qty_dollar_url"]        = url.count("$")
            row["length_url"]            = len(url)
            row["qty_vowels_domain"]     = sum(1 for c in ext.domain if c in "aeiou")
            row["domain_length"]         = len(ext.domain)
            row["domain_in_ip"]          = 1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", url) else 0
            row["qty_dot_directory"]     = parsed.path.count(".")
            row["qty_hyphen_directory"]  = parsed.path.count("-")
            row["qty_slash_directory"]   = parsed.path.count("/")
            row["directory_length"]      = len(parsed.path)
            row["qty_equal_params"]      = parsed.query.count("=")
            row["qty_and_params"]        = parsed.query.count("&")
            row["params_length"]         = len(parsed.query)
            row["qty_params"]            = len(parsed.query.split("&")) if parsed.query else 0
            row["email_in_url"]          = 1 if "@" in url else 0
            row["tls_ssl_certificate"]   = 1 if parsed.scheme == "https" else 0
            row["domain_spf"]            = 1 if parsed.scheme == "https" else 0
            row["url_shortened"]         = 1 if any(s in url_lower for s in ["bit.ly","tinyurl","goo.gl","t.co"]) else 0
        feature_df = pd.DataFrame([row])[feature_names]
        X_scaled   = scaler.transform(feature_df)
        risk_score = float(model.predict_proba(X_scaled)[0][1])
        if text:
            text_lower = text.lower()
            hits   = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
            brands = sum(1 for b in BRAND_KEYWORDS if b in text_lower)
            risk_score = min(risk_score + hits*0.04 + brands*0.03, 1.0)
        risk_level, risk_color, risk_emoji = classify_risk(risk_score)
        signals = extract_risk_signals(url, text)
        feat_display = {"url_length": row.get("length_url",0), "is_https": row.get("tls_ssl_certificate",0), "dot_count": row.get("qty_dot_url",0), "at_sign_count": row.get("qty_at_url",0), "suspicious_tld": 1 if any(t in url.lower() for t in SUSPICIOUS_TLDS) else 0, "urgency_keyword_count": sum(1 for kw in URGENCY_KEYWORDS if kw in text.lower()) if text else 0, "subdomain_count": len(ext.subdomain.split(".")) if ext.subdomain else 0}
        return {"risk_score": risk_score, "risk_level": risk_level, "risk_color": risk_color, "risk_emoji": risk_emoji, "features": feat_display, "top_signals": signals}
    except Exception as e:
        return heuristic_predict(url, text)

def heuristic_predict(url, text):
    score = 0.0
    signals = []
    url_lower  = url.lower()  if url  else ""
    text_lower = text.lower() if text else ""
    if url and not url.startswith("https"): score += 0.20; signals.append("🔓 No HTTPS")
    if "@" in url: score += 0.25; signals.append("⚠️ '@' in URL")
    if len(url) > 75: score += 0.10; signals.append(f"🔗 Long URL ({len(url)} chars)")
    for t in SUSPICIOUS_TLDS:
        if url_lower.endswith(t): score += 0.25; signals.append(f"🌐 Suspicious TLD: {t}"); break
    hits = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
    if hits: score += min(hits*0.06, 0.25); signals.append(f"⚡ {hits} urgency keywords")
    score = min(score, 1.0)
    risk_level, risk_color, risk_emoji = classify_risk(score)
    return {"risk_score": score, "risk_level": risk_level, "risk_color": risk_color, "risk_emoji": risk_emoji, "features": {}, "top_signals": signals or ["✅ No risk indicators"]}
