import os, joblib, numpy as np, pandas as pd, re
from urllib.parse import urlparse

SUSPICIOUS_TLDS  = [".xyz",".tk",".ml",".ga",".cf",".gq",".pw",".top",".click",".download",".link",".win",".loan",".racing",".trade"]
SENSITIVE_WORDS  = ["login","secure","banking","account","verify","update","signin","password","credential","confirm","recover"]
BRAND_KEYWORDS   = ["paypal","amazon","netflix","google","microsoft","apple","bank","irs","fedex","dhl","whatsapp","facebook","instagram"]
URGENCY_KEYWORDS = ["immediately","urgent","verify","suspended","click here","confirm now","limited time","act now","blocked","unauthorized","free gift","winner","claim now","tax refund","last chance","account locked","expire"]
SHORTENERS       = ["bit.ly","tinyurl","goo.gl","t.co","ow.ly","short.io","tiny.cc","is.gd","buff.ly","cutt.ly"]
TRUSTED_DOMAINS  = ["google.com","youtube.com","facebook.com","instagram.com","twitter.com","github.com","microsoft.com","apple.com","amazon.com","netflix.com","linkedin.com","wikipedia.org","stackoverflow.com","reddit.com","whatsapp.com","telegram.org","zoom.us","dropbox.com","paypal.com","ebay.com"]

def load_model():
    return None, None, None

def classify_risk(score):
    if score < 0.30:   return "SAFE",       "#00ff88", "✅"
    elif score < 0.60: return "SUSPICIOUS", "#ffcc00", "⚠️"
    else:              return "DANGEROUS",  "#ff2d55", "🚨"

def is_trusted_domain(url):
    url_lower = url.lower()
    for domain in TRUSTED_DOMAINS:
        if domain in url_lower:
            return True
    return False

def predict(url="", text="", model=None, scaler=None, feature_names=None):
    score   = 0.0
    signals = []
    url_lower  = url.lower()  if url  else ""
    text_lower = text.lower() if text else ""

    if url:
        # Trusted domain check — instant SAFE
        if is_trusted_domain(url) and url.startswith("https"):
            return {
                "risk_score" : 0.05,
                "risk_level" : "SAFE",
                "risk_color" : "#00ff88",
                "risk_emoji" : "✅",
                "features"   : _get_features(url, text),
                "top_signals": ["✅ Verified trusted domain detected"]
            }

        # No HTTPS
        if not url.startswith("https"):
            score += 0.20
            signals.append("🔓 No HTTPS — connection is not encrypted")

        # @ in URL
        if "@" in url:
            score += 0.25
            signals.append("⚠️ '@' symbol in URL — redirect attack")

        # IP address
        if re.search(r"(\d{1,3}\.){3}\d{1,3}", url):
            score += 0.25
            signals.append("🖥️ IP address used instead of domain")

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if url_lower.endswith(tld) or f"{tld}/" in url_lower:
                score += 0.30
                signals.append(f"🌐 High-risk TLD detected ({tld})")
                break

        # Shortened URL
        if any(s in url_lower for s in SHORTENERS):
            score += 0.20
            signals.append("🔀 Shortened URL detected")

        # Sensitive words in URL
        if any(w in url_lower for w in SENSITIVE_WORDS):
            score += 0.10
            signals.append("🔑 Sensitive word in URL (login/verify/account)")

        # Excessive hyphens
        if url.count("-") > 3:
            score += 0.10
            signals.append(f"➖ Excessive hyphens ({url.count('-')})")

        # Excessive dots
        if url.count(".") > 5:
            score += 0.10
            signals.append(f"📡 Excessive dots ({url.count('.')})")

        # Long URL
        if len(url) > 100:
            score += 0.10
            signals.append(f"🔗 Suspicious URL length ({len(url)} chars)")

        # Hex encoding
        if url.count("%") > 3:
            score += 0.10
            signals.append("🔒 Hex encoding detected — obfuscation")

        # Brand impersonation in URL
        brand_in_url = [b for b in BRAND_KEYWORDS if b in url_lower]
        if brand_in_url and not is_trusted_domain(url):
            score += 0.20
            signals.append(f"🏢 Brand impersonation in URL ({brand_in_url[0]})")

    if text:
        # Urgency keywords
        hits = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
        if hits > 0:
            score += min(hits * 0.06, 0.25)
            signals.append(f"⚡ {hits} urgency keyword(s) detected")

        # Brand in message
        brands = [b for b in BRAND_KEYWORDS if b in text_lower]
        if brands:
            score += min(len(brands) * 0.05, 0.15)
            signals.append(f"🏢 Brand impersonation ({', '.join(brands[:2])})")

        # Personal info request
        if any(p in text_lower for p in ["credit card","password","ssn","social security","pin","cvv"]):
            score += 0.20
            signals.append("🆔 Requests sensitive personal information")

        # Uppercase pressure
        words = text.split()
        upper = [w for w in words if w.isupper() and len(w) > 2]
        if len(upper) / max(len(words), 1) > 0.3:
            score += 0.10
            signals.append("📢 Excessive uppercase — pressure tactic")

    score = min(score, 1.0)
    risk_level, risk_color, risk_emoji = classify_risk(score)

    return {
        "risk_score"  : score,
        "risk_level"  : risk_level,
        "risk_color"  : risk_color,
        "risk_emoji"  : risk_emoji,
        "features"    : _get_features(url, text),
        "top_signals" : signals[:6] if signals else ["✅ No major risk indicators detected"]
    }

def _get_features(url, text):
    url_lower  = url.lower()  if url  else ""
    text_lower = text.lower() if text else ""
    return {
        "url_length"           : len(url),
        "is_https"             : 1 if url.startswith("https") else 0,
        "dot_count"            : url.count("."),
        "at_sign_count"        : url.count("@"),
        "suspicious_tld"       : 1 if any(t in url_lower for t in SUSPICIOUS_TLDS) else 0,
        "urgency_keyword_count": sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower),
        "subdomain_count"      : max(url.count(".") - 1, 0)
    }
