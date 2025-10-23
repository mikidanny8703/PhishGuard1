# phishing_features.py
import re
import numpy as np
import tldextract

def extract_features(url: str):
    """Extract 12 numerical features from URL."""
    ext = tldextract.extract(url)
    domain = ext.domain or ""

    feats = [
        len(url),  # URL length
        sum(c.isdigit() for c in url),  # number of digits
        len(re.findall(r"[^a-zA-Z0-9]", url)),  # special chars
        url.count('.'),
        url.count('/'),
        len(domain),
        1 if url.lower().startswith("https") else 0,
        1 if re.match(r"(\d{1,3}\.){3}\d{1,3}", url) else 0,
        1 if "login" in url.lower() else 0,
        1 if "secure" in url.lower() else 0,
        1 if "verify" in url.lower() else 0,
        1 if "update" in url.lower() else 0,
    ]
    return np.array(feats).reshape(1, -1)
