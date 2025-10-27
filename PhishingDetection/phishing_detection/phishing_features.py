import numpy as np
import re
import tldextract

def extract_features(url: str):
    ext = tldextract.extract(url)
    domain = ext.domain or ""
    features = [
        len(url),
        sum(c.isdigit() for c in url),
        len(re.findall(r"[^a-zA-Z0-9]", url)),
        url.count('.'),
        url.count('/'),
        len(domain),
        1 if url.lower().startswith("https") else 0,
        1 if re.match(r"(\d{1,3}\.){3}\d{1,3}", url) else 0,
        1 if "login" in url.lower() else 0,
        1 if "secure" in url.lower() else 0,
        1 if "verify" in url.lower() else 0,
        1 if "update" in url.lower() else 0
    ]
    return np.array(features).reshape(1, -1)
