from flask import Flask, render_template, request, jsonify
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
import joblib
import re
from urllib.parse import urlparse
import ipaddress
import whois
from datetime import datetime
import requests
from bs4 import BeautifulSoup

# --- Your Feature Extraction Code ---
# 1. IP Address in URL
def havingIP(url):
    try:
        ipaddress.ip_address(urlparse(url).hostname)
        return 1  # Phishing
    except:
        return 0  # Legitimate

# 2. URL Length
def getLength(url):
    if len(url) < 54:
        return 0
    elif 54 <= len(url) <= 75:
        return -1
    else:
        return 1  # Phishing

# 3. Shortening Services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net"
def tinyURL(url):
    if re.search(shortening_services, url):
        return 1  # Phishing
    else:
        return 0

# 4. '@' Symbol in URL
def haveAtSign(url):
    return 1 if "@" in url else 0

# 5. Redirection '//' in URL
def redirection(url):
    pos = url.rfind('//')
    return 1 if pos > 6 else 0

# 6. Prefix/Suffix '-' in Domain
def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

# 7. Subdomains Count
def subDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    dots = domain.count('.')
    if dots > 2:
        return 1  # Phishing
    elif dots == 2:
        return 0
    else:
        return -1

# 8. HTTPS in Domain
def httpDomain(url):
    return 1 if 'https' in urlparse(url).netloc else 0

# 9. Domain Age
def domainAge(domain_name):
    try:
        creation_date = domain_name.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days / 365
        return 1 if age < 1 else 0
    except:
        return 1  # Assume phishing if error

# 10. Domain End (Expiration)
def domainEnd(domain_name):
    try:
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        end = (expiration_date - datetime.now()).days / 365
        return 1 if end < 1 else 0
    except:
        return 1

# 11. iFrame
def iframe(response):
    if response and re.findall(r"[<iframe>|<frameBorder>]", response.text):
        return 0
    return 1

# Main Feature Extraction
def extract_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    try:
        whois_info = whois.whois(domain)
    except:
        whois_info = None

    try:
        response = requests.get(url, timeout=5)
    except:
        response = None

    features = [
        havingIP(url),
        getLength(url),
        tinyURL(url),
        haveAtSign(url),
        redirection(url),
        prefixSuffix(url),
        subDomain(url),
        httpDomain(url),
        domainAge(whois_info) if whois_info else 1,
        domainEnd(whois_info) if whois_info else 1,
        iframe(response) if response else 1,
        *[0] * 19  # Placeholder for other 19 UCI features
    ]
    return features

# --- Train Model (Run Once, Comment Out After Saving) ---
"""
df = pd.read_csv('phishing.csv')  # UCI dataset
X = df.drop('Result', axis=1)
y = df['Result']
model = DecisionTreeClassifier()
model.fit(X, y)
joblib.dump(model, 'phishing_model.pkl')
"""

# --- Flask App ---
app = Flask(__name__)
model = joblib.load('phishing_model.pkl')  # Load trained model

# Routes for HTML Pages
@app.route('/')
@app.route('/home.html')
def home():
    return render_template('home.html')

@app.route('/demo.html')
def demo():
    return render_template('demo.html')

@app.route('/contact.html')
def contact():
    return render_template('contact.html')

@app.route('/about.html')
def about():
    return render_template('about.html')

@app.route('/faq.html')
def faq():
    return render_template('faq.html')

@app.route('/features.html')
def features():
    return render_template('features.html')

@app.route('/livedashboard.html')
def livedashboard():
    return render_template('livedashboard.html')

@app.route('/settings.html')
def settings():
    return render_template('settings.html')

# Handle URL Scan
@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    features = extract_features(url)
    features_df = pd.DataFrame([features], columns=[f'f{i+1}' for i in range(30)])  # Match UCI feature names
    prediction = model.predict(features_df)[0]
    result = 'Phishing' if prediction == -1 else 'Legitimate'
    return jsonify({'result': result, 'confidence': 0.96})  # Mock confidence

if __name__ == '__main__':
    app.run(debug=True)