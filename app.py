# app.py
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
import os, io, csv, json, hmac, hashlib, tempfile, joblib, smtplib
from email.mime.text import MIMEText
from datetime import datetime
from phishing_features import extract_features

# === Flask setup ===
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "phishguard_secret_key")

# === Developer credentials ===
DEVELOPER_PASSWORD = os.environ.get("DEV_PASSWORD", "admin123")
DEVELOPER_EMAIL = os.environ.get("DEV_EMAIL", "youremail@example.com")
EMAIL_SENDER = os.environ.get("EMAIL_SENDER", "youremail@example.com")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "your_app_password")  # Gmail app password

# === File paths ===
MODEL_PATH = "model.pkl"
MODEL_SIG_PATH = "model.pkl.hmac"
HONEYPOT_LOG = "honeypot_log.txt"
BLACKLIST_FILE = "blacklist.json"
ALERT_FILE = "last_alert.json"  # track last email alert timestamp

# === HMAC key for model verification ===
HMAC_KEY = os.environ.get("MODEL_HMAC_KEY", "change_this_secret_key").encode("utf-8")

# === Secure JSON writer (atomic replace) ===
def atomic_write_json(path, data):
    dirpath = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=dirpath, prefix=".tmp", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try: os.remove(tmp)
            except: pass

# === Safe JSON loader ===
def safe_load_json(path):
    if not os.path.exists(path):
        atomic_write_json(path, [])
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ {path} corrupted — resetting ({e})")
        backup = path + f".corrupt_" + datetime.now().strftime("%Y%m%d_%H%M%S")
        try: os.rename(path, backup)
        except: pass
        atomic_write_json(path, [])
        return []

# === Safe log append ===
def append_log_line(path, line):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (line + "\n").encode("utf-8"))
    finally:
        os.close(fd)

# === Email alert ===
def send_email_alert(ip, url):
    try:
        subject = "🚨 PhishGuard Alert: New Phishing Attempt Detected"
        body = f"A new phishing attempt was detected.\n\nIP Address: {ip}\nURL: {url}\nTime: {datetime.now()}\n\nStay safe,\nPhishGuard System"
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_SENDER
        msg["To"] = DEVELOPER_EMAIL

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        # Save last alert time
        atomic_write_json(ALERT_FILE, {"last_sent": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        print("📧 Email alert sent successfully.")
    except Exception as e:
        print("⚠️ Failed to send email alert:", e)

# === Get last alert time ===
def get_last_alert_time():
    if not os.path.exists(ALERT_FILE):
        return "No alerts sent yet"
    try:
        with open(ALERT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("last_sent", "No alerts sent yet")
    except:
        return "No alerts sent yet"

# === Verify model integrity ===
def verify_model_signature():
    try:
        if not os.path.exists(MODEL_PATH) or not os.path.exists(MODEL_SIG_PATH):
            print("⚠️ Model or signature missing.")
            return False
        with open(MODEL_PATH, "rb") as f:
            data = f.read()
        with open(MODEL_SIG_PATH, "r") as f:
            expected = f.read().strip()
        actual = hmac.new(HMAC_KEY, data, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, actual):
            print("✅ Model signature verified.")
            return True
        else:
            print("❌ Model signature mismatch.")
            return False
    except Exception as e:
        print("⚠️ Model signature check failed:", e)
        return False

# === Load model ===
model = None
if verify_model_signature():
    try:
        model = joblib.load(MODEL_PATH)
        print("✅ Model loaded successfully.")
    except Exception as e:
        print("⚠️ Failed to load model:", e)
else:
    print("⚠️ Model verification failed — running without ML model.")

# === Initialize files ===
if not os.path.exists(HONEYPOT_LOG):
    open(HONEYPOT_LOG, "w", encoding="utf-8").close()
blacklist = set(safe_load_json(BLACKLIST_FILE))

# === Helper: parse honeypot log ===
def parse_honeypot_log():
    entries = []
    if not os.path.exists(HONEYPOT_LOG):
        return entries
    with open(HONEYPOT_LOG, "r", encoding="utf-8") as f:
        for line in f:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3:
                timestamp, ip, url = parts[0], parts[1], "|".join(parts[2:]).strip()
                entries.append({"timestamp": timestamp, "ip": ip, "url": url})
    entries.reverse()
    return entries

# === Firewall check ===
@app.before_request
def firewall_check():
    endpoint = (request.endpoint or "")
    ip = request.remote_addr
    allowed = {"static", "home", "login", "predict", "honeypot"}
    if ip in blacklist and endpoint not in allowed:
        return render_template("honeypot.html", ip=ip)

# === Routes ===
@app.route("/", endpoint="home")
def home():
    return render_template("home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == DEVELOPER_PASSWORD:
            session["developer_logged_in"] = True
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="❌ Incorrect password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("developer_logged_in", None)
    return redirect(url_for("home"))

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        url = (data.get("url", "") if data else "").strip()
        ip = request.remote_addr

        if not url:
            return jsonify({"result": "Error: No URL provided", "honeypot": "clear"})

        import tldextract
        ext = tldextract.extract(url)
        domain = ext.registered_domain.lower()

        trusted_domains = {
            "chat.openai.com", "chatgpt.com", "openai.com",
            "google.com", "github.com", "microsoft.com", "stackoverflow.com"
        }
        if domain in trusted_domains:
            return jsonify({"result": "Legitimate", "honeypot": "clear"})

        if model is not None:
            try:
                features = extract_features(url)
                pred = model.predict(features)[0]
                result = "Phishing" if int(pred) == 1 else "Legitimate"
            except Exception as e:
                print("Model error:", e)
                result = "Legitimate" if url.startswith("https") else "Phishing"
        else:
            result = "Legitimate" if url.startswith("https") else "Phishing"

        if result == "Phishing":
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            append_log_line(HONEYPOT_LOG, f"{timestamp} | {ip} | {url}")
            blacklist.add(ip)
            atomic_write_json(BLACKLIST_FILE, list(blacklist))
            send_email_alert(ip, url)
            return jsonify({"result": result, "honeypot": "activated"})
        else:
            return jsonify({"result": result, "honeypot": "clear"})

    except Exception as e:
        return jsonify({"result": f"Error: {e}", "honeypot": "clear"})

@app.route("/dashboard")
def dashboard():
    if not session.get("developer_logged_in"):
        return render_template("access_denied.html"), 403

    entries = parse_honeypot_log()
    total = len(entries)
    unique_ips = len(set(e["ip"] for e in entries))
    last_attack = entries[0]["timestamp"] if entries else "N/A"
    last_alert = get_last_alert_time()

    return render_template("dashboard.html",
                           entries=entries[:100],
                           total=total,
                           unique_ips=unique_ips,
                           last_attack=last_attack,
                           last_alert=last_alert)

@app.route("/honeypot")
def honeypot():
    return render_template("honeypot.html", ip=request.remote_addr)

@app.route("/download_logs")
def download_logs():
    entries = parse_honeypot_log()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "ip", "url"])
    for e in entries:
        writer.writerow([e["timestamp"], e["ip"], e["url"]])
    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    mem.seek(0)
    filename = f"honeypot_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(mem, mimetype="text/csv", download_name=filename, as_attachment=True)

@app.route("/clear_logs", methods=["POST"])
def clear_logs():
    open(HONEYPOT_LOG, "w", encoding="utf-8").close()
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(debug=True)
