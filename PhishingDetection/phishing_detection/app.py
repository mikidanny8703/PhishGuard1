from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session, Response
)
from datetime import datetime
import io, csv, json, os

app = Flask(__name__)
app.secret_key = "phishguard_secret_key"

# ============================
# File paths
# ============================
BLACKLIST_FILE = "blacklist.json"

# ============================
# Helper functions
# ============================
def load_blacklist():
    """Load blacklist.json file into memory"""
    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "w") as f:
            json.dump([], f)
        return []
    with open(BLACKLIST_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def save_blacklist(data):
    """Save current blacklist to file"""
    with open(BLACKLIST_FILE, "w") as f:
        json.dump(data, f, indent=4)


def get_client_ip():
    """Get client IP address safely"""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0]
    return request.remote_addr or "unknown"


def next_log_id():
    """Generate incremental log ID"""
    return len(logs) + 1


def is_ip_blacklisted(ip):
    """Check if IP is in blacklist.json"""
    blacklist = load_blacklist()
    return any(entry.get("ip") == ip for entry in blacklist)


def add_to_blacklist(ip, url):
    """Add a new entry to blacklist.json"""
    blacklist = load_blacklist()
    if not any(entry.get("ip") == ip for entry in blacklist):
        blacklist.append({
            "ip": ip,
            "url": url,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        save_blacklist(blacklist)

# ============================
# Mock data (in-memory logs)
# ============================
logs = []


# ============================
# Routes
# ============================
@app.route("/")
@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/features")
def features():
    return render_template("features.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/faq")
def faq():
    return render_template("faq.html")


@app.route("/settings")
def settings():
    return render_template("settings.html")


@app.route("/demo")
def demo():
    return render_template("demo.html")


@app.route("/access-denied")
def access_denied():
    # Make sure your file is named `accessdenied.html` (no underscore)
    return render_template("access_denied.html")


# ============================
# Developer authentication
# ============================
@app.route("/login", methods=["GET", "POST"])
def login():
    ip = get_client_ip()
    if is_ip_blacklisted(ip):
        return redirect(url_for("access_denied"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == "admin" and password == "123":
            session["developer"] = True
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Invalid username or password")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("developer", None)
    return redirect(url_for("home"))


# ============================
# Dashboard
# ============================
@app.route("/dashboard")
def dashboard():
    if not session.get("developer"):
        return redirect(url_for("login"))
    blacklist = load_blacklist()
    return render_template("dashboard.html", entries=logs, blacklist=blacklist)


@app.route("/delete_log/<int:log_id>", methods=["POST"])
def delete_log(log_id):
    global logs
    logs = [l for l in logs if l["id"] != log_id]
    return jsonify({"success": True})


@app.route("/delete_all_logs", methods=["POST"])
def delete_all_logs():
    logs.clear()
    return jsonify({"success": True})


@app.route("/download_logs")
def download_logs():
    """Allow downloading all logs as CSV"""
    csv_output = io.StringIO()
    writer = csv.writer(csv_output)
    writer.writerow(["Timestamp", "IP", "URL", "Status"])
    for entry in logs:
        writer.writerow([entry["time"], entry["ip"], entry["url"], entry["status"]])

    return Response(
        csv_output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=train_80.csv"}
    )


@app.route("/live-dashboard")
def live_dashboard():
    return render_template("livedashboard.html")


# ============================
# Prediction & Blacklisting
# ============================
@app.route("/predict", methods=["POST"])
def predict():
    global latest_threat  # make available globally for live dashboard use

    data = request.get_json() or {}
    url = data.get("url", "").strip()
    ip = get_client_ip()

    if not url:
        return jsonify({"result": "Error", "detail": "Missing URL"})

    # ====== Simple phishing keyword detection logic ======
    phishing_keywords = ["phish", "login", "bank", "verify", "account", "secure", "update"]
    is_phish = any(k in url.lower() for k in phishing_keywords)
    result = "Phishing" if is_phish else "Legitimate"

    # ====== Save to logs list ======
    log_entry = {
        "id": next_log_id(),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "url": url,
        "status": result
    }
    logs.append(log_entry)

    # ====== If phishing detected, add to blacklist ======
    if is_phish:
        add_to_blacklist(ip, url)

    # ====== Store latest threat for dashboard use ======
    latest_threat = {
        "ip": ip,
        "url": url,
        "result": result,
        "time": datetime.now().strftime("%H:%M:%S")
    }

    print("🔴 Latest Threat Updated:", latest_threat)

    # ====== Return both prediction and latest threat ======
    return jsonify({
        "result": result,
        "latest_threat": latest_threat
    })


@app.route("/get_latest_threat")
def get_latest_threat():
    """Route yang dashboard akan panggil setiap 3 saat"""
    return jsonify(latest_threat)


@app.route("/view_blacklist")
def view_blacklist():
    """Return current blacklist as JSON"""
    blacklist = load_blacklist()
    return jsonify({"blacklist": blacklist})


# ============================
# Run server
# ============================
if __name__ == "__main__":
    app.run(debug=True)
