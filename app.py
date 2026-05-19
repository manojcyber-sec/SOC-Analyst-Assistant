from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
import json
import os
import sqlite3
from datetime import datetime
from functools import wraps
from investigator import investigate_ip
from ai_analyst import generate_ai_summary
from report_generator import generate_report
from windows_log_reader import get_real_windows_logs
from log_generator import generate_logs

app = Flask(__name__)
app.secret_key = 'soc-assistant-secret-2026'

USERS = {
    "admin": "soc@2026",
    "analyst": "analyst@2026"
}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/soc.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS investigations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT, alert_type TEXT, username TEXT, severity TEXT,
        threat_level TEXT, abuse_score INTEGER, vt_malicious INTEGER,
        country TEXT, ai_summary TEXT, timestamp TEXT, investigated_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT, type TEXT, severity TEXT, source_ip TEXT,
        username TEXT, computer TEXT, timestamp TEXT,
        status TEXT DEFAULT 'Open'
    )''')
    conn.commit()
    conn.close()

init_db()

def detect_brute_force(alerts):
    from collections import defaultdict
    ip_failures = defaultdict(list)
    for alert in alerts:
        if alert.get('event_id') == '4625':
            ip_failures[alert['source_ip']].append(alert['timestamp'])
    brute_force_ips = set()
    for ip, times in ip_failures.items():
        if len(times) >= 5:
            brute_force_ips.add(ip)
    upgraded = []
    seen_bf = set()
    for alert in alerts:
        if alert['source_ip'] in brute_force_ips and alert.get('event_id') == '4625':
            if alert['source_ip'] not in seen_bf:
                alert = dict(alert)
                alert['type'] = 'BRUTE FORCE DETECTED'
                alert['severity'] = 'Critical'
                alert['bf_count'] = len(ip_failures[alert['source_ip']])
                seen_bf.add(alert['source_ip'])
                upgraded.append(alert)
        else:
            upgraded.append(alert)
    return upgraded

def load_alerts():
    real_logs = get_real_windows_logs()
    if real_logs and len(real_logs) > 0:
        logs = detect_brute_force(real_logs)
        with open("data/alerts.json", "w") as f:
            json.dump(logs, f, indent=2)
        return logs
    path = "data/alerts.json"
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
        return detect_brute_force(data)
    logs = generate_logs()
    logs = detect_brute_force(logs)
    with open(path, "w") as f:
        json.dump(logs, f, indent=2)
    return logs

def save_investigation(ip, alert_data, result, ai_summary):
    abuse = result.get('abuseipdb', {})
    vt = result.get('virustotal', {})
    conn = sqlite3.connect("data/soc.db")
    c = conn.cursor()
    c.execute('''INSERT INTO investigations
        (ip, alert_type, username, severity, threat_level,
         abuse_score, vt_malicious, country, ai_summary, timestamp, investigated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
        (ip, alert_data.get('type','Unknown'), alert_data.get('username','Unknown'),
         alert_data.get('severity','Unknown'), result.get('threat_level','Unknown'),
         abuse.get('abuse_score',0), vt.get('malicious',0),
         abuse.get('country','Unknown'), ai_summary,
         alert_data.get('timestamp',''),
         datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def get_investigation_history():
    conn = sqlite3.connect("data/soc.db")
    c = conn.cursor()
    c.execute('SELECT * FROM investigations ORDER BY investigated_at DESC LIMIT 50')
    rows = c.fetchall()
    conn.close()
    return rows

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in USERS and USERS[username] == password:
            session['user'] = username
            return redirect(url_for('dashboard'))
        error = "Invalid credentials. Try again."
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    alerts = load_alerts()
    return render_template('dashboard.html',
        alerts=alerts,
        total=len(alerts),
        critical=len([a for a in alerts if a["severity"] == "Critical"]),
        high=len([a for a in alerts if a["severity"] == "High"]),
        medium=len([a for a in alerts if a["severity"] == "Medium"]),
        low=len([a for a in alerts if a["severity"] == "Low"]),
        user=session.get('user'))

@app.route('/api/alerts')
@login_required
def api_alerts():
    alerts = load_alerts()
    return jsonify({
        "alerts": alerts,
        "total": len(alerts),
        "critical": len([a for a in alerts if a["severity"] == "Critical"]),
        "high": len([a for a in alerts if a["severity"] == "High"]),
        "medium": len([a for a in alerts if a["severity"] == "Medium"]),
        "low": len([a for a in alerts if a["severity"] == "Low"])
    })

@app.route('/update_status', methods=['POST'])
@login_required
def update_status():
    data = request.get_json()
    alert_id = data.get('id')
    new_status = data.get('status')
    path = "data/alerts.json"
    if os.path.exists(path):
        with open(path, "r") as f:
            alerts = json.load(f)
        for alert in alerts:
            if str(alert.get('id')) == str(alert_id):
                alert['status'] = new_status
                break
        with open(path, "w") as f:
            json.dump(alerts, f, indent=2)
    return jsonify({"success": True})

@app.route('/ingest', methods=['POST'])
def ingest():
    data = request.get_json()
    logs = data.get('logs', [])
    if not logs:
        return jsonify({"error": "No logs provided"}), 400
    existing = []
    path = "data/alerts.json"
    if os.path.exists(path):
        with open(path, "r") as f:
            existing = json.load(f)
    for i, log in enumerate(logs):
        log['id'] = len(existing) + i + 1
        log['status'] = 'Open'
    existing = logs + existing
    with open(path, "w") as f:
        json.dump(existing[:200], f, indent=2)
    return jsonify({"success": True, "ingested": len(logs)})

@app.route('/investigate', methods=['POST'])
@login_required
def investigate():
    data = request.get_json()
    ip = data.get('ip')
    alert_data = data.get('alert', {})
    if not ip:
        return jsonify({"error": "No IP provided"})
    result = investigate_ip(ip)
    ai_summary = generate_ai_summary(alert_data, result)
    result['ai_summary'] = ai_summary
    save_investigation(ip, alert_data, result, ai_summary)
    return jsonify(result)

@app.route('/history')
@login_required
def history():
    rows = get_investigation_history()
    return jsonify([{
        "id": r[0], "ip": r[1], "alert_type": r[2],
        "username": r[3], "severity": r[4], "threat_level": r[5],
        "abuse_score": r[6], "vt_malicious": r[7],
        "country": r[8], "investigated_at": r[10]
    } for r in rows])

@app.route('/report', methods=['POST'])
@login_required
def report():
    data = request.get_json()
    filename = generate_report(
        data.get('alert', {}),
        data.get('investigation', {}),
        data.get('ai_summary', '')
    )
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)