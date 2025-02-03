from flask import Flask, request, jsonify, render_template
import re
import time
import json
from collections import defaultdict

app = Flask(__name__)

# Rate limiting settings
RATE_LIMIT = 10  # Max requests per window
TIME_WINDOW = 60  # Time window in seconds
request_counts = defaultdict(lambda: [0, time.time()])
blocked_ips = set()
LOG_FILE = "waf_logs.json"

# Common attack patterns
SQLI_PATTERNS = [
    r"(?i)(union.*select|select.*from|insert.*into|drop\s+table|update.*set|delete.*from|--|#|\\*|\bOR\b|\bAND\b)"
]
XSS_PATTERNS = [r"(?i)<script.*?>.*?</script.*?>", r"(?i)onerror=", r"(?i)onload="]
BAD_USER_AGENTS = ["sqlmap", "nmap", "curl", "badbot"]

def log_attack(ip, attack_type, request_data):
    log_entry = {"ip": ip, "attack_type": attack_type, "data": request_data, "timestamp": time.time()}
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def is_sql_injection(data):
    return any(re.search(pattern, data) for pattern in SQLI_PATTERNS)

def is_xss_attack(data):
    return any(re.search(pattern, data) for pattern in XSS_PATTERNS)

def is_bad_user_agent(user_agent):
    return any(bot in user_agent.lower() for bot in BAD_USER_AGENTS)

def rate_limit(ip):
    count, start_time = request_counts[ip]
    if time.time() - start_time > TIME_WINDOW:
        request_counts[ip] = [1, time.time()]
        return False
    if count >= RATE_LIMIT:
        return True
    request_counts[ip][0] += 1
    return False

@app.before_request
def waf_middleware():
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "").lower()
    request_data = request.args.to_dict() or request.form.to_dict()
    
    if ip in blocked_ips:
        return render_template("error.html", error="Your IP has been permanently blocked!"), 403
    
    if rate_limit(ip):
        return render_template("error.html", error="Too many requests. Slow down!"), 429
    
    if is_bad_user_agent(user_agent):
        log_attack(ip, "Bad Bot", request_data)
        return render_template("error.html", error="Access denied: Suspicious bot detected!"), 403
    
    for key, value in request_data.items():
        if is_sql_injection(value):
            log_attack(ip, "SQL Injection", request_data)
            blocked_ips.add(ip)
            return render_template("error.html", error="SQL Injection attempt detected! Your IP has been blocked."), 403
        if is_xss_attack(value):
            log_attack(ip, "XSS Attack", request_data)
            return render_template("error.html", error="XSS Attack detected!"), 403

@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
