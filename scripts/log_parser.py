import json
import re
from datetime import datetime

LOG_FILE = "logs/sample_logs.json"
ALERT_FILE = "reports/alerts.txt"

SUSPICIOUS_PATTERNS = [
    r"failed login",
    r"unauthorized access",
    r"root login attempt",
    r"sql injection",
    r"malware detected",
]

def load_logs():
    with open(LOG_FILE, "r") as f:
        return json.load(f)

def match_threats(log_entry):
    text = log_entry.get("message", "").lower()
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text):
            return True
    return False

def write_alert(entry):
    with open(ALERT_FILE, "a") as f:
        timestamp = datetime.now().isoformat()
        f.write(f"[{timestamp}] ALERT: {entry['message']}\n")

def main():
    logs = load_logs()
    for entry in logs:
        if match_threats(entry):
            write_alert(entry)
    print("Analysis completed. Check reports/alerts.txt")

if __name__ == "__main__":
    main()
