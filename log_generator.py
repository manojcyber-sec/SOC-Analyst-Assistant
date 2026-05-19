import json
import random
from datetime import datetime, timedelta

def generate_logs(count=50):
    event_types = [
        {"event_id": "4625", "type": "Failed Login", "severity": "Medium"},
        {"event_id": "4624", "type": "Successful Login", "severity": "Low"},
        {"event_id": "4740", "type": "Account Lockout", "severity": "High"},
        {"event_id": "4720", "type": "New User Created", "severity": "High"},
        {"event_id": "4688", "type": "Process Started", "severity": "Low"},
        {"event_id": "4648", "type": "Login With Explicit Credentials", "severity": "High"},
    ]

    usernames = ["admin", "john.doe", "jane.smith", "guest", "root", "administrator"]

    ips = [
        "185.220.101.45",
        "192.168.1.10",
        "45.33.32.156",
        "103.21.244.0",
        "192.168.1.105",
        "91.108.4.0",
        "10.0.0.5",
        "198.51.100.23"
    ]

    logs = []
    base_time = datetime.now()

    for i in range(count):
        event = random.choice(event_types)
        log = {
            "id": i + 1,
            "timestamp": (base_time - timedelta(minutes=random.randint(0, 120))).strftime("%Y-%m-%d %H:%M:%S"),
            "event_id": event["event_id"],
            "type": event["type"],
            "severity": event["severity"],
            "source_ip": random.choice(ips),
            "username": random.choice(usernames),
            "status": "Open"
        }
        logs.append(log)

    logs.sort(key=lambda x: x["timestamp"], reverse=True)
    return logs

if __name__ == "__main__":
    logs = generate_logs()
    with open("data/alerts.json", "w") as f:
        json.dump(logs, f, indent=2)
    print(f"Generated {len(logs)} alerts successfully.")