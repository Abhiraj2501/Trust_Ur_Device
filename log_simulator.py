'''log_simulator.py - Simulates system events for testing'''
import time, random, datetime, os, subprocess

os.makedirs("logs", exist_ok=True)

def send_mac_notification(title, message):
    script = f'display notification "{message}" with title "{title}" sound name "Basso"'
    subprocess.run(["osascript", "-e", script])

send_mac_notification(
    "🛡️ TrustUrDevice",
    "Monitoring active — system protection is running"
)

EVENTS = [
    ("com.apple.Safari launched by user", "LOW", "browser"),
    ("Spotify.app accessed microphone", "MEDIUM", "permission"),
    ("Unknown process 'updater_x86' requested admin privileges", "HIGH", "privilege_escalation"),
    ("Incoming email from paypal-secure@paypal-update.net", "HIGH", "phishing"),
    ("Installation package 'AdobeFlash.dmg' downloaded from 185.220.101.34", "HIGH", "malware"),
    ("Chrome extension installed: ID=unknown, source=third-party", "MEDIUM", "browser_hijack"),
    ("System update check from apple.com", "LOW", "system"),
    ("Python script accessed /etc/hosts file", "HIGH", "suspicious_file_access"),
    ("Pop-up notification: 'Your Mac is infected! Click to clean'", "HIGH", "scareware"),
    ("Zoom.app accessed camera", "LOW", "permission"),
    ("Unknown binary executed from /tmp/install.sh", "HIGH", "malware"),
    ("DNS query to known malicious domain: track-metrics-cdn.ru", "HIGH", "c2_communication"),
    ("iCloud backup completed successfully", "LOW", "system"),
    ("New login attempt: root@localhost via SSH", "HIGH", "unauthorized_access"),
]

print("🟢 Log simulator running... generating events every 4 seconds")

last_notification_time = 0

while True:
    event, level, category = random.choice(EVENTS)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{level}] [{category}] {event}\n"

    with open("logs/system_events.log", "a") as f:
        f.write(line)

    # Only notify once every 30 seconds
    current_time = time.time()
    if level == "HIGH" and (current_time - last_notification_time) > 30:
        send_mac_notification(
            "⚠️ TrustUrDevice — Threat Detected",
            event
        )
        last_notification_time = current_time

    print(f"  → logged: {line.strip()}")
    time.sleep(8)