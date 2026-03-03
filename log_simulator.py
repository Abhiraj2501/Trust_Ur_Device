import subprocess, time, datetime, os, json

os.makedirs("logs", exist_ok=True)

def send_mac_notification(title, message):
    script = f'display notification "{message}" with title "{title}" sound name "Basso"'
    subprocess.run(["osascript", "-e", script])

send_mac_notification(
    "🛡️ TrustUrDevice",
    "Real-time monitoring active — watching your system"
)

WHITELIST = [
    "imagent", "com.apple.contacts", "com.apple.coredata",
    "NSCocoaErrorDomain", "com.apple.tiswitcher", "com.apple.cloudd",
    "CloudKitDaemon", "com.apple.icloud", "com.apple.windowserver",
    "com.apple.coreaudio", "com.apple.bluetooth", "com.apple.AppleLOM",
    "WirelessProximity", "bluetoothd", "runningboardd", "memorystatus",
    "com.apple.libxpc", "OSLaunchd", "com.apple.runningboard",
    "NSPOSIXErrorDomain", "com.apple.xpc", "springboard",
    "com.apple.cfnetwork", "symptom", "networkd", "trustd",
    "com.apple.security", "sharingd", "com.apple.safari",
    "com.apple.webkit", "com.apple.appkit", "com.apple.foundation",
    "chronod", "dasd", "mds", "mdworker", "com.apple.spotlight",
    "coreauthd", "com.apple.authkit", "com.apple.systempreferences",
    "com.apple.dock", "com.apple.finder", "com.apple.mail","com.apple.bird",
    "XProtectBridge",
    "xprotect",
    "com.apple.AssetCache",
    "cloudd",
    "com.apple.mmcs",
]

def is_whitelisted(line):
    return any(w.lower() in line.lower() for w in WHITELIST)

def fetch_real_logs():
    try:
        result = subprocess.run([
            "log", "show",
            "--last", "1m",
            "--style", "syslog",
            "--predicate",
            'eventMessage CONTAINS "denied" OR '
            'eventMessage CONTAINS "failed" OR '
            'eventMessage CONTAINS "unauthorized" OR '
            'eventMessage CONTAINS "malicious" OR '
            'eventMessage CONTAINS "blocked" OR '
            'eventMessage CONTAINS "suspicious" OR '
            'eventMessage CONTAINS "permission" OR '
            'eventMessage CONTAINS "sandbox" OR '
            'eventMessage CONTAINS "error" OR '
            'eventMessage CONTAINS "exploit" OR '
            'eventMessage CONTAINS "injection"'
        ], capture_output=True, text=True, timeout=15)

        lines = result.stdout.strip().split("\n")
        return [l for l in lines if l.strip() and not l.startswith("Filtering")]
    except Exception as e:
        print(f"Log fetch error: {e}")
        return []

last_notification_time = 0
seen_lines = set()

print("🟢 TrustUrDevice — Real log monitoring started")
print("📡 Pulling live macOS system events every 30 seconds...\n")

while True:
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Fetching real system logs...")

    real_logs = fetch_real_logs()
    new_lines = [l for l in real_logs if l not in seen_lines]

    if new_lines:
        print(f"  → {len(new_lines)} new events found")

        for line in new_lines[-10:]:
            if is_whitelisted(line):
                print(f"  → [SAFE] Whitelisted, skipping")
                seen_lines.add(line)
                continue

            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            line_lower = line.lower()

            if any(w in line_lower for w in ["denied", "unauthorized", "exploit", "injection", "malicious", "rootkit", "backdoor"]):
                level = "HIGH"
            elif any(w in line_lower for w in ["failed", "blocked", "sandbox violation", "permission denied"]):
                level = "MEDIUM"
            else:
                level = "LOW"

            log_entry = {
                "timestamp": timestamp,
                "level": level,
                "category": "system",
                "event": line.strip(),
                "source": "macos_system_log"
            }

            with open("logs/system_events.json", "a") as f:
                f.write(json.dumps(log_entry) + "\n")

            print(f"  → [{level}] {line[:80]}...")
            seen_lines.add(line)

            current_time = time.time()
            if level == "HIGH" and (current_time - last_notification_time) > 30:
                send_mac_notification(
                    "⚠️ TrustUrDevice — Threat Detected",
                    line[:100]
                )
                last_notification_time = current_time
    else:
        print("  → No new suspicious events. System looks clean.")

    time.sleep(30)