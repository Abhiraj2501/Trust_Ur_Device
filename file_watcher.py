'''file_watcher.py - Real-time file system monitoring'''
import time, json, datetime, os, subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

os.makedirs("logs", exist_ok=True)

SENSITIVE_PATHS = [
    "/etc/hosts", "/etc/passwd", "/etc/sudoers",
    "/private/etc", os.path.expanduser("~/.ssh"),
    os.path.expanduser("~/Library/Keychains"),
]

SUSPICIOUS_DIRS = ["/private/tmp", "/private/var/tmp", os.path.expanduser("~/Downloads")]
def send_mac_notification(title, message):
    script = f'display notification "{message}" with title "{title}" sound name "Basso"'
    subprocess.run(["osascript", "-e", script])

def log_event(level, category, event_text):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": timestamp,
        "level": level,
        "category": category,
        "event": event_text,
        "source": "file_watcher"
    }
    with open("logs/system_events.json", "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"  → [{level}] {event_text[:80]}")

    if level == "HIGH":
        send_mac_notification("⚠️ TrustUrDevice — File Threat", event_text[:100])

class ThreatFileHandler(FileSystemEventHandler):

    def on_modified(self, event):
        if event.is_directory:
            return
        path = event.src_path

        # Sensitive system file accessed
        if any(path.startswith(s) for s in SENSITIVE_PATHS):
            log_event("HIGH", "system_file_access",
                f"Sensitive file modified: {path}")

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path

        # Executable created in suspicious location
        if any(path.startswith(d) for d in SUSPICIOUS_DIRS):
            if path.endswith(('.sh', '.py', '.rb', '.exe', '.bin', '.dmg')):
                log_event("HIGH", "malware_execution",
                    f"Suspicious executable created in {os.path.dirname(path)}: {os.path.basename(path)}")
            else:
                log_event("MEDIUM", "suspicious_file_access",
                    f"New file created in suspicious directory: {path}")

        # Script created anywhere in home dir
        if path.startswith(os.path.expanduser("~")) and path.endswith(('.sh', '.bash')):
            log_event("MEDIUM", "suspicious_file_access",
                f"Shell script created: {path}")

    def on_deleted(self, event):
        if event.is_directory:
            return
        # Mass deletion could indicate ransomware
        pass

def start_file_watcher():
    watch_paths = [
        "/private/etc",
        "/private/tmp",      # ← was /tmp
        "/private/var/tmp",  # ← was /var/tmp
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/.ssh"),
    ]

    observer = Observer()
    handler = ThreatFileHandler()

    for path in watch_paths:
        if os.path.exists(path):
            observer.schedule(handler, path, recursive=True)
            print(f"  👁 Watching: {path}")

    observer.start()
    print("🟢 File system watcher active")
    return observer

if __name__ == "__main__":
    print("🛡️ TrustUrDevice — File System Monitor")
    observer = start_file_watcher()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()