import subprocess, sys, os, time, webbrowser

os.makedirs("logs", exist_ok=True)

print("🛡️  Starting TrustUrDevice...")

# Start file watcher
file_watcher = subprocess.Popen(
    [sys.executable, "file_watcher.py"],
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL
)
print("✅ File system watcher running")

# Start log simulator
simulator = subprocess.Popen(
    [sys.executable, "log_simulator.py"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)
print("✅ System log monitor running")

time.sleep(3)

print("✅ Launching dashboard...")
webbrowser.open("http://localhost:8501")

streamlit = subprocess.Popen(
    ["streamlit", "run", "app.py", "--server.headless=true"],
)

try:
    streamlit.wait()
except KeyboardInterrupt:
    print("\n🛑 Shutting down TrustUrDevice...")
    file_watcher.terminate()
    simulator.terminate()
    streamlit.terminate()