import subprocess, sys, os, time, webbrowser

os.makedirs("logs", exist_ok=True)

print("🛡️  Starting TrustUrDevice...")

# Start the log simulator in background
simulator = subprocess.Popen(
    [sys.executable, "log_simulator.py"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

print("✅ Threat monitor running")
time.sleep(2)  # Give simulator a head start

# Launch Streamlit
print("✅ Launching dashboard...")
time.sleep(1)
webbrowser.open("http://localhost:8501")

streamlit = subprocess.Popen(
    ["streamlit", "run", "app.py", "--server.headless=true"],
)

try:
    streamlit.wait()
except KeyboardInterrupt:
    print("\n🛑 Shutting down TrustUrDevice...")
    simulator.terminate()
    streamlit.terminate()