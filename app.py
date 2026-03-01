'''app.py - Main Streamlit application for TrustUrDevice'''
import streamlit as st
import time, os, json
from threat_analyzer import analyze_log_line
from phishing_detector import analyze_email
from file_scanner import scan_file
import tempfile

st.set_page_config(
    page_title="TrustUrDevice",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

LOG_PATH = "logs/system_events.json"
COLORS = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}

# -------------------------------
# Utilities
# -------------------------------

def load_recent_events(n=3):
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, "r") as f:
        lines = f.readlines()
    events = []
    for line in lines[-n:]:
        try:
            events.append(json.loads(line))
        except:
            continue
    return events

def calculate_risk(analyzed):
    score = 0
    for e in analyzed:
        if e["level"] == "HIGH":
            score += 3
        elif e["level"] == "MEDIUM":
            score += 2
        else:
            score += 1
    return score

# -------------------------------
# Sidebar
# -------------------------------

with st.sidebar:
    st.markdown("## 🛡️ TrustUrDevice")
    st.caption("Privacy-First AI Cybersecurity Assistant")
    st.divider()
    st.markdown("**Status**")
    st.success("🟢 Monitoring Active")
    refresh = st.slider("Refresh rate (seconds)", 2, 10, 4)
    auto_refresh = st.toggle("Live monitoring", value=True)
    st.divider()
    st.markdown("**Data Policy**")
    st.info("🔒 All analysis runs on-device.\nNo logs leave your machine.")

# -------------------------------
# Load + Analyze Logs
# -------------------------------

raw_events = load_recent_events(3)

# Fix: pass the event string to analyze_log_line, not the dict
analyzed = []
for e in raw_events:
    if not e:
        continue
    # Reconstruct the string format that analyze_log_line expects
    log_string = f"[{e['timestamp']}] [{e['level']}] [{e['category']}] {e['event']}"
    result = analyze_log_line(log_string)
    if result:
        analyzed.append(result)

highs = sum(1 for e in analyzed if e["level"] == "HIGH")
meds = sum(1 for e in analyzed if e["level"] == "MEDIUM")
lows = sum(1 for e in analyzed if e["level"] == "LOW")
risk_score = calculate_risk(analyzed)
high_alerts = [e for e in analyzed if e["level"] == "HIGH"]

# -------------------------------
# Header
# -------------------------------

st.title("🛡️ TrustUrDevice — System Threat Monitor")
st.caption("Explainable, on-device AI threat detection")

if highs > 3:
    st.warning(f"⚠️ {highs} high-severity threats detected this session.")
elif highs == 0:
    st.success("✅ No high-severity threats detected.")

# -------------------------------
# Tabs
# -------------------------------

tab1, tab2, tab3 = st.tabs(["📊 Live Monitor", "📧 Email Scanner", "📁 File Scanner"])

# ===============================
# TAB 1 — LIVE MONITOR
# ===============================

with tab1:

    # HIGH THREAT BANNER
    if high_alerts:
        latest = high_alerts[-1]
        st.error(f"""
🚨 HIGH THREAT DETECTED

Event: {latest['event']}

Action: {latest['profile']['action']}
""")

    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown("### 📋 Live Event Feed")
        if not analyzed:
            st.info("Waiting for system events...")
        else:
            for ev in reversed(analyzed[-8:]):
                icon = COLORS.get(ev["level"], "⚪")
                st.markdown(f"{icon} `{ev['timestamp']}` — {ev['event']}")

    with col2:
        st.markdown("### 📊 Session Summary")
        st.metric("🔴 High Threats", highs)
        st.metric("🟡 Medium Alerts", meds)
        st.metric("🟢 Low / Normal", lows)
        st.metric("⚠️ Risk Score", risk_score)

        if risk_score > 25:
            st.error("🔴 CRITICAL RISK")
        elif risk_score > 15:
            st.warning("🟡 GUARDED")
        else:
            st.success("🟢 LOW RISK")

    st.divider()
    st.markdown("### 🔍 Threat Analysis")

    threats = [e for e in analyzed if e["level"] in ["HIGH", "MEDIUM"]]

    if not threats:
        st.success("No active threats in recent events.")
    else:
        for ev in reversed(threats[:5]):
            p = ev["profile"]
            with st.expander(
                f"{COLORS[ev['level']]} {p['title']} — {ev['timestamp']}",
                expanded=(ev["level"] == "HIGH")
            ):
                st.markdown(f"**Event:** `{ev['event']}`")
                st.divider()
                st.markdown(f"**What's happening:** {p['explanation']}")
                st.markdown(f"**What to do:** {p['action']}")
                st.info(f"💡 Digital Hygiene Tip: {p['hygiene_tip']}")

    # Threat History
    st.divider()
    st.markdown("### 📜 Threat History — This Session")
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r") as f:
            all_lines = f.readlines()
        high_events = []
        for line in all_lines:
            try:
                entry = json.loads(line)
                if entry.get("level") == "HIGH":
                    high_events.append(entry)
            except:
                continue
        if high_events:
            for entry in reversed(high_events[-10:]):
                st.error(f"[{entry['timestamp']}] {entry['event']}")
        else:
            st.success("No high-severity events recorded this session.")

# ===============================
# TAB 2 — EMAIL SCANNER
# ===============================

with tab2:
    st.markdown("### 📧 Email Threat Scanner")
    sender = st.text_input("Sender Email")
    subject = st.text_input("Subject Line")
    body = st.text_area("Email Body", height=200)

    if st.button("Analyse Email"):
        if body or subject:
            risk, flags, score = analyze_email(subject, body, sender)
            st.markdown(f"## {COLORS[risk]} Threat Level: **{risk}**")
            if not flags:
                st.success("No suspicious signals detected.")
            else:
                st.markdown("### Why this was flagged:")
                for category, trigger in flags:
                    st.warning(f"{category} → triggered by '{trigger}'")
                st.markdown("### 💡 What you should do:")
                if risk == "HIGH":
                    st.error("Do not click any links. Do not reply. Report as phishing and delete.")
                elif risk == "MEDIUM":
                    st.warning("Verify the sender through a different channel before acting.")

# ===============================
# TAB 3 — FILE SCANNER
# ===============================

with tab3:
    st.markdown("### 📁 File Threat Scanner")
    uploaded = st.file_uploader(
        "Upload a file to scan",
        type=['exe', 'dll', 'pdf', 'docx', 'bat', 'ps1', 'zip']
    )

    if uploaded:
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded.name)[1]) as f:
            f.write(uploaded.read())
            tmppath = f.name

        risk, flags, score = scan_file(tmppath)
        st.markdown(f"## {COLORS[risk]} Threat Level: **{risk}**")

        if not flags:
            st.success("No threats detected.")
        else:
            st.markdown("### Why this was flagged:")
            for category, detail in flags:
                st.warning(f"{category} → {detail}")

        os.unlink(tmppath)

# -------------------------------
# Live Refresh
# -------------------------------

if auto_refresh:
    time.sleep(refresh)
    st.rerun()