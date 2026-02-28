import streamlit as st
import time, os
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

LOG_PATH = "logs/system_events.log"
COLORS = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}

def load_recent_events(n=15):
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, "r") as f:
        lines = f.readlines()
    return [l.strip() for l in lines[-n:] if l.strip()]

# --- Calculate highs FIRST before sidebar references it ---
events = load_recent_events(15)
analyzed = [analyze_log_line(e) for e in events]
highs = sum(1 for e in analyzed if e["level"] == "HIGH")
meds = sum(1 for e in analyzed if e["level"] == "MEDIUM")
lows = sum(1 for e in analyzed if e["level"] == "LOW")

# --- Sidebar ---
with st.sidebar:
    st.markdown("## 🛡️ TrustUrDevice")
    st.caption("Privacy-First AI Cybersecurity Assistant")
    st.divider()
    st.markdown("**Status**")
    st.success("🟢 Monitoring Active")
    st.divider()
    st.markdown("### 🔴 Threats Blocked")
    st.markdown(f"# {highs}")
    st.caption("This session")
    st.divider()
    st.markdown("**Data Policy**")
    st.info("🔒 All analysis runs on-device.\nNo logs or events leave your machine.")
    st.divider()
    refresh = st.slider("Refresh rate (seconds)", 2, 10, 4)
    auto_refresh = st.toggle("Live monitoring", value=True)

# --- Status bar ---
if highs > 3:
    st.warning(f"⚠️ {highs} high-severity threats detected this session. Review alerts below.")
elif highs == 0:
    st.success("✅ System clean — no high-severity threats detected.")

st.title("🛡️ TrustUrDevice — System Threat Monitor")
st.caption("Monitoring system events in real-time. Explainable alerts. No data leaves this machine.")
st.divider()

# --- Tabs ---
tab1, tab2, tab3 = st.tabs(["📊 Live Monitor", "📧 Email Scanner", "📁 File Scanner"])

# ==================== TAB 1 — LIVE MONITOR ====================
with tab1:
    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown("### 📋 Live Event Feed")
        feed_placeholder = st.empty()

    with col2:
        st.markdown("### 📊 Session Summary")
        summary_placeholder = st.empty()

    st.divider()
    st.markdown("### 🔍 Threat Analysis")
    analysis_placeholder = st.empty()

    st.divider()
    st.markdown("### 📜 Threat History — This Session")
    history_placeholder = st.empty()

    while True:
        events = load_recent_events(15)
        analyzed = [analyze_log_line(e) for e in events]

        highs = sum(1 for e in analyzed if e["level"] == "HIGH")
        meds = sum(1 for e in analyzed if e["level"] == "MEDIUM")
        lows = sum(1 for e in analyzed if e["level"] == "LOW")

        # Event feed
        with feed_placeholder.container():
            for ev in reversed(analyzed[-8:]):
                icon = COLORS.get(ev["level"], "⚪")
                st.markdown(f"{icon} `{ev['timestamp']}` — {ev['event']}")

        # Summary metrics
        with summary_placeholder.container():
            st.metric("🔴 High Threats", highs)
            st.metric("🟡 Medium Alerts", meds)
            st.metric("🟢 Low / Normal", lows)

        # Threat analysis cards
        with analysis_placeholder.container():
            threats = [e for e in reversed(analyzed) if e["level"] in ["HIGH", "MEDIUM"] and e["profile"]]
            if not threats:
                st.success("No active threats in recent events.")
            else:
                for ev in threats[:5]:
                    p = ev["profile"]
                    with st.expander(f"{COLORS[ev['level']]} {p['title']} — {ev['timestamp']}", expanded=(ev['level'] == 'HIGH')):
                        st.markdown(f"**Event:** `{ev['event']}`")
                        st.divider()
                        st.markdown(f"**What's happening:** {p['explanation']}")
                        st.markdown(f"**What to do:** {p['action']}")
                        st.info(f"💡 Digital Hygiene Tip: {p['hygiene_tip']}")

        # Threat history
        with history_placeholder.container():
            if os.path.exists(LOG_PATH):
                with open(LOG_PATH, "r") as f:
                    all_lines = f.readlines()
                high_events = [l.strip() for l in all_lines if "[HIGH]" in l]
                if high_events:
                    for event in reversed(high_events[-10:]):
                        st.error(event)
                else:
                    st.success("No high-severity events recorded this session.")

        if not auto_refresh:
            st.stop()

        time.sleep(refresh)

# ==================== TAB 2 — EMAIL SCANNER ====================
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
                st.success("No suspicious signals detected. This email looks clean.")
            else:
                st.markdown("### Why this was flagged:")
                for category, trigger in flags:
                    with st.expander(f"⚠️ {category.replace('_', ' ').title()} — triggered by: *'{trigger}'*"):
                        from threat_analyzer import THREAT_PROFILES
                        profile = THREAT_PROFILES.get(category, {})
                        st.write(profile.get("explanation", "Suspicious pattern detected."))

                st.markdown("### 💡 What you should do:")
                if risk == "HIGH":
                    st.error("Do not click any links. Do not reply. Report as phishing and delete.")
                elif risk == "MEDIUM":
                    st.warning("Proceed with caution. Verify the sender through a different channel.")

# ==================== TAB 3 — FILE SCANNER ====================
with tab3:
    st.markdown("### 📁 File Threat Scanner")
    uploaded = st.file_uploader("Upload a file to scan", type=['exe', 'dll', 'pdf', 'docx', 'bat', 'ps1', 'zip'])

    if uploaded:
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded.name)[1]) as f:
            f.write(uploaded.read())
            tmppath = f.name

        risk, flags, score = scan_file(tmppath)
        st.markdown(f"## {COLORS[risk]} Threat Level: **{risk}**")

        if not flags:
            st.success("No threats detected in this file.")
        else:
            st.markdown("### Why this was flagged:")
            for category, detail in flags:
                with st.expander(f"⚠️ {detail}"):
                    from threat_analyzer import THREAT_PROFILES
                    profile = THREAT_PROFILES.get(category, {})
                    st.write(profile.get("explanation", "Suspicious pattern detected."))

        os.unlink(tmppath)