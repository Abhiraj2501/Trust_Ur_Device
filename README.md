#  TrustUrDevice

**Privacy-First, On-Device AI Cybersecurity Assistant**

> Detects threats before you act. Explains why. Keeps your data local.

---

## What it does

TrustUrDevice is a background AI agent that monitors system activity in 
real-time — emails, files, processes, network events — and alerts you 
before you interact with a threat. Every alert comes with a plain-English 
explanation and a digital hygiene tip.

No data leaves your machine. Ever.

---

## Features

- Real-time phishing detection on incoming emails
- Static malware analysis on files before execution
- Process & network monitoring for suspicious activity
- Explainable alerts — not just a red flag, but a reason
- Digital hygiene guidance to stop repeat mistakes
- 100% on-device — no cloud, no API calls, works air-gapped

---

## Tech Stack

- Python, PyTorch, Scikit-learn
- ChromaDB (vector database for RAG threat intelligence)
- Sentence-transformers (local embeddings)
- Ollama + Mistral 7B (local LLM inference)
- Streamlit (prototype UI)
- pefile, watchdog, psutil (system monitoring)
- AMD ROCm (GPU acceleration)

---

## Run it locally
```bash
# Terminal 1 — start the event simulator
python log_simulator.py

# Terminal 2 — launch the dashboard
streamlit run app.py
```

---

## Project Structure
```
TrustUrDevice/
├── app.py              # Main Streamlit dashboard
├── log_simulator.py    # System event simulator
├── threat_analyzer.py  # AI threat analysis engine
└── logs/               # Runtime log storage (gitignored)
```

---

Built for AMD Slingshot Hackathon 2026
