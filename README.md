# TrustUrDevice
**Privacy-First, On-Device AI Cybersecurity Assistant**

> Detects threats before you act. Explains why. Keeps your data local.

---

## What it does

TrustUrDevice is a background AI agent that monitors your macOS system in real time across three layers — system logs, file system activity, and email content — and alerts you the moment something looks wrong.

Every alert includes a plain-English explanation of what happened, a recommended action, and a digital hygiene tip. No black-box "threat detected" messages.

No data leaves your machine. Ever.

---

## How it works

```
Real macOS System Logs + File System Events
              ↓
        Log Parser & Classifier
              ↓
     FAISS Vector Search (threat_kb)
     Matches event against known attack patterns
              ↓
     qwen2:1.5b via Ollama
     AI reasons with retrieved context — not blind guessing
              ↓
     Threat Classification  →  HIGH / MEDIUM / LOW
              ↓
     Dashboard Alert + Native macOS Notification
```

This is a RAG (Retrieval-Augmented Generation) pipeline — the LLM doesn't reason in a vacuum. It gets matched threat patterns from the knowledge base as context before generating a response.

---

## Features

- **Live system log monitoring** — pulls real macOS logs every 30 seconds, filters for security-relevant events
- **Real-time file system watcher** — instant detection when suspicious executables or scripts are created in sensitive directories
- **RAG-powered threat analysis** — FAISS vector search + local LLM reasoning grounded in a curated threat knowledge base
- **Phishing email classifier** — TF-IDF + Logistic Regression trained on 6,500 real messages, 98% accuracy, 0% false positive rate on safe emails
- **Static file scanner** — PE header analysis, entropy scoring, dangerous import detection
- **Explainable alerts** — every HIGH/MEDIUM event gets a reason, a recommended action, and a hygiene tip
- **Native macOS notifications** — fires immediately on HIGH severity events
- **100% on-device** — no cloud calls, no API keys, works fully air-gapped

---

## Tech Stack

| Layer | Technology |
|---|---|
| LLM inference | Ollama + qwen2:1.5b |
| Vector search | FAISS + sentence-transformers (all-MiniLM-L6-v2) |
| ML classifier | Scikit-learn — TF-IDF + Logistic Regression |
| System monitoring | macOS `log` CLI + watchdog |
| Static analysis | pefile |
| Dashboard | Streamlit |
| GPU acceleration | AMD ROCm |
# Required on macOS due to OpenMP conflict between PyTorch and sentence-transformers
export KMP_DUPLICATE_LIB_OK=TRUE
---

## Performance

| Metric | Result |
|---|---|
| Phishing detection accuracy | 98.01% |
| False positive rate (safe emails) | 0% |
| Phishing recall | 90% |
| F1-score (phishing class) | 0.94 |
| AI inference time per event | ~2–3 seconds |
| Log pull interval | 30 seconds |
| File system detection latency | Instant (event-driven) |

---

## Run it locally

**Prerequisites:** Python 3.13, [Ollama](https://ollama.com) installed

```bash
# Pull the LLM
ollama pull qwen2:1.5b

# Install dependencies
pip install streamlit sentence-transformers faiss-cpu watchdog scikit-learn pefile numpy ollama

# Terminal 1 — LLM server
ollama serve

# Terminal 2 — file system watcher
export KMP_DUPLICATE_LIB_OK=TRUE
python3 file_watcher.py

# Terminal 3 — system log monitor
python3 log_simulator.py

# Terminal 4 — dashboard
export KMP_DUPLICATE_LIB_OK=TRUE
streamlit run app.py
```

Dashboard runs at `http://localhost:8501`

---

## Project Structure

```
TrustUrDevice/
├── app.py                  # Streamlit dashboard (Live Monitor, Email Scanner, File Scanner)
├── log_simulator.py        # Real macOS log reader + event classifier
├── file_watcher.py         # Real-time file system threat detection
├── threat_analyzer.py      # Orchestrates RAG pipeline per event
├── rag_agent.py            # RAG pipeline — vector search + LLM reasoning
├── threat_kb.py            # FAISS knowledge base — embedded threat patterns
├── ai_agent.py             # Direct Ollama interface (fallback)
├── phishing_detector.py    # ML email classifier
├── file_scanner.py         # Static PE analysis
├── main.py                 # Single entry point (launches all processes)
├── model/
│   ├── phishing_model.pkl  # Trained Logistic Regression model
│   └── vectorizer.pkl      # TF-IDF vectorizer
├── threat_db/              # FAISS index + embedded threat patterns
└── logs/                   # Runtime event storage (gitignored)
```

---

## Threat Knowledge Base

The RAG pipeline reasons against a curated set of known attack patterns covering:

- Privilege escalation & sudo abuse
- Malware execution from temp directories
- C2 communication & DNS exfiltration
- Ransomware indicators (mass file modification)
- Credential theft via keychain access
- Phishing & browser hijacking
- SSH brute force & unauthorized remote access
- Persistence via launch agents
- Privacy violations (mic/camera access)

New patterns can be added to `threat_kb.py` and re-embedded without retraining any model.

---

Built for AMD Slingshot Hackathon 2026
