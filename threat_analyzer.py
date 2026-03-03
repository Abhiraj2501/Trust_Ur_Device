'''threat_analyzer.py - Now powered by RAG pipeline'''
from rag_agent import analyse_with_rag
import os, json

AI_LOG_PATH = "logs/ai_events.jsonl"

def persist_ai_event(result):
    os.makedirs("logs", exist_ok=True)
    with open(AI_LOG_PATH, "a") as f:
        f.write(json.dumps(result) + "\n")

def analyze_log_line(line):
    if not line.strip():
        return None

    try:
        sections = line.split("]")
        timestamp = sections[0].replace("[", "").strip()
        level = sections[1].replace("[", "").strip()
        category = sections[2].replace("[", "").strip()
        event_text = "]".join(sections[3:]).strip()
    except:
        timestamp = "Unknown"
        level = "LOW"
        category = "unknown"
        event_text = line.strip()

    # Skip AI for LOW — saves time, prevents hallucination
    if level == "LOW":
        return {
            "timestamp": timestamp,
            "level": "LOW",
            "category": category,
            "event": event_text,
            "profile": {
                "title": "Normal Activity",
                "explanation": "Normal system activity detected.",
                "action": "No action required.",
                "hygiene_tip": "Keep your system updated."
            }
        }

    # RAG pipeline for MEDIUM / HIGH
    rag_result = analyse_with_rag(event_text)

    enriched = {
        "timestamp": timestamp,
        "level": rag_result["threat_level"],
        "category": rag_result.get("category", category),
        "event": event_text,
        "reason": rag_result["reason"],
        "action": rag_result["action"],
        "hygiene_tip": rag_result["hygiene_tip"],
        "rag_used": rag_result.get("rag_context_used", False),
        "rag_matches": rag_result.get("rag_matches", [])
    }

    persist_ai_event(enriched)

    if enriched["level"] == "HIGH":
        print(f"[HIGH ALERT] {enriched['event'][:80]}")
        print(f"  → {enriched['action']}")

    return {
        "timestamp": timestamp,
        "level": enriched["level"],
        "category": enriched["category"],
        "event": event_text,
        "profile": {
            "title": f"{enriched['category'].replace('_', ' ').title()} Detected",
            "explanation": enriched["reason"],
            "action": enriched["action"],
            "hygiene_tip": enriched["hygiene_tip"]
        }
    }