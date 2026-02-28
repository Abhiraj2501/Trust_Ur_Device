from ai_agent import analyse_threat
import os, json

AI_LOG_PATH = "logs/ai_events.jsonl"


def persist_ai_event(result):
    os.makedirs("logs", exist_ok=True)
    with open(AI_LOG_PATH, "a") as f:
        f.write(json.dumps(result) + "\n")


def analyze_log_line(line):
    if not line.strip():
        return None

    # ---- robust parser ----
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

    # ---- skip AI for LOW events (prevent hallucination) ----
    if level == "LOW":
        enriched = {
            "timestamp": timestamp,
            "level": "LOW",
            "category": category,
            "event": event_text,
            "reason": "Normal system activity.",
            "action": "No action required.",
            "hygiene_tip": "Keep your system updated."
        }

        persist_ai_event(enriched)

        return {
            "timestamp": timestamp,
            "level": "LOW",
            "category": category,
            "event": event_text,
            "profile": {
                "title": f"{category.replace('_', ' ').title()} Detected",
                "explanation": enriched["reason"],
                "action": enriched["action"],
                "hygiene_tip": enriched["hygiene_tip"]
            }
        }

    # ---- AI analysis for MEDIUM / HIGH ----
    ai_result = analyse_threat(event_text)

    enriched = {
        "timestamp": timestamp,
        "level": ai_result["threat_level"],
        "category": category,
        "event": event_text,
        "reason": ai_result["reason"],
        "action": ai_result["action"],
        "hygiene_tip": ai_result["hygiene_tip"]
    }

    persist_ai_event(enriched)

    # ---- alert trigger ----
    if enriched["level"] == "HIGH":
        print(f"[ALERT] {enriched['event']} → {enriched['action']}")

    return {
        "timestamp": timestamp,
        "level": enriched["level"],
        "category": category,
        "event": event_text,
        "profile": {
            "title": f"{category.replace('_', ' ').title()} Detected",
            "explanation": enriched["reason"],
            "action": enriched["action"],
            "hygiene_tip": enriched["hygiene_tip"]
        }
    }