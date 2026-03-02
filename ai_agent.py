import ollama

def analyse_threat(log_line):
    prompt = f"""
You are a cybersecurity AI assistant on macOS.
Known safe Apple system processes should be rated LOW.
Only flag HIGH if there is clear evidence of malicious intent.

Event: {log_line}

Respond in EXACTLY this format, nothing else:
THREAT_LEVEL: HIGH or MEDIUM or LOW
REASON: one sentence explaining why this is or isn't dangerous
ACTION: one sentence telling the user exactly what to do right now
HYGIENE_TIP: one sentence of long-term security advice
"""

    try:
        response = ollama.chat(
            model="qwen2:1.5b",
            messages=[{"role": "user", "content": prompt}]
        )

        text = response["message"]["content"]
        return parse_response(text)

    except Exception as e:
        print(f"AI error: {e} — falling back to rule-based")
        return fallback_analysis(log_line)


def parse_response(text):
    result = {
        "threat_level": "MEDIUM",
        "reason": "Suspicious activity detected.",
        "action": "Monitor this activity closely.",
        "hygiene_tip": "Keep your system updated."
    }

    for line in text.strip().split("\n"):
        if line.startswith("THREAT_LEVEL:"):
            result["threat_level"] = line.split(":", 1)[1].strip()
        elif line.startswith("REASON:"):
            result["reason"] = line.split(":", 1)[1].strip()
        elif line.startswith("ACTION:"):
            result["action"] = line.split(":", 1)[1].strip()
        elif line.startswith("HYGIENE_TIP:"):
            result["hygiene_tip"] = line.split(":", 1)[1].strip()

    return result


def fallback_analysis(log_line):
    line_lower = log_line.lower()

    if any(w in line_lower for w in ["malware", "unknown binary", "tmp", "flash", "root", "ssh", "admin", "hosts", "malicious"]):
        level = "HIGH"
    elif any(w in line_lower for w in ["microphone", "camera", "extension", "permission"]):
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "threat_level": level,
        "reason": "Detected based on known threat patterns.",
        "action": "Review this activity carefully.",
        "hygiene_tip": "Regularly audit app permissions and installed software."
    }