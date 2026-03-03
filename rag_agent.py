'''rag_agent.py - RAG-powered threat analysis'''
import ollama
from threat_kb import query_threat_kb

def analyse_with_rag(event_text):
    """
    Full RAG pipeline:
    1. Query ChromaDB for similar known threats
    2. Feed event + context to AI
    3. AI reasons with knowledge, not blind guessing
    """

    # Step 1 — retrieve similar threats from knowledge base
    similar_threats = query_threat_kb(event_text, n_results=3)

    # Step 2 — build context from retrieved patterns
    context = ""
    top_severity = "LOW"
    for i, match in enumerate(similar_threats):
        context += f"\nKnown threat pattern {i+1} (similarity: {match['similarity']:.2f}):\n"
        context += f"  Pattern: {match['pattern']}\n"
        context += f"  Category: {match['category']}\n"
        context += f"  Severity: {match['severity']}\n"
        context += f"  Recommended action: {match['action']}\n"

        if match['severity'] == "HIGH" and match['similarity'] > 0.5:
            top_severity = "HIGH"
        elif match['severity'] == "MEDIUM" and top_severity == "LOW" and match['similarity'] > 0.5:
            top_severity = "MEDIUM"

    # Step 3 — AI reasons with context
    prompt = f"""You are a cybersecurity AI on macOS. Analyse this system event using the known threat patterns below.

System Event: {event_text}

Similar known threat patterns from knowledge base:
{context}

Based on the event and the threat patterns above, respond in EXACTLY this format:
THREAT_LEVEL: HIGH or MEDIUM or LOW
REASON: one sentence explaining what is happening and why it is or isn't dangerous
ACTION: one sentence telling the user exactly what to do right now
HYGIENE_TIP: one sentence of long-term security advice
CATEGORY: one word category like malware, phishing, safe, privilege_escalation etc
"""

    try:
        response = ollama.chat(
            model="qwen2:1.5b",
            messages=[{"role": "user", "content": prompt}]
        )
        result = parse_response(response["message"]["content"])
        result["rag_matches"] = similar_threats
        result["rag_context_used"] = True
        return result

    except Exception as e:
        print(f"RAG agent error: {e} — using KB match directly")
        return fallback_from_kb(similar_threats, top_severity)


def parse_response(text):
    result = {
        "threat_level": "LOW",
        "reason": "Normal system activity.",
        "action": "No action required.",
        "hygiene_tip": "Keep your system updated.",
        "category": "unknown",
        "rag_context_used": True
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
        elif line.startswith("CATEGORY:"):
            result["category"] = line.split(":", 1)[1].strip()

    return result


def fallback_from_kb(matches, top_severity):
    """Use KB match directly if AI is unavailable"""
    if not matches:
        return {
            "threat_level": "LOW",
            "reason": "No matching threat pattern found.",
            "action": "Monitor this activity.",
            "hygiene_tip": "Keep your system updated.",
            "category": "unknown",
            "rag_context_used": False
        }

    best = matches[0]
    return {
        "threat_level": top_severity,
        "reason": f"Matches known pattern: {best['pattern']}",
        "action": best["action"],
        "hygiene_tip": best["hygiene"],
        "category": best["category"],
        "rag_context_used": False
    }