# phishing_detector.py
import re

PHISHING_SIGNALS = {
    "urgent_language": ["verify immediately", "account suspended", "click now", "urgent action", "limited time"],
    "credential_theft": ["confirm your password", "update your details", "enter your credentials", "bank account"],
    "suspicious_sender": ["noreply@", "no-reply@", "support@secure", "paypal-security", "amazon-update"],
    "suspicious_links": ["bit.ly", "tinyurl", "t.co", "click here", "login now", "verify here"]
}

def analyze_email(subject, body, sender):
    flags = []
    score = 0
    text = f"{subject} {body} {sender}".lower()

    for category, patterns in PHISHING_SIGNALS.items():
        for pattern in patterns:
            if pattern in text:
                flags.append((category, pattern))
                score += 1

    risk = "LOW" if score == 0 else "MEDIUM" if score <= 2 else "HIGH"
    return risk, flags, score