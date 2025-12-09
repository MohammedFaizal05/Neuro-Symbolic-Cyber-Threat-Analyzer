import json
from typing import Dict

import requests

# ====== CONFIG ======
# Toggle this if you ever want to go back to mock mode
USE_MOCK = False

# Your friend's Tailscale IP + Ollama API endpoint
OLLAMA_URL = "http://100.117.73.123:11434/api/generate"
MODEL_NAME = "llama3:8b"


class LLMClient:
    def __init__(self, model: str = MODEL_NAME):
        self.model = model

    # -------- MAIN METHOD USED BY PIPELINE ----------
    def analyze_text(self, text: str) -> Dict:
        if USE_MOCK:
            return self._mock_analyze_text(text)
        else:
            return self._real_analyze_text(text)

    # -------- MOCK IMPLEMENTATION (offline testing) ----------
    def _mock_analyze_text(self, text: str) -> Dict:
        text_lower = text.lower()
        result = {
            "cve_id": None,
            "vulnerability_type": "unknown",
            "possible_tactic": "Initial Access",
            "possible_technique_name": "Exploit Public-Facing Application",
            "brief_reasoning": "Mock LLM: default reasoning.",
        }

        # very simple keyword-based rules just for demo/testing
        if "cve-" in text_lower:
            start = text_lower.find("cve-")
            result["cve_id"] = text[start:start + 13].upper()

        if "remote code execution" in text_lower or "rce" in text_lower:
            result["vulnerability_type"] = "RCE"
            result["possible_tactic"] = "Initial Access"
            result["possible_technique_name"] = "Exploit Public-Facing Application"
            result["brief_reasoning"] = (
                "Mock LLM: This looks like remote code execution on a public-facing app."
            )
        elif "phishing" in text_lower or "email" in text_lower:
            result["vulnerability_type"] = "Phishing"
            result["possible_tactic"] = "Initial Access"
            result["possible_technique_name"] = "Phishing"
            result["brief_reasoning"] = (
                "Mock LLM: This text mentions phishing/email, so mapped to phishing technique."
            )
        elif "command line" in text_lower or "shell" in text_lower:
            result["vulnerability_type"] = "Command Execution"
            result["possible_tactic"] = "Execution"
            result["possible_technique_name"] = "CommandLineExecution"
            result["brief_reasoning"] = (
                "Mock LLM: Command line usage indicates execution of commands."
            )

        return result

    # -------- REAL IMPLEMENTATION (Ollama + llama3:8b) ----------
    def _real_analyze_text(self, text: str) -> Dict:
        prompt = f"""
You are a cyber threat intelligence assistant.

Extract the following information from the text:

- cve_id (if present, else null)
- vulnerability_type (e.g., RCE, SQLi, phishing, privilege escalation, etc.)
- possible_tactic (one of: "Initial Access", "Execution", "Privilege Escalation",
  "Persistence", "Defense Evasion", "Credential Access", "Discovery",
  "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact")
- possible_technique_name (a short MITRE ATT&CK-like technique name, e.g.,
  "Exploit Public-Facing Application", "Command-Line Execution", "Phishing")
- brief_reasoning (1–2 sentences of explanation)

Return ONLY a single JSON object with EXACTLY these keys:

{{
  "cve_id": "... or null",
  "vulnerability_type": "...",
  "possible_tactic": "... or null",
  "possible_technique_name": "... or null",
  "brief_reasoning": "..."
}}

Do NOT include any explanation outside of the JSON. Respond with JSON only.

Text to analyze:
\"\"\"{text}\"\"\"
"""

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }

        resp = requests.post(OLLAMA_URL, json=payload)
        resp.raise_for_status()
        raw = resp.json()["response"]

        # Try to parse JSON; if the model adds extra text, extract JSON block
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start == -1 or end == -1:
                raise ValueError(f"LLM did not return JSON: {raw}")
            data = json.loads(raw[start:end])

        return data


if __name__ == "__main__":
    client = LLMClient()
    sample = "CVE-2021-1234 allows remote code execution on a public-facing web application."
    print(client.analyze_text(sample))
