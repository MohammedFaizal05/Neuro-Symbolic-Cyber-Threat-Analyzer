import json
import re
from typing import Dict

import requests

# ... (rest of imports)

# ====== CONFIG ======
# Toggle this if you ever want to go back to mock mode
USE_MOCK = False

# Your friend's Tailscale IP + Ollama API endpoint
OLLAMA_URL = "http://100.82.17.120:11434/api/generate"
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
        # Simple mock for testing
        return {
            "cve_id": None, 
            "vulnerability_type": "Mock", 
            "possible_tactic": "Initial Access", 
            "possible_technique_name": "Mock Technique", 
            "brief_reasoning": "Mock response"
        }

    def _robust_json_parse(self, raw_text: str) -> Dict:
        """
        Attempt to clean and parse JSON from a raw LLM response.
        Handles common errors like single quotes, trailing commas, markdown blocks.
        """
        # 1. Strip markdown code blocks if present
        text = raw_text.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        
        # 2. Extract the substring from first '{' to last '}'
        start = text.find("{")
        end = text.rfind("}") + 1
        if start != -1 and end != -1:
            text = text[start:end]
            
        # 3. Direct attempt
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 4. Fallback: Fix common LLM syntax errors
        
        # FIX: Handle double double-quotes at start of value (e.g. "key": ""Value...)
        # Replace "" with " ONLY if not followed by comma/brace (i.e., not an empty string)
        text = re.sub(r'(:\s*)"{2,}(?![,\s}])', r'\1"', text)

        # FIX: Handle double double-quotes at end of value (e.g. ...Value"" } )
        # Replace "" with " ONLY if followed by comma/brace
        text = re.sub(r'"{2,}(\s*[,}])', r'"\1', text)
        
        # Replace single quotes with double quotes for keys/values
        text_fixed = re.sub(r"'([^']+)':", r'"\1":', text)
        try:
            return json.loads(text_fixed)
        except json.JSONDecodeError:
            pass
            
        # Try replacing ALL single quotes with double quotes (risky if text contains apostrophes)
        try:
            text_fixed_all = text.replace("'", '"')
            return json.loads(text_fixed_all)
        except json.JSONDecodeError:
            pass

        # 5. Last Resort: Safety Net
        # If the LLM completely butchered the JSON, don't crash the app.
        # Just return the raw text as the reasoning.
        print(f"JSON Parse failed. Returning raw fallback. Raw: {raw_text[:100]}...")
        return {
            "cve_id": None,
            "vulnerability_type": "LLM Parsing Error",
            "possible_tactic": None,
            "possible_technique_name": None,
            "brief_reasoning": f"Could not parse strict JSON. Raw LLM Response:\n\n{raw_text}"
        }

    # -------- REAL IMPLEMENTATION (Ollama + llama3:8b) ----------
    def _real_analyze_text(self, text: str) -> Dict:
        prompt = f"""
You are a cyber threat intelligence assistant.

1. DETECTION MODE:
   If the text describes a specific cyber attack, vulnerability, or incident, extract:
   - cve_id (if present in text, else null)
   - vulnerability_type (e.g., RCE, SQLi, phishing)
   - possible_tactic (MITRE tactic)
   - possible_technique_name (MITRE technique name)
   - brief_reasoning (1-2 sentences explaining why)
   - related_cves (list of strings): Identify any OTHER well-known CVEs associated with this technique/vulnerability type from your knowledge base (e.g., if Log4j, suggest CVE-2021-44228).

2. Q&A / EDUCATIONAL MODE:
   If the text is a GENERAL QUESTION (e.g., "What is phishing?", "Explain CVE-2021-44228"):
   - brief_reasoning: Provide a detailed, helpful, ChatGPT-style answer to the user's question. Be educational and clear.
   
   CRITICAL FOR Q&A:
   - possible_technique_name: IF the question mentions ANY specific attack type, EXTRACT IT.
   - possible_tactic: Infer the likely tactic.
   - cve_id: IF the text mentions a CVE, EXTRACT IT.
   - vulnerability_type: Classify the topic.
   - related_cves (list of strings): List 3-5 famous CVEs related to this topic (e.g. for "SMB", list "CVE-2017-0144").

Return ONLY a single valid JSON object.
IMPORTANT:
- Use DOUBLE QUOTES for all property names and string values.
- Do NOT use single quotes.
- Do NOT use trailing commas.
- Escape any double quotes inside strings with backslashes.

Example format:
{{
  "cve_id": "CVE-2023-xxxx",
  "vulnerability_type": "Phishing",
  "possible_tactic": "Initial Access",
  "possible_technique_name": "Phishing",
  "brief_reasoning": "Phishing is a type of social engineering...",
  "related_cves": ["CVE-2021-44228", "CVE-2017-0144"]
}}

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

        return self._robust_json_parse(raw)


if __name__ == "__main__":
    client = LLMClient()
    sample = "CVE-2021-1234 allows remote code execution on a public-facing web application."
    print(client.analyze_text(sample))
