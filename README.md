# 🧠🔐 Neuro-Symbolic Cyber Threat Analyzer  
A hybrid AI-powered system that combines **Large Language Models (LLaMA3:8B)** with **ontology-based symbolic reasoning** to perform automated, explainable Cyber Threat Intelligence (CTI) analysis.

---

## 🚀 Overview  
The **Neuro-Symbolic Cyber Threat Analyzer** extracts TTPs, IOCs, malware families, threat actors, CVEs, and CAPEC patterns using a local LLM, and validates them through a custom **OWL-based CTI ontology** using *Owlready2*.  
It generates **attack summaries, risk scores, defensive actions (MITRE D3FEND)** and visualizes results via a Streamlit dashboard.

---

## 🔍 Key Features  
- **LLM-Based Extraction (LLaMA3:8B – Ollama)**
  - ATT&CK Tactics & Techniques  
  - Malware families  
  - Threat actors  
  - CVEs, CWE, CAPEC patterns  
  - IOC detection (IP, domain, URL, hashes, emails)

- **Ontology Reasoning (NS-CyberOnt)**
  - Semantic consistency checking  
  - Technique-tactic relationships  
  - Threat actor behavior inference  
  - D3FEND mitigation mapping  

- **Neuro-Symbolic Pipeline**
  - Neural extraction → Symbolic validation → Risk scoring → Defense recommendations

- **Risk & Confidence Scoring**
  - Composite heuristic scoring system  
  - Flags Critical, High, Medium, Low threats  

- **Interactive Streamlit Dashboard**
  - Threat summary  
  - Technique mapping view  
  - IOC viewer  
  - Defense recommendations  
  - Error-handling & stability


---

## 🧩 Architecture  
1. **User Input** (CTI text)  
2. **LLM Extraction** via LLaMA3  
3. **Ontology Mapping** (NS-CyberOnt)  
4. **Reasoning Engine** (Owlready2 + reasoner)  
5. **Risk & Defense Analysis**  
6. **Interactive Dashboard Output**

---

## 🛠️ Tech Stack  
- **Languages:** Python  
- **Frameworks:** Streamlit  
- **AI Models:** LLaMA3:8B (Ollama)  
- **Ontology:** OWL / Protégé  
- **Libraries:** Owlready2, regex, numpy, pandas  
- **DevOps:** Docker support  
- **Networking:** Tailscale-compatible deployment  

---

## 🧪 Running the App  
Install dependencies:

```bash
pip install -r requirements.txt

ollama pull llama3:8b

streamlit run app.py
```

---

## 🛡️ Risk Scoring
Risk score combines:
  - **Technique severity**
  - **Threat actor sophistication**
  - **Malware impact**
  - **Number & severity of CVEs**
  - **IOC strength**

Threat levels:
Critical | High | Medium | Low

---

## 🧷 Defense Recommendations
Based on MITRE D3FEND, mapped automatically using ontology reasoning.
Examples include:

  - **Credential hardening**
  - **Boundary protection**
  - **Application isolation**
  - **Network monitoring**
  - **MFA enforcement**

---

## 🔮 Future Enhancements
  - **SIEM/EDR integration**
  - **Temporal reasoning in ontology**
  - **Explainable AI traces for decisions**
  - **Interactive knowledge-graph visualization**
  - **Auto-updating ontology with new ATT&CK entries **

---
