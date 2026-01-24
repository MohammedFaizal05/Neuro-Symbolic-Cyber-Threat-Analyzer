# Neuro-Symbolic Cyber Threat Analyzer - Enhancement Walkthrough

This walkthrough details the new features added to the Cyber Threat Analyzer.

## 1. Architecture Changes

The codebase has been modularized to support the new features while keeping `app.py` clean:

- **`ioc_reputation.py`**: Handles API interactions with AbuseIPDB and VirusTotal. Includes automatic key rotation and rate limit handling.
- **`pdf_handler.py`**: Robust text extraction from PDF files using `PyPDF2` with `pdfminer.six` fallback.
- **`report_generator.py`**: Generates professional PDF reports using `reportlab`.
- **`pipeline.py`**: Updated to integrate the reputation checker and pass data to the frontend.

## 2. New Features

### 🛡️ IOC Reputation
- **What it does**: Automatically checks IPs against AbuseIPDB and URLs/Hashes against VirusTotal.
- **Where to see it**: A new "🛡️ IOC Reputation" tab appears in the analysis results.
- **Setup**: Add your API keys to `.env` (see `.env.example`).

### 🤖 Educational Q&A Mode
- **What it does**: Ask general questions (e.g., "What is ransomware?") instead of pasting threat data.
- **How to use**: Type your question in the text box and Analyze. The answer will appear in "🤖 LLM Analysis" -> "LLM Reasoning".

### 📎 PDF Report Upload
- **What it does**: Allows you to upload a threat report PDF instead of pasting text.
- **How to use**: Click the "📎 PDF Upload" tab in the input section.

### 📥 Downloadable Report
- **What it does**: Generates a comprehensive PDF report of the analysis.
- **How to use**: Click the "📄 Download PDF Report" button at the bottom of the results.

### 🚀 Running the App
- **Command**: Run the following in your terminal:
  ```bash
  python -m streamlit run app.py --server.port 8501
  ```


### 🛡️ Semantic Ontology Expansion
- **What it does**: The ontology has been upgraded to store **Defensive**, **Preventative**, and **Detection** logic directly within the knowledge graph.
- **Benefits**:
  - Decoupled logic: Defense knowledge is no longer hardcoded in Python.
  - Extensibility: You can add new techniques/defenses into `cyber_ontology.owl` or use `enrich_ontology.py` to batch import them.
  - Comprehensive Data: Common attacks now include specific detection queries and D3FEND mappings.

## 3. Setup Instructions

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure API Keys**:
   - Copy `.env.example` to `.env`.
   - Add your AbuseIPDB and VirusTotal API keys.

3. **Run the Application**:
3. **Run the Application**:
   Run the following command in your terminal:
   ```bash
   python -m streamlit run app.py --server.port 8501
   ```

## 4. Verification

We have verified that:
- [x] IOC Reputation module correctly handles API logic and failover.
- [x] PDF Handler extracts text from documents.
- [x] Report Generator builds valid PDF documents.
- [x] Application binds to localhost for security.

## 5. Project File Structure

Here is a guide to the key files in the project and their purpose:

### Core Logic
- **`app.py`**: The main Streamlit application. Handles the UI, user input, and displaying results.
- **`pipeline.py`**: The central coordinator. It orchestrates the flow of data between the LLM, Ontology, and other modules.
- **`llm_client.py`**: Handles communication with the local LLM (Ollama). Includes prompt engineering and robust JSON parsing.
- **`ontology_engine.py`**: Manages the Neuro-Symbolic knowledge graph (`cyber_ontology.owl`). Handles semantic mapping, fuzzy matching, and retrieving defenses.

### Helpers & Modules
- **`ioc_reputation.py`**: Connects to external APIs (AbuseIPDB, VirusTotal) to check the reputation of IPs and URLs.
- **`pdf_handler.py`**: Extracts clean text from uploaded PDF threat reports.
- **`report_generator.py`**: Creates the downloadable PDF analysis report using ReportLab.
- **`enrich_ontology.py`**: A utility script to batch-import new knowledge into the ontology.

### Data & Config
- **`cyber_ontology.owl`**: The OWL file storing the specialized cyber security knowledge graph.
- **`.env`**: Stores secret API keys (not committed to git).
- **`requirements.txt`**: Lists all Python libraries required to run the project.
