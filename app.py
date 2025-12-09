import json
import traceback

import streamlit as st
from pipeline import NeuroSymbolicPipeline

import requests

# -------------------------------------------------
# Init pipeline
# -------------------------------------------------
pipeline = NeuroSymbolicPipeline()

# -------------------------------------------------
# Page Configuration & Custom CSS
# -------------------------------------------------
st.set_page_config(
    page_title="Neuro-Symbolic Cyber Threat Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
    <style>
        /* Use Streamlit theme variables so it works in BOTH light & dark */
        :root {
            --ns-primary: var(--primary-color);
            --ns-bg: var(--background-color);
            --ns-bg-secondary: var(--secondary-background-color);
            --ns-text: var(--text-color);
            --ns-border: rgba(128, 128, 128, 0.35);
        }

        /* Main container spacing */
        .main .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
        }

        html, body, [data-testid="stAppViewContainer"] {
            background-color: var(--ns-bg);
            color: var(--ns-text);
        }

        /* Header styling */
        h1 {
            background: linear-gradient(90deg, #1f77b4, #ff7f0e);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }

        h2 {
            color: var(--ns-primary);
            border-bottom: 2px solid var(--ns-primary);
            padding-bottom: 0.5rem;
            margin-top: 2rem;
        }

        /* Metric cards – theme aware */
        [data-testid="stMetric"] {
            background-color: var(--ns-bg-secondary) !important;
            color: var(--ns-text) !important;
            padding: 1rem !important;
            border-radius: 0.75rem !important;
            border: 1px solid var(--ns-border) !important;
        }
        [data-testid="stMetric"] label,
        [data-testid="stMetricValue"],
        [data-testid="stMetricDelta"] {
            color: var(--ns-text) !important;
        }

        /* Info / warning / error / success boxes – keep theme background, just add border */
        .stInfo, .stWarning, .stError, .stSuccess {
            border-left-width: 4px !important;
            border-left-style: solid !important;
        }
        .stInfo     { border-left-color: #1f77b4 !important; }
        .stWarning  { border-left-color: #ff7f0e !important; }
        .stError    { border-left-color: #d62728 !important; }
        .stSuccess  { border-left-color: #2ca02c !important; }

        /* Analyze button */
        .stButton > button {
            background: linear-gradient(90deg, #1f77b4, #ff7f0e);
            color: white !important;
            border: none;
            border-radius: 0.5rem;
            padding: 0.6rem 2rem;
            font-weight: 600;
            font-size: 1rem;
            transition: all 0.3s;
        }
        .stButton > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.25);
        }

        /* Text area */
        .stTextArea > div > div > textarea {
            border-radius: 0.5rem;
            border: 1px solid var(--ns-border);
            background-color: var(--ns-bg-secondary);
            color: var(--ns-text);
        }

        /* Generic section containers */
        .section-container {
            background-color: var(--ns-bg-secondary);
            color: var(--ns-text);
            padding: 1.5rem;
            border-radius: 0.75rem;
            margin: 1rem 0;
            border: 1px solid var(--ns-border);
        }

        /* JSON boxes */
        .stJson {
            background-color: var(--ns-bg-secondary);
            border-radius: 0.5rem;
            padding: 1rem;
            border: 1px solid var(--ns-border);
        }

        /* Badges (still look good on both themes) */
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.875rem;
            font-weight: 600;
            margin: 0.25rem;
        }
        .badge-critical { background-color: #d62728; color: white; }
        .badge-high     { background-color: #ff7f0e; color: white; }
        .badge-medium   { background-color: #ffbb78; color: #333; }
        .badge-low      { background-color: #2ca02c; color: white; }
    </style>
""", unsafe_allow_html=True)



# -------------------------------------------------
# Sidebar
# -------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ About")
    st.markdown("""
    This tool uses a **neuro-symbolic approach** to analyze cyber threats:
    
    - **Neural**: LLM extracts information from text
    - **Symbolic**: Cyber ontology validates and enriches data
    
    **Features:**
    - MITRE ATT&CK mapping
    - Risk assessment
    - IOC extraction
    - Defense recommendations
    """)
    
    st.markdown("---")
    st.markdown("### 📊 System Status")
    st.success("✅ Pipeline Ready")
    st.info("💡 Enter threat text to begin analysis")

# -------------------------------------------------
# Main Header
# -------------------------------------------------
st.markdown("# 🛡️ Neuro-Symbolic Cyber Threat Analyzer")
st.markdown("### *Advanced AI-Powered Threat Intelligence Platform*")

st.markdown("---")

# -------------------------------------------------
# Input Section
# -------------------------------------------------
st.markdown("### 📝 Threat Input")
st.markdown(
    "Paste a CVE description or threat text below. "
    "The system will use a local LLM + cyber ontology to extract tactics/techniques, "
    "estimate risk, extract IOCs, suggest defenses, and check for consistency."
)

user_text = st.text_area(
    "Paste CVE / threat text:",
    height=200,
    placeholder="Example: CVE-2021-44228 allows remote code execution on a public-facing web app...",
    label_visibility="collapsed"
)

# -------------------------------------------------
# Analyze button with robust error handling
# -------------------------------------------------
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    analyze_button = st.button("🔍 Analyze Threat", use_container_width=True, type="primary")
    
if analyze_button:
    if not user_text.strip():
        st.warning("⚠️ Please enter some text to analyze.")
    else:
        try:
            with st.spinner("🔍 Analyzing with LLM + Ontology..."):
                result = pipeline.analyze_document(user_text)

            # Basic validation of the result structure
            required_keys = [
                "llm_raw",
                "mapped_technique",
                "mapped_tactics",
                "symbolic_note",
                "final_explanation",
            ]
            for key in required_keys:
                if key not in result:
                    raise KeyError(f"Pipeline result is missing key: '{key}'")

        except requests.exceptions.RequestException as e:
            st.error(
                "❌ Connection error while calling the LLM.\n\n"
                "Possible reasons:\n"
                "- Ollama is not running on your Server (`ollama serve`).\n"
                "- Tailscale is disconnected on either machine.\n"
                "- The IP/port in `llm_client.py` is incorrect.\n\n"
                f"Details: {e}"
            )
            with st.expander("Technical details"):
                st.code(traceback.format_exc())

        except json.JSONDecodeError as e:
            st.error(
                "❌ The LLM returned a response that could not be parsed as JSON.\n\n"
                "This usually means the model did not follow the strict JSON format in the prompt.\n"
                "You can try re-running the analysis or tightening the prompt formatting."
            )
            with st.expander("Technical details"):
                st.code(traceback.format_exc())

        except KeyError as e:
            st.error(
                "❌ The pipeline returned an unexpected result structure.\n\n"
                "One or more expected fields were missing in the output."
            )
            with st.expander("Technical details"):
                st.code(traceback.format_exc())

        except Exception as e:
            # Catch-all for anything else
            st.error(
                "❌ An unexpected error occurred during analysis.\n\n"
                "Please check that:\n"
                "- Ollama is running and reachable.\n"
                "- The ontology file path is correct.\n"
                "- The network connection is stable.\n\n"
                f"Error: {e}"
            )
            with st.expander("Technical details"):
                st.code(traceback.format_exc())

        else:
            st.markdown("---")
            st.markdown("## 📊 Analysis Results")
            
            # -------------------------------------------------
            # Top-level metrics (confidence + risk)
            # -------------------------------------------------
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                confidence = result.get('confidence', 0)
                st.metric(
                    "🎯 LLM Confidence",
                    f"{confidence}%",
                    delta=f"{confidence-50}%" if confidence > 50 else None
                )
            
            with col2:
                risk = result.get("risk_level", "Unknown")
                risk_icon = {
                    "Critical": "🔴",
                    "High": "🟠",
                    "Medium": "🟡",
                    "Low": "🟢"
                }.get(risk, "⚪")
                st.metric("⚠️ Risk Level", f"{risk_icon} {risk}")
            
            with col3:
                mitre_id = result.get("mitre_id", "N/A")
                st.metric("🎯 MITRE ID", mitre_id if mitre_id != "N/A" else "Not Mapped")
            
            with col4:
                tactics_count = len(result.get("mapped_tactics", []))
                st.metric("📋 Tactics", f"{tactics_count}")
            
            # Risk level visual indicator
            risk = result.get("risk_level", "Unknown")
            if risk == "Critical":
                st.error(f"🔴 **CRITICAL RISK** - Immediate action required")
            elif risk == "High":
                st.warning(f"🟠 **HIGH RISK** - Priority attention needed")
            elif risk == "Medium":
                st.info(f"🟡 **MEDIUM RISK** - Monitor and assess")
            elif risk == "Low":
                st.success(f"🟢 **LOW RISK** - Standard monitoring")
            
            st.markdown("---")

            # -------------------------------------------------
            # Tabbed Results Display
            # -------------------------------------------------
            tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
                "🎯 MITRE Mapping",
                "🤖 LLM Analysis",
                "🔍 IOCs & Indicators",
                "🛡️ Defense Recommendations",
                "📋 Full Details",
                "📄 Report View"
])

            
            # Tab 1: MITRE Mapping
            with tab1:
                st.markdown("### 🎯 MITRE ATT&CK Mapping")
                
                mapped_technique = result.get("mapped_technique")
                mapped_tactics = result.get("mapped_tactics", [])
                mitre_id = result.get("mitre_id")
                nice_name = result.get("nice_technique_name")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("#### Technique Information")
                    if mapped_technique:
                        st.info(f"**Raw Ontology Name:**\n{mapped_technique}")
                    if nice_name:
                        st.success(f"**MITRE Technique Name:**\n{nice_name}")
                    if mitre_id and mitre_id != "N/A":
                        st.markdown(f"**MITRE ID:** `{mitre_id}`")
                        st.markdown(f"**🔗 [View on MITRE ATT&CK](https://attack.mitre.org/techniques/{mitre_id}/)**")
                
                with col2:
                    st.markdown("#### Tactics")
                    if mapped_tactics:
                        for tactic in mapped_tactics:
                            st.markdown(f"- 🎯 {tactic}")
                    else:
                        st.info("No tactics mapped")
                
                st.markdown("---")
                
                # Related Malware & Threat Actors
                st.markdown("#### 🦠 Related Malware & Threat Actors")
                related_malware = result.get("related_malware", [])
                related_actors = result.get("related_actors", [])
                
                if not related_malware and not related_actors:
                    st.info("No specific malware families or threat actors are linked to this technique in the current ontology.")
                else:
                    col1, col2 = st.columns(2)
                    with col1:
                        if related_malware:
                            st.markdown("**Malware Families:**")
                            for malware in related_malware:
                                st.markdown(f"- 🦠 {malware}")
                    with col2:
                        if related_actors:
                            st.markdown("**Threat Actors:**")
                            for actor in related_actors:
                                st.markdown(f"- 👤 {actor}")
                
                # Symbolic Consistency Check
                st.markdown("---")
                st.markdown("#### ✅ Symbolic Consistency Check")
                st.info(result["symbolic_note"])
            
            # Tab 2: LLM Analysis
            with tab2:
                st.markdown("### 🤖 LLM Extraction Results")
                
                llm_raw = result["llm_raw"]
                
                # Detect "empty-like" extraction
                empty_like = False
                if isinstance(llm_raw, dict):
                    values = [
                        llm_raw.get("cve_id"),
                        llm_raw.get("vulnerability_type"),
                        llm_raw.get("possible_tactic"),
                        llm_raw.get("possible_technique_name"),
                        llm_raw.get("brief_reasoning"),
                    ]
                    empty_like = all(
                        v is None or (isinstance(v, str) and not v.strip())
                        for v in values
                    )
                
                if empty_like:
                    st.warning(
                        "⚠️ The LLM could not confidently extract any CVE, vulnerability type, "
                        "tactic, or technique from this text. It may not describe a clear cyber attack."
                    )
                
                with st.expander("📄 View Raw LLM JSON Output", expanded=False):
                    st.json(llm_raw)
                
                st.markdown("---")
                st.markdown("#### 💭 LLM Reasoning")
                st.markdown(result["final_explanation"] or "*No explanation available.*")
                
                st.markdown("---")
                st.markdown("#### 📝 Combined Attack Summary")
                attack_summary = result.get("attack_summary", "No summary generated.")
                st.markdown(f"*{attack_summary}*")
            
            # Tab 3: IOCs & Indicators
            with tab3:
                st.markdown("### 🔍 Indicators of Compromise (IOCs)")
                
                iocs = result.get("iocs", {})
                has_any_ioc = any(iocs.get(k) for k in ["ip_addresses", "urls", "emails", "hashes"])
                
                if not has_any_ioc:
                    st.info("ℹ️ No obvious IOCs (IPs, URLs, emails, hashes) were detected in the text.")
                else:
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if iocs.get("ip_addresses"):
                            st.markdown("#### 🌐 IP Addresses")
                            for ip in iocs["ip_addresses"]:
                                st.code(ip, language=None)
                        
                        if iocs.get("urls"):
                            st.markdown("#### 🔗 URLs")
                            for url in iocs["urls"]:
                                st.code(url, language=None)
                    
                    with col2:
                        if iocs.get("emails"):
                            st.markdown("#### 📧 Email Addresses")
                            for email in iocs["emails"]:
                                st.code(email, language=None)
                        
                        if iocs.get("hashes"):
                            st.markdown("#### 🔐 Hashes")
                            for hash_val in iocs["hashes"]:
                                st.code(hash_val, language=None)
            
            # Tab 4: Defense Recommendations
            with tab4:
                st.markdown("### 🛡️ Defense Recommendations")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("#### 🚫 Prevention Recommendations")
                    defense_pre = result.get("defense_recommendations", [])
                    if defense_pre:
                        for i, item in enumerate(defense_pre, 1):
                            st.markdown(f"{i}. {item}")
                    else:
                        st.info("No prevention recommendations available for this technique.")
                
                with col2:
                    st.markdown("#### 🛡️ D3FEND-Style Defenses")
                    defense_d3 = result.get("defense_d3fend", [])
                    if defense_d3:
                        for i, item in enumerate(defense_d3, 1):
                            st.markdown(f"{i}. {item}")
                    else:
                        st.info("No D3FEND-style defensive techniques available for this technique.")
            
            # Tab 5: Full Details
            with tab5:
                st.markdown("### 📋 Complete Analysis Details")
                
                with st.expander("🔍 Full Result JSON", expanded=False):
                    st.json(result)
                
                st.markdown("---")
                
                # Display all sections in full detail
                st.markdown("#### All Extracted Information")
                
                for key, value in result.items():
                    if key not in ["llm_raw"]:  # Already shown in Tab 2
                        st.markdown(f"**{key.replace('_', ' ').title()}:**")
                        if isinstance(value, (dict, list)):
                            st.json(value)
                        else:
                            st.write(value)
                        st.markdown("---")
            # Tab 6: Printable Report View
            with tab6:
                st.markdown("## 📄 Printable Threat Report")
                st.markdown("### 📝 Input Text")
                st.markdown(f"> {user_text}")
                st.markdown("### 🎯 MITRE Mapping")
                st.write("**Technique (Ontology):**", result.get("mapped_technique", "N/A"))
                st.write("**Technique (MITRE Name):**", result.get("nice_technique_name", "N/A"))
                st.write("**MITRE ID:**", result.get("mitre_id", "N/A"))
                st.write("**Tactics:**", ", ".join(result.get("mapped_tactics", [])) or "None") 
                st.markdown("### 🤖 LLM Extraction Summary")
                llm_raw = result["llm_raw"]
                st.write("**CVE ID:**", llm_raw.get("cve_id"))
                st.write("**Vulnerability Type:**", llm_raw.get("vulnerability_type"))
                st.write("**Possible Tactic:**", llm_raw.get("possible_tactic"))
                st.write("**Possible Technique Name:**", llm_raw.get("possible_technique_name"))
                st.write("**LLM Reasoning:**")
                st.markdown(llm_raw.get("brief_reasoning", "") or "_No reasoning available._")
                st.markdown("### 🧠 Combined Attack Summary")
                st.markdown(result.get("attack_summary", "_No summary generated._"))
                st.markdown("### 🔍 Indicators of Compromise (IOCs)")
                iocs = result.get("iocs", {})
                if any(iocs.get(k) for k in ["ip_addresses", "urls", "emails", "hashes"]):
                    if iocs.get("ip_addresses"):
                        st.write("**IP Addresses:**")
                        for ip in iocs["ip_addresses"]:
                            st.code(ip)
                    if iocs.get("urls"):
                        st.write("**URLs:**")
                        for url in iocs["urls"]:
                            st.code(url)
                    if iocs.get("emails"):
                        st.write("**Email Addresses:**")
                        for email in iocs["emails"]:
                            st.code(email)
                    if iocs.get("hashes"):
                        st.write("**Hashes:**")
                        for h in iocs["hashes"]:
                            st.code(h)
                else:
                    st.markdown("_No IOCs detected in the text._")
            
                st.markdown("### 🛡️ Defense Recommendations")
                defense_pre = result.get("defense_recommendations", [])
                if defense_pre:
                    for i, item in enumerate(defense_pre, 1):
                        st.markdown(f"{i}. {item}")
                else:
                    st.markdown("_No prevention recommendations available._")
            
                st.markdown("### 🛡️ D3FEND-Style Defenses")
                defense_d3 = result.get("defense_d3fend", [])
                if defense_d3:
                    for i, item in enumerate(defense_d3, 1):
                        st.markdown(f"{i}. {item}")
                else:
                    st.markdown("_No D3FEND-style defenses available._")
            
                st.markdown("### ✅ Symbolic Consistency Note")
                st.markdown(result.get("symbolic_note", "_No note available._"))

