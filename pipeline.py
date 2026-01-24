from llm_client import LLMClient
from ontology_engine import OntologyEngine
from ioc_reputation import IOCReputationChecker
import re
from typing import Dict, Any, List

# ---------------- SMALL NORMALIZER ----------------
# ---------------- DEFENSE KNOWLEDGE BASE ----------------
# NOTE: Defense knowledge is now sourced dynamically from the ontology (cyber_ontology.owl)
# via the OntologyEngine classes (hasPreventionRecommendation, hasDetectionLogic, etc.)


class NeuroSymbolicPipeline:
    def __init__(self, check_ioc_reputation: bool = True):
        self.llm = LLMClient()
        self.onto = OntologyEngine()
        self.check_ioc_reputation = check_ioc_reputation
        self.ioc_checker = IOCReputationChecker() if check_ioc_reputation else None

    # ---------------- IOC EXTRACTION ----------------
    def _extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Naive IOC extraction: IPs, URLs, emails, hashes."""
        if not text:
            return {"ip_addresses": [], "urls": [], "emails": [], "hashes": []}

        # IP addresses (simple IPv4)
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        # URLs
        url_pattern = r"\bhttps?://[^\s<>\"']+"
        # Emails
        email_pattern = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        # Very naive hash pattern (32+ hex chars)
        hash_pattern = r"\b[a-fA-F0-9]{32,}\b"

        ips = re.findall(ip_pattern, text)
        urls = re.findall(url_pattern, text)
        emails = re.findall(email_pattern, text)
        hashes = re.findall(hash_pattern, text)

        # Remove duplicates while preserving order
        def unique(seq):
            seen = set()
            out = []
            for x in seq:
                if x not in seen:
                    seen.add(x)
                    out.append(x)
            return out

        return {
            "ip_addresses": unique(ips),
            "urls": unique(urls),
            "emails": unique(emails),
            "hashes": unique(hashes),
        }

    # ---------------- RISK SCORING ----------------
    def _assess_risk(
        self,
        vulnerability_type: str,
        tactic_name: str,
        technique_name: str,
        text: str,
    ) -> str:
        """Very simple heuristic risk scoring."""
        vt = (vulnerability_type or "").lower()
        tac = (tactic_name or "").lower()
        tech = (technique_name or "").lower()
        t = (text or "").lower()

        # Critical: RCE, destructive, ransomware, impact/exfiltration tactic
        if any(
            kw in vt or kw in t
            for kw in [
                "remote code execution",
                "rce",
                "ransomware",
                "data encrypted",
                "wiper",
                "destructive",
            ]
        ):
            return "Critical"

        if any(kw in tac for kw in ["impact", "exfiltration"]):
            return "Critical"

        # High: privilege escalation, credential access, lateral movement
        if any(
            kw in vt or kw in tac or kw in tech or kw in t
            for kw in [
                "privilege escalation",
                "credential",
                "lateral movement",
                "password dump",
                "credential dumping",
            ]
        ):
            return "High"

        # Medium: phishing, brute force, initial access, recon
        if any(
            kw in vt or kw in tac or kw in tech or kw in t
            for kw in [
                "phishing",
                "brute force",
                "initial access",
                "reconnaissance",
                "scan",
                "enumeration",
            ]
        ):
            return "Medium"

        # Default
        return "Low"

    # ---------------- CONFIDENCE SCORING ----------------
    def _compute_confidence(self, llm_result: Dict[str, Any]) -> int:
        """
        Simple heuristic confidence: how many key fields are non-empty.
        """
        fields = [
            "cve_id",
            "vulnerability_type",
            "possible_tactic",
            "possible_technique_name",
            "brief_reasoning",
        ]
        filled = 0
        for f in fields:
            v = llm_result.get(f)
            if v is None:
                continue
            if isinstance(v, str):
                if v.strip():
                    filled += 1
            else:
                filled += 1

        if not fields:
            return 0
        score = int((filled / len(fields)) * 100)
        return max(0, min(100, score))

    # ---------------- MITRE ID + CLEAN NAME ----------------
    def _split_mitre_technique(self, mapped_technique: str):
        """
        Split something like 'T1190_ExploitPublicFacingApplication'
        into ('T1190', 'Exploit Public-Facing Application').
        """
        if not mapped_technique:
            return None, None

        parts = mapped_technique.split("_", 1)
        mitre_id = parts[0] if parts else None
        nice_name = None
        if len(parts) > 1:
            nice_name = parts[1].replace("_", " ")
        return mitre_id, nice_name

    # ---------------- ATTACK SUMMARY ----------------
    def _build_summary(
        self,
        llm_result: Dict[str, Any],
        mapped_technique: str,
        mapped_tactics: list,
        mitre_id: str,
        nice_tech_name: str,
        risk_level: str,
    ) -> str:
        tactic_from_llm = llm_result.get("possible_tactic") or ""
        vuln_type = llm_result.get("vulnerability_type") or ""
        cve_id = llm_result.get("cve_id") or "Unknown CVE"

        tactic_display = tactic_from_llm or (mapped_tactics[0] if mapped_tactics else "Unknown Tactic")
        tech_display = (
            nice_tech_name
            or llm_result.get("possible_technique_name")
            or mapped_technique
            or "Unknown Technique"
        )

        parts = []
        parts.append(f"The text appears to describe {cve_id} or a similar issue.")
        parts.append(
            f"It is classified as '{vuln_type or 'unknown type'}' and likely falls under the '{tactic_display}' tactic."
        )
        if mitre_id:
            parts.append(
                f"The technique most closely matched in the ontology is '{tech_display}' (MITRE {mitre_id})."
            )
        else:
            parts.append(
                f"The technique most closely matched in the ontology is '{tech_display}'."
            )

        parts.append(
            f"Overall risk is assessed as **{risk_level}** based on the described behavior and context."
        )

        return " ".join(parts)

    # ---------------- MAIN PIPELINE ----------------
    def analyze_document(self, text: str) -> dict:
        # 1) Neural: call LLM
        llm_result = self.llm.analyze_text(text)

        tactic_name = llm_result.get("possible_tactic", "")
        technique_name = llm_result.get("possible_technique_name", "")

        # 2) Symbolic: map to ontology
        technique_matches = self.onto.find_technique_by_name(technique_name)
        mapped_technique = technique_matches[0].name if technique_matches else None

        mapped_tactics = []
        if technique_matches:
            mapped_tactics = [
                t.name for t in self.onto.get_tactics_for_technique(technique_matches[0])
            ]

        # 3) Consistency check
        symbolic_note = ""
        if not technique_matches:
            symbolic_note = "No matching technique found in ontology (possible novel or hallucinated)."
        elif tactic_name and mapped_tactics:
            # crude comparison, just for demo
            if tactic_name.replace(" ", "").lower() not in mapped_tactics[0].lower():
                symbolic_note = (
                    f"LLM tactic '{tactic_name}' differs from ontology tactic '{mapped_tactics[0]}'. "
                    "Potential inconsistency."
                )
            else:
                symbolic_note = "LLM tactic is consistent with ontology."
        else:
            symbolic_note = "Insufficient data for consistency check."

        # 4) IOC extraction
        iocs = self._extract_iocs(text)
        
        # 4.5) IOC reputation checking (optional, server-side only)
        ioc_reputation = {}
        if self.check_ioc_reputation and self.ioc_checker and any(iocs.get(k) for k in ["ip_addresses", "urls", "emails", "hashes"]):
            try:
                ioc_reputation = self.ioc_checker.check_all_iocs(iocs)
            except Exception as e:
                # Fail gracefully - reputation check is optional
                ioc_reputation = {"error": f"Reputation check failed: {str(e)}"}

        # 5) Risk scoring
        risk_level = self._assess_risk(
            llm_result.get("vulnerability_type", ""),
            tactic_name,
            technique_name,
            text,
        )

        # 6) Confidence scoring
        confidence = self._compute_confidence(llm_result)

        # 7) MITRE ID + clean technique name
        mitre_id, nice_tech_name = self._split_mitre_technique(mapped_technique)

        # 8) Defense recommendations lookup (Fully Dynamic from Ontology)
        defense_data = {
            "prevention": [],
            "detection": [],
            "d3fend": []
        }
        
        if technique_matches:
            # Use the best match from the ontology
            best_tech = technique_matches[0]
            
            # Fetch properties dynamically
            defense_data["prevention"] = self.onto.get_prevention_recommendations(best_tech)
            defense_data["detection"] = self.onto.get_detection_logic(best_tech)
            defense_data["d3fend"] = self.onto.get_d3fend_mitigations(best_tech)
            
            # If empty, we can try to fallback to tactic-based generic advice (optional, skipping for now)

        # 9) Attack summary
        attack_summary = self._build_summary(
            llm_result,
            mapped_technique,
            mapped_tactics,
            mitre_id,
            nice_tech_name,
            risk_level,
        )

        # 10) Related malware & threat actors from ontology
        related_malware = []
        related_actors = []
        if technique_matches:
            tech_ind = technique_matches[0]
            related_malware = [m.name for m in self.onto.get_malware_for_technique(tech_ind)]
            related_actors = [a.name for a in self.onto.get_actors_for_technique(tech_ind)]

        # 11) CVE Auto-Promotion
        # If no explicit CVE was found in the text, but the LLM suggested related CVEs,
        # promote the first suggestion to be the primary 'cve_id'.
        # This ensures it appears in the UI header and PDF report.
        if not llm_result.get("cve_id") and llm_result.get("related_cves"):
             llm_result["cve_id"] = llm_result["related_cves"][0]

        return {
            "llm_raw": llm_result,
            "mapped_technique": mapped_technique,
            "mapped_tactics": mapped_tactics,
            "symbolic_note": symbolic_note,
            "final_explanation": llm_result.get("brief_reasoning", ""),
            "related_cves": llm_result.get("related_cves", []),
            "iocs": iocs,
            "ioc_reputation": ioc_reputation,
            "risk_level": risk_level,
            "confidence": confidence,
            "mitre_id": mitre_id,
            "nice_technique_name": nice_tech_name,
            "attack_summary": attack_summary,
            "defense_recommendations": defense_data.get("prevention", []),
            "defense_detection": defense_data.get("detection", []),
            "defense_d3fend": defense_data.get("d3fend", []),
            "related_malware": related_malware,
            "related_actors": related_actors,
        }


if __name__ == "__main__":
    pipe = NeuroSymbolicPipeline()
    text = "CVE-2021-1234 allows remote code execution on a public-facing web server."
    print(pipe.analyze_document(text))
