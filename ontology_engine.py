from owlready2 import get_ontology
import re
import os

# Try multiple possible paths for the ontology file
ONTO_PATH = None
possible_paths = [
    "cyber_ontology.owl",  # Same directory
    "../ontology/cyber_ontology.owl",  # Parent ontology directory
    os.path.join(os.path.dirname(__file__), "cyber_ontology.owl"),  # Same directory as this file
    os.path.join(os.path.dirname(__file__), "..", "ontology", "cyber_ontology.owl"),  # Relative to this file
]

for path in possible_paths:
    if os.path.exists(path):
        ONTO_PATH = path
        break

if ONTO_PATH is None:
    # Default fallback
    ONTO_PATH = "cyber_ontology.owl"


def _normalize(s: str) -> str:
    """Lowercase + remove all non-alphanumeric chars."""
    return re.sub(r"[^a-z0-9]", "", s.lower()) if s else ""


class OntologyEngine:
    def __init__(self, path: str = ONTO_PATH):
        self.onto = get_ontology(path).load()

    COMMON_ALIASES = {
        "remote code execution": "T1190_ExploitPublic-FacingApplication",
        "rce": "T1190_ExploitPublic-FacingApplication",
        "log4shell": "T1190_ExploitPublic-FacingApplication",
        "phishing": "T1566_Phishing",
        "spearphishing": "T1566_Phishing",
        "sql injection": "T1190_ExploitPublic-FacingApplication",
        "sqli": "T1190_ExploitPublic-FacingApplication",
        "xss": "T1190_ExploitPublic-FacingApplication",
        "powershell": "T1059.001_PowerShell",
        "cmd": "T1059_CommandandScriptingInterpreter",
        "command line": "T1059_CommandandScriptingInterpreter",
        "ransomware": "T1486_DataEncryptedforImpact",
        "privilege escalation": "T1068_ExploitationforPrivilegeEscalation",
        "local privilege escalation": "T1068_ExploitationforPrivilegeEscalation",
        "lpe": "T1068_ExploitationforPrivilegeEscalation",
        "pwnkit": "T1068_ExploitationforPrivilegeEscalation",
        "cve-2021-4034": "T1068_ExploitationforPrivilegeEscalation",
    }

    def find_technique_by_name(self, name: str):
        """
        Robust technique matching:
        1. Alias lookup.
        2. Exact/Fuzzy match on name.
        3. Token set intersection for better hit rate.
        """
        if not name:
            return []
            
        # 0. Alias Lookup
        lower_name = name.lower().strip()
        if lower_name in self.COMMON_ALIASES:
            target_alias = self.COMMON_ALIASES[lower_name]
            # Find this specific instance
            for cls in self.onto.classes():
                if cls.name == "Technique":
                    for inst in cls.instances():
                        if inst.name == target_alias:
                            return [inst]

        target = _normalize(name)
        target_tokens = set(target.split())
        candidates = []
        best_score = 0
        best_match = None

        for cls in self.onto.classes():
            if cls.name == "Technique":
                for inst in cls.instances():
                    inst_norm = _normalize(inst.name)
                    
                    # 1. Substring Match
                    if target and (target in inst_norm or inst_norm in target):
                        # Calculate length diff to prefer exact matches
                        score = 100 - abs(len(target) - len(inst_norm))
                        candidates.append((score, inst))
                    
                    # 2. Token Overlap (matches "Exploit Public-Facing" with "Exploit Public Facing Application")
                    inst_tokens = set(inst_norm.split())
                    overlap = len(target_tokens.intersection(inst_tokens))
                    if overlap > 0:
                        # Jaccard-ish score
                        score = (overlap / len(inst_tokens.union(target_tokens))) * 50
                        candidates.append((score, inst))

        # Sort by score descending
        candidates.sort(key=lambda x: x[0], reverse=True)
        
        # Return top matches (just specific instances)
        # Deduplicate while preserving order
        seen = set()
        final_results = []
        for score, inst in candidates:
            if inst not in seen:
                final_results.append(inst)
                seen.add(inst)
        
        return final_results

    def get_tactics_for_technique(self, technique_individual):
        """Return all Tactic individuals linked via belongsToTactic."""
        if hasattr(self.onto, "belongsToTactic"):
            return list(technique_individual.belongsToTactic)
        return []

    def get_malware_for_technique(self, technique_individual):
        """
        Return all Malware individuals that use this technique
        via malwareUsesTechnique property.
        """
        results = []
        try:
            malware_class = getattr(self.onto, "Malware", None)
            prop = getattr(self.onto, "malwareUsesTechnique", None)
            if malware_class is None or prop is None:
                return []

            for m in malware_class.instances():
                if technique_individual in getattr(m, "malwareUsesTechnique", []):
                    results.append(m)
        except Exception:
            # fail-quiet; pipeline will just show empty list
            return []
        return results

    def get_actors_for_technique(self, technique_individual):
        """
        Return all ThreatActor individuals that use this technique
        via actorUsesTechnique property.
        """
        results = []
        try:
            actor_class = getattr(self.onto, "ThreatActor", None)
            prop = getattr(self.onto, "actorUsesTechnique", None)
            if actor_class is None or prop is None:
                return []

            for a in actor_class.instances():
                if technique_individual in getattr(a, "actorUsesTechnique", []):
                    results.append(a)
        except Exception:
            # fail-quiet; pipeline will just show empty list
            return []
        return results

    def get_prevention_recommendations(self, technique_individual):
        """Return list of prevention strings from hasPreventionRecommendation."""
        if hasattr(technique_individual, "hasPreventionRecommendation"):
            return list(technique_individual.hasPreventionRecommendation)
        return []

    def get_detection_logic(self, technique_individual):
        """Return list of detection strings from hasDetectionLogic."""
        if hasattr(technique_individual, "hasDetectionLogic"):
            return list(technique_individual.hasDetectionLogic)
        return []

    def get_d3fend_mitigations(self, technique_individual):
        """Return list of DefensiveTechnique names that mitigate this technique."""
        # Query DefensiveTechnique instances that have 'mitigates' matching this technique
        results = []
        try:
            def_class = getattr(self.onto, "DefensiveTechnique", None)
            if not def_class:
                return []
            
            for d in def_class.instances():
                if hasattr(d, "mitigates") and technique_individual in d.mitigates:
                    results.append(d.name)
        except Exception:
            return []
        return results


if __name__ == "__main__":
    eng = OntologyEngine()
    print("Ontology loaded!")
    print("All techniques:")
    for inst in eng.onto.Technique.instances():
        print(" -", inst.name)

    # Small debug: malware & actors for a known technique
    if hasattr(eng.onto, "T1486_DataEncryptedForImpact"):
        tech = eng.onto.T1486_DataEncryptedForImpact
        print("\nMalware using T1486_DataEncryptedForImpact:")
        for m in eng.get_malware_for_technique(tech):
            print(" -", m.name)

        print("\nThreat actors using T1486_DataEncryptedForImpact:")
        for a in eng.get_actors_for_technique(tech):
            print(" -", a.name)
