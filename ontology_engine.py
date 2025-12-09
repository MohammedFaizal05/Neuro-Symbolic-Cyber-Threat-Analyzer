from owlready2 import get_ontology
import re

ONTO_PATH = "../ontology/cyber_ontology.owl"


def _normalize(s: str) -> str:
    """Lowercase + remove all non-alphanumeric chars."""
    return re.sub(r"[^a-z0-9]", "", s.lower()) if s else ""


class OntologyEngine:
    def __init__(self, path: str = ONTO_PATH):
        self.onto = get_ontology(path).load()

    def find_technique_by_name(self, name: str):
        """Fuzzy match technique name to ontology individuals."""
        if not name:
            return []

        target = _normalize(name)
        candidates = []

        for cls in self.onto.classes():
            if cls.name == "Technique":   # only our Technique class
                for inst in cls.instances():
                    inst_norm = _normalize(inst.name)
                    # match if either string contains the other
                    if target and (target in inst_norm or inst_norm in target):
                        candidates.append(inst)

        return candidates

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
