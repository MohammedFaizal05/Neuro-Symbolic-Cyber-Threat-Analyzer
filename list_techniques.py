from ontology_engine import OntologyEngine

eng = OntologyEngine()
print("--- TECHNIQUES ---")
for cls in eng.onto.classes():
    if cls.name == "Technique":
        for inst in cls.instances():
            print(inst.name)
