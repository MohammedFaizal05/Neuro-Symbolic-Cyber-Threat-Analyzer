from ontology_engine import OntologyEngine

eng = OntologyEngine("cyber_ontology.owl")
print("Ontology loaded.")

# Test a technique we enriched, e.g., T1190 or T1059
tech_name = "T1190_ExploitPublicFacingApplication"
# In ontology, names might have underscores or look different, let's search
candidates = eng.find_technique_by_name("Exploit Public-Facing Application")
if not candidates:
    print("Could not find technique 'Exploit Public-Facing Application'")
else:
    tech = candidates[0]
    print(f"Found technique: {tech.name}")
    
    prev = eng.get_prevention_recommendations(tech)
    print(f"Prevention ({len(prev)}): {prev}")
    
    det = eng.get_detection_logic(tech)
    print(f"Detection ({len(det)}): {det}")
    
    d3 = eng.get_d3fend_mitigations(tech)
    print(f"D3FEND ({len(d3)}): {d3}")

print("Test complete.")
