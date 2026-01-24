import os
import types
from owlready2 import *

# -------------------------------------------------------------------------
# 1. KNOWLEDGE BASE (Raw Data)
# -------------------------------------------------------------------------
# This dictionary mimics the structure we want to inject into the ontology.
# It includes:
# - Technique ID & Name
# - Tactics
# - Prevention Recommendations (Strings)
# - Detection Logic (Strings)
# - D3FEND-style Mitigations (Concept Links)

MITRE_KB = {
    # --- RECONNAISSANCE ---
    "T1595": {
        "name": "Active Scanning",
        "tactics": ["Reconnaissance"],
        "prevention": [
            "Use firewalls to block unnecessary ports.",
            "Implement intrusion detection/prevention systems (IDS/IPS)."
        ],
        "detection": [
            "Monitor for sequential port scans or sweep scans from single GPs.",
            "Analyze flow logs for high volume of rejected connections."
        ],
        "d3fend": ["D_NetworkTrafficFiltering", "D_DecoyEnvironment"]
    },
    
    # --- INITIAL ACCESS ---
    "T1566": {
        "name": "Phishing",
        "tactics": ["Initial Access"],
        "prevention": [
            "Implement SPF, DKIM, and DMARC.",
            "User training on identifying suspicious emails.",
            "Block executable attachments."
        ],
        "detection": [
            "Monitor for emails with known malicious domains.",
            "Analyze email headers for inconsistencies."
        ],
        "d3fend": ["D_EmailFiltering", "D_UserTraining"]
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactics": ["Initial Access"],
        "prevention": [
            "Patch applications immediately.",
            "Use Web Application Firewalls (WAF).",
            "Minimize internet-facing surface area."
        ],
        "detection": [
            "Monitor application logs for crash reports or error codes.",
            "Inspect HTTP traffic for SQLi/XSS patterns."
        ],
        "d3fend": ["D_WebApplicationFirewall", "D_ApplicationHardening"]
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
        "prevention": [
            "Enforce Multi-Factor Authentication (MFA).",
            "Disable default or unused accounts.",
            "Regularly rotate passwords."
        ],
        "detection": [
            "Monitor for simultaneous logins from different locations.",
            "Detect logins at unusual times."
        ],
        "d3fend": ["D_MFAAndStrongAuth", "D_AccountMonitoring"]
    },

    # --- EXECUTION ---
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactics": ["Execution"],
        "prevention": [
            "Restrict PowerShell execution policy.",
            "Disable command-line interpreters for standard users."
        ],
        "detection": [
            "Enable PowerShell script block logging.",
            "Monitor process creation events (Event ID 4688)."
        ],
        "d3fend": ["D_ExecutionIsolation", "D_ScriptAnalysis"]
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactics": ["Execution"],
        "prevention": [
            "Set ExecutionPolicy to RemoteSigned or Restricted.",
            "Use AppLocker to block powershell.exe."
        ],
        "detection": [
            "Monitor for EncodedCommand usage.",
            "Analyze PowerShell history files."
        ],
        "d3fend": ["D_ExecutionIsolation", "D_EDRMonitoring"]
    },
    "T1204": {
        "name": "User Execution",
        "tactics": ["Execution"],
        "prevention": [
            "Use application control/whitelisting.",
            "Disable macros in Office documents."
        ],
        "detection": [
            "Monitor execution of unknown binaries.",
            "Alert on children processes spawned by Office apps."
        ],
        "d3fend": ["D_ProcessWhitelisting", "D_UserTraining"]
    },

    # --- PERSISTENCE ---
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactics": ["Persistence", "Execution", "Privilege Escalation"],
        "prevention": [
            "Restrict permissions to create scheduled tasks.",
            "Monitor creation of new tasks."
        ],
        "detection": [
            "Monitor Event ID 4698 (Task Created).",
            "Review scheduled tasks for unknown binaries."
        ],
        "d3fend": ["D_SystemConfigurationPermissions", "D_ProcessMonitoring"]
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactics": ["Persistence", "Privilege Escalation"],
        "prevention": [
            "Use Sysinternals Autoruns to audit startup.",
            "Restrict registry write access to Run keys."
        ],
        "detection": [
            "Monitor registry changes to HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run."
        ],
        "d3fend": ["D_RegistryPermissions", "D_ConfigurationAudit"]
    },

    # --- PRIVILEGE ESCALATION ---
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactics": ["Privilege Escalation"],
        "prevention": [
            "Apply OS security patches.",
            "Use memory protection (ASLR, DEP)."
        ],
        "detection": [
            "Monitor for crash dumps of system processes.",
            "Detect processes spawning as SYSTEM unexpectedly."
        ],
        "d3fend": ["D_PatchManagement", "D_ExploitMitigation"]
    },

    # --- DEFENSE EVASION ---
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactics": ["Defense Evasion"],
        "prevention": [
            "Restrict execution of unknown scripts.",
            "Use signature-based AV."
        ],
        "detection": [
            "Analyze high entropy strings in commands.",
            "Detect base64 encoded payloads."
        ],
        "d3fend": ["D_SignatureAnalysis", "D_HeuristicAnalysis"]
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactics": ["Defense Evasion"],
        "prevention": [
            "Forward logs to a remote SIEM immediately.",
            "Set strict permissions on audit logs."
        ],
        "detection": [
            "Alert on Event ID 1102 (Log Cleared).",
            "Monitor deletion of .evtx files."
        ],
        "d3fend": ["D_LogIntegrityProtection", "D_RemoteLogging"]
    },

    # --- CREDENTIAL ACCESS ---
    "T1003": {
        "name": "OS Credential Dumping",
        "tactics": ["Credential Access"],
        "prevention": [
            "Enable Credential Guard.",
            "Restrict access to LSASS process."
        ],
        "detection": [
            "Monitor access handle requests to lsass.exe.",
            "Detect execution of Mimikatz-like tools."
        ],
        "d3fend": ["D_CredentialGuidance", "D_MemoryProtection"]
    },
    "T1110": {
        "name": "Brute Force",
        "tactics": ["Credential Access"],
        "prevention": [
            "Implement account lockout policies.",
            "Use CAPTCHA on login portals."
        ],
        "detection": [
            "Alert on high volume of failed logins (Event ID 4625).",
            "Detect multiple failures followed by success."
        ],
        "d3fend": ["D_AccountLockout", "D_AuthenticationRateLimiting"]
    },

    # --- DISCOVERY ---
    "T1087": {
        "name": "Account Discovery",
        "tactics": ["Discovery"],
        "prevention": [
            "Restrict 'net user' and similar commands.",
            "Audit AD queries."
        ],
        "detection": [
            "Monitor use of 'net user', 'net group', 'whoami'.",
            "Detect LDAP enumeration queries."
        ],
        "d3fend": ["D_CommandMonitoring", "D_DirectoryAccessControl"]
    },
    "T1046": {
        "name": "Network Service Scanning",
        "tactics": ["Discovery"],
        "prevention": [
            "Disable unnecessary services.",
            "Use host-based firewalls."
        ],
        "detection": [
            "Detect rapid connection attempts to multiple ports.",
            "Monitor for 'nmap' execution artifacts."
        ],
        "d3fend": ["D_NetworkTrafficAnalysis", "D_HoneyTokens"]
    },

    # --- LATERAL MOVEMENT ---
    "T1021": {
        "name": "Remote Services",
        "tactics": ["Lateral Movement"],
        "prevention": [
            "Disable SMBv1.",
            "Restrict RDP access via firewall."
        ],
        "detection": [
            "Monitor for new service creations (Event 4697).",
            "Analyze RDP logins from non-admin workstations."
        ],
        "d3fend": ["D_NetworkSegmentation", "D_JumpHost"]
    },
    "T1091": {
        "name": "Replication Through Removable Media",
        "tactics": ["Lateral Movement", "Initial Access"],
        "prevention": [
            "Disable AutoRun.",
            "Restrict USB device usage."
        ],
        "detection": [
            "Monitor mount events of removable drives.",
            "Scan USB files before access."
        ],
        "d3fend": ["D_PeripheralRestrictions", "D_MediaScanning"]
    },

    # --- COLLECTION ---
    "T1005": {
        "name": "Data from Local System",
        "tactics": ["Collection"],
        "prevention": [
            "Encrypt sensitive files at rest.",
            "Implement strict file permissions."
        ],
        "detection": [
            "Monitor bulk file reads.",
            "Detect access to sensitive directories by non-owners."
        ],
        "d3fend": ["D_FileEncryption", "D_AccessControl"]
    },

    # --- COMMAND AND CONTROL ---
    "T1071": {
        "name": "Application Layer Protocol",
        "tactics": ["Command and Control"],
        "prevention": [
            "Use proxy with application-aware filtering.",
            "Block unknown user-agents."
        ],
        "detection": [
            "Analyze beaconing patterns in HTTP traffic.",
            "Detect long communication sessions."
        ],
        "d3fend": ["D_ProtocolAnalysis", "D_TrafficFiltering"]
    },

    # --- EXFILTRATION ---
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactics": ["Exfiltration"],
        "prevention": [
            "Restrict upload sizes on proxies.",
            "Enforce egress filtering."
        ],
        "detection": [
            "Monitor large outbound data transfers.",
            "Detect unusual upload spikes during off-hours."
        ],
        "d3fend": ["D_DataLossPrevention", "D_EgressFiltering"]
    },

    # --- IMPACT ---
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactics": ["Impact"],
        "prevention": [
            "Maintain offline backups.",
            "Restrict file modification rates."
        ],
        "detection": [
            "Monitor for mass file renaming (e.g., .lock, .enc).",
            "Detect high I/O operations."
        ],
        "d3fend": ["D_BackupAndRecovery", "D_FileIntegrityMonitoring"]
    }
}

# -------------------------------------------------------------------------
# 2. ONTOLOGY ENRICHMENT SCRIPT
# -------------------------------------------------------------------------

def enrich_ontology():
    onto_path = "cyber_ontology.owl"
    
    # helper for safe strings
    def clean(s):
        # Remove all non-alphanumeric characters (keep only letters and numbers)
        return "".join(c for c in s if c.isalnum())

    print(f"Loading ontology from {onto_path}...")
    onto = get_ontology(onto_path).load()

    with onto:
        # -----------------------------------------------------------------
        # A. DEFINE NEW PROPERTIES
        # -----------------------------------------------------------------
        print("Defining new properties...")
        
        # New data property: hasPreventionRecommendation
        class hasPreventionRecommendation(DataProperty):
            domain = [onto.Technique]
            range = [str]

        # New data property: hasDetectionLogic
        class hasDetectionLogic(DataProperty):
            domain = [onto.Technique]
            range = [str]
            
        # Ensure DefensiveTechnique exists
        if not onto.DefensiveTechnique:
            class DefensiveTechnique(Thing):
                pass
        
        # Ensure mitigates exists
        if not onto.mitigates:
            class mitigates(ObjectProperty):
                domain = [onto.DefensiveTechnique]
                range = [onto.Technique]

        # -----------------------------------------------------------------
        # B. POPULATE KNOWLEDGE BASE
        # -----------------------------------------------------------------
        print("Populating knowledge base...")

        for tech_id, data in MITRE_KB.items():
            # Create/Find Technique Individual
            # Format: "T1234_TechniqueName" (No spaces)
            safe_name = f"{tech_id}_{clean(data['name'])}"
            
            # Check if exists, else create
            tech_inst = onto.search_one(iri=f"*{safe_name}")
            if not tech_inst:
                print(f"Creating new technique: {safe_name}")
                tech_inst = onto.Technique(safe_name)
            else:
                # Update label if needed
                pass

            # 1. Add Prevention Recommendations
            tech_inst.hasPreventionRecommendation = []  # Clear old
            for prev in data["prevention"]:
                tech_inst.hasPreventionRecommendation.append(prev)

            # 2. Add Detection Logic
            tech_inst.hasDetectionLogic = []  # Clear old
            for det in data["detection"]:
                tech_inst.hasDetectionLogic.append(det)

            # 3. Link Tactics (create if missing)
            for tac_name in data["tactics"]:
                safe_tac = clean(tac_name)
                tac_inst = onto.search_one(iri=f"*{safe_tac}")
                
                # If tactic doesn't exist, create it (should match Tactic class)
                if not tac_inst:
                     # try to find by simple name match in existing individuals
                    pass 
                
                if tac_inst and hasattr(tech_inst, 'belongsToTactic'):
                    if tac_inst not in tech_inst.belongsToTactic:
                        tech_inst.belongsToTactic.append(tac_inst)

            # 4. Link D3FEND Defenses
            for d3_name in data["d3fend"]:
                # Create/Find D3FEND individual
                d3_inst = onto.search_one(iri=f"*{d3_name}")
                if not d3_inst:
                    d3_inst = onto.DefensiveTechnique(d3_name)
                
                # Link mitigation: d3_inst mitigates tech_inst
                if tech_inst not in d3_inst.mitigates:
                    d3_inst.mitigates.append(tech_inst)

    # -----------------------------------------------------------------
    # C. SAVE UPDATED ONTOLOGY
    # -----------------------------------------------------------------
    output_path = "cyber_ontology.owl" # Overwrite existing
    onto.save(file=output_path)
    print(f"Ontology enriched and saved to {output_path}")

if __name__ == "__main__":
    enrich_ontology()
