MITRE_MAPPING = {
    "brute_force": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
    },
    "port_scan": {
        "technique": "T1046",
        "name": "Network Service Scanning",
        "tactic": "Discovery",
    },
    "suspicious_process": {
        "technique": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "malware": {
        "technique": "T1204",
        "name": "User Execution",
        "tactic": "Execution",
    },
    "data_exfiltration": {
        "technique": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
    },
}


def map_mitre(event_type: str) -> str:
    entry = MITRE_MAPPING.get(event_type)
    if not entry:
        return ""
    return f"{entry['technique']} {entry['name']} ({entry['tactic']})"
