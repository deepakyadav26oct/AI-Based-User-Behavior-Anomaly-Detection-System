from typing import Dict, Any, List

MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
    'RULE_BRUTE_FORCE': {
        'id': 'T1110.001',
        'tactic': 'Credential Access',
        'name': 'Brute Force: Password Guessing',
        'description': 'Adversary repeatedly attempts authentication passwords against valid account names to gain unauthorized access.',
        'url': 'https://attack.mitre.org/techniques/T1110/001/'
    },
    'RULE_IMPOSSIBLE_TRAVEL': {
        'id': 'T1078.004',
        'tactic': 'Defense Evasion & Initial Access',
        'name': 'Valid Accounts: Cloud / Enterprise Accounts',
        'description': 'Adversary leverages stolen credentials from geographically disparate locations, violating Haversine physical velocity limits.',
        'url': 'https://attack.mitre.org/techniques/T1078/004/'
    },
    'RULE_CRITICAL_RESOURCE': {
        'id': 'T1083',
        'tactic': 'Discovery & Credential Access',
        'name': 'File and Directory Discovery',
        'description': 'Adversary enumerates and probes sensitive application assets including credential stores, system configuration, and payroll vaults.',
        'url': 'https://attack.mitre.org/techniques/T1083/'
    },
    'RULE_SUSPICIOUS_TOOLING': {
        'id': 'T1588.002',
        'tactic': 'Resource Development',
        'name': 'Obtain Capabilities: Penetration Testing Tool',
        'description': 'Adversary interacts with authentication endpoints via adversarial distributions (Kali Linux, Parrot OS, Tor Browser) or automated scraping utilities.',
        'url': 'https://attack.mitre.org/techniques/T1588/002/'
    },
    'RULE_NEW_IP': {
        'id': 'T1071.001',
        'tactic': 'Command and Control',
        'name': 'Application Layer Protocol: Web Protocols',
        'description': 'Adversary establishes authentication session through previously unobserved foreign IP, proxy, or anonymous ASN infrastructure.',
        'url': 'https://attack.mitre.org/techniques/T1071/001/'
    },
    'RULE_UNUSUAL_HOUR': {
        'id': 'T1078',
        'tactic': 'Defense Evasion',
        'name': 'Valid Accounts: Schedule Anomaly',
        'description': 'Authentication attempted during anomalous off-hours schedule (e.g. 02:00 AM) to circumvent active administrator vigilance.',
        'url': 'https://attack.mitre.org/techniques/T1078/'
    },
    'RULE_NEW_DEVICE': {
        'id': 'T1204',
        'tactic': 'Execution',
        'name': 'User Execution: Rogue Client Device',
        'description': 'Session initiated from an unrecognized hardware device signature or spoofed User-Agent environment.',
        'url': 'https://attack.mitre.org/techniques/T1204/'
    },
    'RULE_ML_ANOMALY': {
        'id': 'T1078',
        'tactic': 'Initial Access',
        'name': 'Valid Accounts: Multi-Vector Outlier',
        'description': 'Isolation Forest identified extreme multi-dimensional divergence across timing, velocity, frequency, and duration dimensions.',
        'url': 'https://attack.mitre.org/techniques/T1078/'
    }
}

class MitreAttackMapper:
    """
    Standardized mapper connecting Sentinel AI behavioral rules and ML anomalies
    to official MITRE ATT&CK Enterprise Matrix tactics and techniques.
    """

    @classmethod
    def get_technique_for_rule(cls, rule_flag: str) -> Dict[str, str]:
        """Resolve a specific rule flag to its corresponding MITRE ATT&CK technique."""
        return MITRE_TECHNIQUES.get(rule_flag, {
            'id': 'T1078',
            'tactic': 'Initial Access',
            'name': 'Valid Accounts: General Anomaly',
            'description': 'Behavioral anomaly detected in user account telemetry.',
            'url': 'https://attack.mitre.org/techniques/T1078/'
        })

    @classmethod
    def map_rule_flags(cls, rule_flags: List[str]) -> List[Dict[str, str]]:
        """Map a list of rule flags to unique MITRE ATT&CK techniques."""
        seen_ids = set()
        results = []
        for flag in rule_flags:
            tech = cls.get_technique_for_rule(flag)
            if tech['id'] not in seen_ids:
                seen_ids.add(tech['id'])
                results.append(tech)
        return results

    @classmethod
    def get_all_matrix_techniques(cls) -> List[Dict[str, Any]]:
        """Return the complete catalog of mapped MITRE ATT&CK tactics & techniques."""
        return list(MITRE_TECHNIQUES.values())
