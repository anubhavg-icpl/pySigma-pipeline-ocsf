#!/usr/bin/env python3
# linux_threat_hunting.py

import subprocess
import json
from pathlib import Path

class LinuxThreatHunter:
    def __init__(self):
        self.backend = TextQueryTestBackend(ocsf_pipeline())
    
    def common_linux_attacks(self):
        """Generate OCSF queries for common Linux attack patterns"""
        
        attack_patterns = {
            "reverse_shell": """
title: Linux Reverse Shell Detection
logsource:
    category: process_creation
    product: linux
detection:
    sel:
        CommandLine|contains:
            - 'bash -i'
            - 'sh -i'
            - '/dev/tcp/'
            - 'nc -e'
            - 'ncat -e'
    condition: sel
""",
            "persistence_mechanisms": """
title: Linux Persistence via Cron
logsource:
    category: file_event
    product: linux
detection:
    sel:
        TargetFilename|contains:
            - '/etc/crontab'
            - '/var/spool/cron'
            - '/etc/cron.d/'
    condition: sel
""",
            "lateral_movement": """
title: Linux Lateral Movement via SSH
logsource:
    category: network_connection
    product: linux
detection:
    sel:
        DestinationPort: 22
        Image|endswith: '/ssh'
    condition: sel
""",
            "data_exfiltration": """
title: Linux Data Exfiltration
logsource:
    category: process_creation
    product: linux
detection:
    sel:
        CommandLine|contains:
            - 'curl -X POST'
            - 'wget --post'
            - 'scp'
            - 'rsync'
        Image|endswith:
            - '/curl'
            - '/wget'
            - '/scp'
            - '/rsync'
    condition: sel
"""
        }
        
        ocsf_rules = {}
        for attack_type, rule_yaml in attack_patterns.items():
            rule = SigmaCollection.from_yaml(rule_yaml)
            ocsf_rules[attack_type] = self.backend.convert(rule)
        
        return ocsf_rules
    
    def export_for_siem(self, output_file: str = "linux_threats_ocsf.json"):
        """Export Linux threat hunting rules in OCSF format for SIEM integration"""
        rules = self.common_linux_attacks()
        
        export_data = {
            "metadata": {
                "description": "Linux threat hunting rules in OCSF format",
                "generated_by": "pySigma OCSF Pipeline",
                "target_platform": "linux"
            },
            "rules": []
        }
        
        for attack_type, queries in rules.items():
            for i, query in enumerate(queries):
                export_data["rules"].append({
                    "id": f"linux_{attack_type}_{i}",
                    "attack_type": attack_type,
                    "ocsf_query": query,
                    "severity": self._get_severity(attack_type)
                })
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"Exported {len(export_data['rules'])} Linux threat hunting rules to {output_file}")
    
    def _get_severity(self, attack_type: str) -> str:
        severity_map = {
            "reverse_shell": "high",
            "persistence_mechanisms": "medium", 
            "lateral_movement": "medium",
            "data_exfiltration": "high"
        }
        return severity_map.get(attack_type, "medium")

# Usage
hunter = LinuxThreatHunter()
hunter.export_for_siem("arch_linux_threats.json")
