#!/usr/bin/env python3
# linux_auditd_monitor.py

from sigma.collection import SigmaCollection
from sigma.backends.test import TextQueryTestBackend
from sigma.pipelines.ocsf import ocsf_pipeline

class LinuxSecurityMonitor:
    def __init__(self):
        self.backend = TextQueryTestBackend(ocsf_pipeline())
    
    def auditd_rules(self):
        """Convert Linux auditd monitoring rules to OCSF"""
        rules = {
            "privilege_escalation": """
title: Linux Privilege Escalation via Sudo
logsource:
    product: linux
    service: sudo
detection:
    sel:
        USER|contains: 'root'
        COMMAND|contains:
            - '/bin/bash'
            - '/bin/sh'
            - 'su -'
    condition: sel
""",
            "ssh_brute_force": """
title: SSH Brute Force Attempt
logsource:
    product: linux
    service: sshd
detection:
    sel:
        msg|contains: 'Failed password'
    condition: sel | count() > 5
""",
            "file_permission_change": """
title: Suspicious File Permission Changes
logsource:
    product: linux
    service: auditd
detection:
    sel:
        type: 'SYSCALL'
        syscall|contains:
            - 'chmod'
            - 'chown'
        exe|endswith:
            - '/chmod'
            - '/chown'
    condition: sel
"""
        }
        
        converted_rules = {}
        for rule_name, rule_yaml in rules.items():
            try:
                rule = SigmaCollection.from_yaml(rule_yaml)
                ocsf_queries = self.backend.convert(rule)
                converted_rules[rule_name] = ocsf_queries
            except Exception as e:
                print(f"Failed to convert {rule_name}: {e}")
        
        return converted_rules

# Usage
monitor = LinuxSecurityMonitor()
linux_rules = monitor.auditd_rules()

for rule_name, queries in linux_rules.items():
    print(f"\n=== {rule_name.upper()} ===")
    for query in queries:
        print(query)
