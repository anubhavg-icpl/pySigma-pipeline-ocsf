#!/bin/bash
# integrate_with_wazuh.sh - Convert Sigma rules for Wazuh SIEM

python3 << 'EOF'
from sigma.collection import SigmaCollection
from sigma.backends.test import TextQueryTestBackend
from sigma.pipelines.ocsf import ocsf_pipeline

# Generate Wazuh-compatible OCSF rules for Linux monitoring
backend = TextQueryTestBackend(ocsf_pipeline())

wazuh_linux_rules = [
    """
title: Linux Rootkit Detection
logsource:
    category: file_event
    product: linux
detection:
    sel:
        TargetFilename|contains:
            - '/dev/shm/'
            - '/tmp/.'
            - '/var/tmp/.'
    condition: sel
""",
    """
title: Linux Command Injection
logsource:
    category: process_creation
    product: linux
detection:
    sel:
        CommandLine|contains:
            - ';rm -rf'
            - '&&rm -rf'
            - '|rm -rf'
    condition: sel
"""
]

print("<!-- Wazuh Linux Rules in OCSF Format -->")
for i, rule_yaml in enumerate(wazuh_linux_rules):
    rule = SigmaCollection.from_yaml(rule_yaml)
    queries = backend.convert(rule)
    for query in queries:
        print(f"<rule id=\"{20000+i}\" level=\"10\">")
        print(f"  <description>Linux Security Alert</description>")
        print(f"  <ocsf_query>{query}</ocsf_query>")
        print("</rule>")
EOF
