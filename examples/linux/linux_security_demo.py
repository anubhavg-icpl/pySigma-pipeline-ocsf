#!/usr/bin/env python3
# linux_security_demo.py - Complete Linux security monitoring demo

from sigma.collection import SigmaCollection
from sigma.backends.test import TextQueryTestBackend
from sigma.pipelines.ocsf import ocsf_pipeline
import json

def main():
    """Demonstrate Linux security monitoring with OCSF conversion"""

    backend = TextQueryTestBackend(ocsf_pipeline())

    # Linux Security Rules for different attack vectors
    security_rules = {
        "Suspicious Process Execution": """
title: Suspicious Linux Process Execution
logsource:
    category: process_creation
    product: linux
detection:
    sel:
        Image|endswith:
            - '/nc'
            - '/ncat'
            - '/netcat'
        CommandLine|contains:
            - '-e /bin/sh'
            - '-e /bin/bash'
    condition: sel
""",
        "Critical File Access": """
title: Critical File Access on Linux
logsource:
    category: file_event
    product: linux
detection:
    sel:
        TargetFilename|contains:
            - '/etc/passwd'
            - '/etc/shadow'
            - '/root/.ssh'
    condition: sel
""",
        "Suspicious Network Activity": """
title: Suspicious Network Connection
logsource:
    category: network_connection
    product: linux
detection:
    sel:
        DestinationPort:
            - 4444
            - 5555
            - 1337
        Initiated: true
    condition: sel
""",
        "Privilege Escalation Attempt": """
title: Linux Privilege Escalation
logsource:
    category: process_creation
    product: linux
detection:
    sel:
        CommandLine|contains:
            - 'sudo su'
            - 'su -'
            - 'sudo -i'
        Image|endswith:
            - '/sudo'
            - '/su'
    condition: sel
""",
        "Persistence Mechanism": """
title: Linux Persistence via Crontab
logsource:
    category: file_event
    product: linux
detection:
    sel:
        TargetFilename|contains:
            - '/etc/crontab'
            - '/var/spool/cron'
            - '/etc/cron.d'
    condition: sel
"""
    }

    print("🔒 Linux Security Monitoring - OCSF Conversion Demo")
    print("=" * 60)

    converted_rules = {}

    for rule_name, rule_yaml in security_rules.items():
        try:
            rule = SigmaCollection.from_yaml(rule_yaml)
            ocsf_queries = backend.convert(rule)
            converted_rules[rule_name] = ocsf_queries

            print(f"\n📋 {rule_name}")
            print("-" * 40)
            for query in ocsf_queries:
                print(f"OCSF Query: {query}")

        except Exception as e:
            print(f"❌ Failed to convert {rule_name}: {e}")

    # Export to JSON for SIEM integration
    export_data = {
        "metadata": {
            "description": "Linux security rules converted to OCSF format",
            "generated_by": "pySigma OCSF Pipeline",
            "timestamp": "2025-05-22",
            "platform": "linux"
        },
        "rules": []
    }

    for rule_name, queries in converted_rules.items():
        for i, query in enumerate(queries):
            export_data["rules"].append({
                "id": f"linux_{rule_name.lower().replace(' ', '_')}_{i}",
                "name": rule_name,
                "ocsf_query": query,
                "category": "security",
                "platform": "linux"
            })

    # Save to file
    with open("linux_security_ocsf.json", "w") as f:
        json.dump(export_data, f, indent=2)

    print(f"\n✅ Exported {len(export_data['rules'])} rules to 'linux_security_ocsf.json'")
    print(f"📊 Successfully converted {len(converted_rules)} rule categories")

if __name__ == "__main__":
    main()
