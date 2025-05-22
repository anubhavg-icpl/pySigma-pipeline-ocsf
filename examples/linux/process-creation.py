#!/usr/bin/env python3
from sigma.collection import SigmaCollection
from sigma.backends.test import TextQueryTestBackend
from sigma.pipelines.ocsf import ocsf_pipeline

backend = TextQueryTestBackend(ocsf_pipeline())

# Suspicious Linux process execution
linux_process_rule = """
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
"""

rule = SigmaCollection.from_yaml(linux_process_rule)
ocsf_query = backend.convert(rule)
print("Linux Process Creation -> OCSF:")
print(ocsf_query[0])
