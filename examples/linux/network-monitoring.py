#!/usr/bin/env python3
from sigma.collection import SigmaCollection
from sigma.backends.test import TextQueryTestBackend
from sigma.pipelines.ocsf import ocsf_pipeline

backend = TextQueryTestBackend(ocsf_pipeline())

# Detect suspicious network connections
linux_network_rule = """
title: Suspicious Linux Network Connection
logsource:
    category: network_connection
    product: linux
detection:
    sel:
        DestinationPort:
            - 4444
            - 5555
            - 6666
        Initiated: true
    condition: sel
"""

rule = SigmaCollection.from_yaml(linux_network_rule)
ocsf_query = backend.convert(rule)
print("Linux Network Connection -> OCSF:")
print(ocsf_query[0])
