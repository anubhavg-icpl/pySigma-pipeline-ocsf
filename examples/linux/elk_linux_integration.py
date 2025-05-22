#!/usr/bin/env python3
# elk_linux_integration.py

import json
from sigma.collection import SigmaCollection
from sigma.backends.test import TextQueryTestBackend
from sigma.pipelines.ocsf import ocsf_pipeline

def generate_elastic_queries():
    """Generate Elasticsearch queries from Linux Sigma rules via OCSF"""

    backend = TextQueryTestBackend(ocsf_pipeline())

    linux_security_rules = """
title: Linux System Compromise Indicators
logsource:
    product: linux
    category: process_creation
detection:
    sel1:
        Image|endswith:
            - '/nc'
            - '/wget'
            - '/curl'
    sel2:
        Image|endswith:
            - '/bash'
            - '/sh'
        CommandLine|contains:
            - '-i'
            - '/dev/tcp'
    condition: sel1 or sel2
"""

    rule = SigmaCollection.from_yaml(linux_security_rules)
    ocsf_queries = backend.convert(rule)

    # Convert OCSF to Elasticsearch format (basic example)
    elastic_queries = []
    for query in ocsf_queries:
        # Transform OCSF syntax to Elasticsearch
        elastic_query = query.replace('=', ':').replace(' and ', ' AND ')
        elastic_queries.append({
            "query": {
                "query_string": {
                    "query": elastic_query
                }
            }
        })

    return elastic_queries

# Generate for your ELK stack
if __name__ == "__main__":
    queries = generate_elastic_queries()
    for i, query in enumerate(queries):
        print(f"Linux Security Query {i+1}:")
        print(json.dumps(query, indent=2))
