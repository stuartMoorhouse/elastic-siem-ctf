#!/usr/bin/env python3
"""
Test individual rule queries to understand why alerts aren't firing.
"""

import yaml
from elasticsearch import Elasticsearch

def load_credentials(credentials_file: str) -> dict:
    """Load credentials from YAML file."""
    with open(credentials_file, 'r') as f:
        return yaml.safe_load(f)

def main():
    # Load credentials
    creds = load_credentials('credentials.yml')
    client = Elasticsearch(
        cloud_id=creds['ELASTIC_CLOUD_ID'],
        api_key=creds['EC_API_KEY']
    )

    print("TESTING INDIVIDUAL RULES")
    print("=" * 60)

    # Test Rule 1: Office Child Process (WORKING - generates alerts)
    print("\n1. OFFICE CHILD PROCESS (System Security)")
    result = client.search(
        index="logs-system.security-default",
        size=3,
        query={
            "bool": {
                "must": [
                    {"match": {"host.os.type": "windows"}},
                    {"match": {"event.type": "start"}}
                ]
            }
        }
    )
    print(f"   Total events with event.type=start: {result['hits']['total']['value']}")

    # Check for parent process name
    result = client.search(
        index="logs-system.security-default",
        size=0,
        aggs={
            "parent_processes": {
                "terms": {"field": "process.parent.name", "size": 10, "missing": "NO_PARENT"}
            }
        }
    )
    print("   Parent processes found:")
    for bucket in result['aggregations']['parent_processes']['buckets']:
        print(f"     - {bucket['key']}: {bucket['doc_count']}")

    # Test Rule 4: Registry (WORKING - generates 6 alerts)
    print("\n4. REGISTRY RUN KEY (Registry Events)")
    result = client.search(
        index="logs-endpoint.events.registry-default",
        size=10,
        query={"match_all": {}}
    )
    print(f"   Total registry events: {result['hits']['total']['value']}")

    for hit in result['hits']['hits']:
        src = hit['_source']
        print(f"   Event: {src.get('event', {}).get('type', 'unknown')} | "
              f"Hive: {src.get('registry', {}).get('hive', 'unknown')} | "
              f"Path: {src.get('registry', {}).get('path', 'unknown')[:50]}")

    # Test Rule 8: Mimikatz (NOT WORKING)
    print("\n8. MIMIKATZ LOG (Sysmon)")
    result = client.search(
        index="logs-windows.sysmon_operational-default",
        size=10,
        query={
            "bool": {
                "filter": [
                    {"exists": {"field": "file.name"}}
                ]
            }
        }
    )
    print(f"   Events with file.name: {result['hits']['total']['value']}")

    if result['hits']['total']['value'] > 0:
        for hit in result['hits']['hits']:
            src = hit['_source']
            print(f"     File: {src.get('file', {}).get('name', 'unknown')} | "
                  f"Process: {src.get('process', {}).get('name', 'unknown')}")

    # Test Rule 5: Startup Folder (NOT WORKING)
    print("\n5. STARTUP PERSISTENCE (Sysmon)")
    result = client.search(
        index="logs-windows.sysmon_operational-default",
        size=10,
        query={
            "bool": {
                "must": [
                    {"exists": {"field": "file.path"}}
                ]
            }
        }
    )
    print(f"   Events with file.path: {result['hits']['total']['value']}")

    if result['hits']['total']['value'] > 0:
        for hit in result['hits']['hits']:
            src = hit['_source']
            file_path = src.get('file', {}).get('path', 'unknown')
            if 'Startup' in file_path or 'startup' in file_path:
                print(f"     ✓ Startup folder: {file_path}")
            else:
                print(f"     File: {file_path[:80]}")

    # Test Rule 10: RunDLL32 Network (NOT WORKING)
    print("\n10. RUNDLL32 NETWORK (Sysmon)")

    # Check process events
    result = client.search(
        index="logs-windows.sysmon_operational-default",
        size=10,
        query={
            "bool": {
                "must": [
                    {"match": {"process.name": "rundll32.exe"}},
                    {"match": {"event.category": "process"}}
                ]
            }
        }
    )
    print(f"   RunDLL32 process events: {result['hits']['total']['value']}")

    # Check network events
    result = client.search(
        index="logs-windows.sysmon_operational-default",
        size=10,
        query={
            "bool": {
                "must": [
                    {"match": {"process.name": "rundll32.exe"}},
                    {"match": {"event.category": "network"}}
                ]
            }
        }
    )
    print(f"   RunDLL32 network events: {result['hits']['total']['value']}")

    # Check if entity_id exists for correlation
    result = client.search(
        index="logs-windows.sysmon_operational-default",
        size=10,
        query={
            "bool": {
                "must": [
                    {"exists": {"field": "process.entity_id"}}
                ]
            }
        }
    )
    print(f"   Events with process.entity_id: {result['hits']['total']['value']}")

    # Test Rule 11: CMD Network (NOT WORKING)
    print("\n11. CMD NETWORK (Sysmon)")

    # Check CMD process events
    result = client.search(
        index="logs-windows.sysmon_operational-default",
        size=10,
        query={
            "bool": {
                "must": [
                    {"match": {"process.name": "cmd.exe"}},
                    {"match": {"event.category": "process"}}
                ]
            }
        }
    )
    print(f"   CMD process events: {result['hits']['total']['value']}")

    # Check CMD network events
    result = client.search(
        index="logs-windows.sysmon_operational-default",
        size=10,
        query={
            "bool": {
                "must": [
                    {"match": {"process.name": "cmd.exe"}},
                    {"match": {"event.category": "network"}}
                ]
            }
        }
    )
    print(f"   CMD network events: {result['hits']['total']['value']}")

    # Test Rule 12: Unusual Process Location (NOT WORKING)
    print("\n12. UNUSUAL PROCESS LOCATION (Sysmon)")
    result = client.search(
        index="logs-windows.sysmon_operational-default",
        size=10,
        query={
            "wildcard": {
                "process.executable": "*:\\Users\\Public\\*.exe"
            }
        }
    )
    print(f"   Processes from Users\\Public: {result['hits']['total']['value']}")

    # Check what process.executable values we have
    result = client.search(
        index="logs-windows.sysmon_operational-default",
        size=0,
        aggs={
            "executables": {
                "terms": {"field": "process.executable", "size": 5}
            }
        }
    )
    print("   Sample process.executable paths:")
    for bucket in result['aggregations']['executables']['buckets']:
        print(f"     - {bucket['key']}")

    print("\n" + "=" * 60)
    print("KEY FINDINGS:")
    print("1. Office Child Process: Has events but parent.name field might be missing")
    print("2. Registry: WORKS - generating 6 alerts as expected")
    print("3. Mimikatz: Need file.name='mimilsa.log' with process.name='lsass.exe'")
    print("4. Startup: Need file events with specific Startup folder paths")
    print("5. Network Rules: Need both process AND network events with matching entity_id")
    print("6. Unusual Location: Need process.executable from specific directories")

if __name__ == "__main__":
    main()