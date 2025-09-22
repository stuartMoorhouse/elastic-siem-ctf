#!/usr/bin/env python3
"""
Diagnostic script to test why detection rules aren't generating alerts.
Tests each rule's query directly against the data to identify missing fields or conditions.
"""

import yaml
import json
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta

def load_credentials(credentials_file: str) -> dict:
    """Load credentials from YAML file."""
    with open(credentials_file, 'r') as f:
        return yaml.safe_load(f)


def test_rule_query(client, rule_name, index_pattern, query, query_type="kql"):
    """Test a rule's query against the data."""
    print(f"\n{'='*60}")
    print(f"Testing: {rule_name}")
    print(f"Index: {index_pattern}")
    print(f"Query Type: {query_type}")

    # Convert KQL to Elasticsearch query
    if query_type == "kql":
        # For KQL, use query_string
        es_query = {
            "query_string": {
                "query": query,
                "analyze_wildcard": True,
                "default_field": "*"
            }
        }
    elif query_type == "eql":
        # For EQL, we need to use the EQL API
        print("  ⚠️  EQL queries need special handling")
        return test_eql_query(client, index_pattern, query)
    else:
        es_query = {"match_all": {}}

    try:
        # First, check if indices exist and have data
        for index in index_pattern.split(','):
            index = index.strip()
            try:
                count = client.count(index=index, ignore_unavailable=True)
                print(f"  Index {index}: {count.get('count', 0)} total events")
            except:
                print(f"  Index {index}: Not found or empty")

        # Now run the actual query
        result = client.search(
            index=index_pattern,
            body={
                "size": 5,
                "query": es_query,
                "_source": ["@timestamp", "host.name", "process.name", "event.action", "event.dataset"]
            },
            ignore_unavailable=True
        )

        hits = result['hits']['total']['value']
        print(f"\n  🎯 Query matches: {hits} events")

        if hits > 0:
            print("  ✅ Rule SHOULD generate alerts")
            print("  Sample matches:")
            for hit in result['hits']['hits'][:3]:
                src = hit['_source']
                timestamp = src.get('@timestamp', 'unknown')
                host = src.get('host', {}).get('name', 'unknown')
                process = src.get('process', {}).get('name', 'unknown')
                print(f"    - {timestamp}: {host} / {process}")
        else:
            print("  ❌ Rule query matches NO events - no alerts expected")

            # Try to diagnose why
            print("\n  Debugging - checking for partial matches:")

            # Extract key conditions from the query
            if "process.parent.name" in query:
                # Check for parent process
                parent_query = {
                    "exists": {"field": "process.parent.name"}
                }
                parent_result = client.search(
                    index=index_pattern,
                    body={"size": 0, "query": parent_query},
                    ignore_unavailable=True
                )
                parent_hits = parent_result['hits']['total']['value']
                print(f"    Events with process.parent.name: {parent_hits}")

            if "event.type" in query:
                # Check event types
                type_agg = client.search(
                    index=index_pattern,
                    body={
                        "size": 0,
                        "aggs": {
                            "types": {
                                "terms": {"field": "event.type", "size": 10}
                            }
                        }
                    },
                    ignore_unavailable=True
                )
                print("    Event types found:")
                for bucket in type_agg['aggregations']['types']['buckets']:
                    print(f"      - {bucket['key']}: {bucket['doc_count']}")

        return hits > 0

    except Exception as e:
        print(f"  ❌ Error testing query: {str(e)[:200]}")
        return False


def test_eql_query(client, index_pattern, query):
    """Test an EQL query."""
    try:
        # EQL queries need special API
        # For now, we'll just check if the indices have the required fields
        print("  EQL query detected - checking field availability")

        # Extract field names from the query
        import re
        fields = re.findall(r'(\w+\.\w+(?:\.\w+)*)', query)
        unique_fields = set(fields)

        print(f"  Required fields: {', '.join(unique_fields)}")

        # Check if fields exist in mapping
        for index in index_pattern.split(','):
            index = index.strip()
            try:
                mapping = client.indices.get_mapping(index=index)
                # This is simplified - would need proper field path checking
                print(f"    {index}: Mapping exists")
            except:
                print(f"    {index}: No mapping found")

        return False

    except Exception as e:
        print(f"  Error with EQL: {e}")
        return False


def main():
    print("DETECTION RULE DIAGNOSTIC TOOL")
    print("="*60)

    # Load credentials
    creds = load_credentials('credentials.yml')
    client = Elasticsearch(
        cloud_id=creds['ELASTIC_CLOUD_ID'],
        api_key=creds['EC_API_KEY']
    )

    print("Connected to Elasticsearch")

    # Define rules to test based on product requirements
    rules_to_test = [
        {
            "name": "Rule 1: Suspicious MS Office Child Process",
            "index": "logs-system.security*",
            "query": """host.os.type:"windows" and event.type:"start" and
                process.parent.name:(eqnedt32.exe or excel.exe or fltldr.exe or msaccess.exe or
                mspub.exe or powerpnt.exe or winword.exe or outlook.exe) and
                process.name:(cmd.exe or powershell.exe or wscript.exe or cscript.exe or
                rundll32.exe or regsvr32.exe or mshta.exe)""",
            "type": "kql"
        },
        {
            "name": "Rule 2: Execution of File Written by Office",
            "index": "logs-endpoint.events.file-*,logs-endpoint.events.process-*",
            "query": "sequence with maxspan=2h [file where host.os.type == \"windows\"] [process where host.os.type == \"windows\"]",
            "type": "eql"
        },
        {
            "name": "Rule 3: PowerShell Suspicious Payload",
            "index": "winlogbeat-*",
            "query": """event.category:process and host.os.type:windows and
                powershell.file.script_block_text:(System.IO.Compression.DeflateStream or
                System.IO.Compression.GzipStream) and
                powershell.file.script_block_text:FromBase64String""",
            "type": "kql"
        },
        {
            "name": "Rule 4: Registry Run Key Modification",
            "index": "logs-endpoint.events.registry-*",
            "query": """registry where host.os.type == "windows" and event.type == "change" and
                registry.hive:(HKEY_USERS or HKLM) and
                registry.path:(*\\CurrentVersion\\Run\\* or *\\CurrentVersion\\RunOnce\\*)""",
            "type": "eql"
        },
        {
            "name": "Rule 5: Startup Persistence",
            "index": "logs-windows.sysmon_operational-*",
            "query": """file where host.os.type == "windows" and event.type != "deletion" and
                file.path:("C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*")
                and process.name:(cmd.exe or powershell.exe or rundll32.exe)""",
            "type": "eql"
        },
        {
            "name": "Rule 6: Windows Event Logs Cleared",
            "index": "logs-system.system*",
            "query": """host.os.type:windows and event.action:("audit-log-cleared" or "Log clear")""",
            "type": "kql"
        },
        {
            "name": "Rule 7: PowerShell Log Clear Script",
            "index": "logs-windows.powershell*",
            "query": """event.category:process and host.os.type:windows and
                powershell.file.script_block_text:(Clear-EventLog or Remove-EventLog)""",
            "type": "kql"
        },
        {
            "name": "Rule 8: Mimikatz Log File",
            "index": "logs-windows.sysmon_operational-*",
            "query": 'file where host.os.type == "windows" and file.name:"mimilsa.log" and process.name:"lsass.exe"',
            "type": "eql"
        },
        {
            "name": "Rule 9: PowerShell MiniDump",
            "index": "winlogbeat-*",
            "query": """event.category:process and host.os.type:windows and
                powershell.file.script_block_text:(MiniDumpWriteDump or MiniDumpWithFullMemory)""",
            "type": "kql"
        },
        {
            "name": "Rule 10: RunDLL32 Network Connection",
            "index": "logs-windows.sysmon_operational-*",
            "query": "sequence by host.id [process where process.name:\"rundll32.exe\"] [network where process.name:\"rundll32.exe\"]",
            "type": "eql"
        },
        {
            "name": "Rule 11: CMD Network Connection",
            "index": "logs-windows.sysmon_operational-*",
            "query": "sequence by process.entity_id [process where process.name:\"cmd.exe\"] [network where process.name:\"cmd.exe\"]",
            "type": "eql"
        },
        {
            "name": "Rule 12: Process from Unusual Directory",
            "index": "logs-windows.sysmon_operational-*",
            "query": """process where host.os.type == "windows" and event.type == "start" and
                process.executable:("?:\\PerfLogs\\*.exe" or "?:\\Users\\Public\\*.exe" or "?:\\Windows\\Tasks\\*.exe")""",
            "type": "eql"
        }
    ]

    print(f"\nTesting {len(rules_to_test)} detection rules...")

    working_rules = []
    failing_rules = []

    for rule in rules_to_test:
        result = test_rule_query(
            client,
            rule["name"],
            rule["index"],
            rule["query"],
            rule["type"]
        )

        if result:
            working_rules.append(rule["name"])
        else:
            failing_rules.append(rule["name"])

    # Summary
    print("\n" + "="*60)
    print("DIAGNOSTIC SUMMARY")
    print("="*60)

    print(f"\n✅ Rules with matching events ({len(working_rules)}):")
    for rule in working_rules:
        print(f"  - {rule}")

    print(f"\n❌ Rules with NO matching events ({len(failing_rules)}):")
    for rule in failing_rules:
        print(f"  - {rule}")

    print("\nRECOMMENDATIONS:")
    print("1. For rules with no matches, check:")
    print("   - Are the required fields present in events?")
    print("   - Do field values match the query conditions?")
    print("   - Are parent-child process relationships correct?")
    print("2. For EQL sequence rules, ensure:")
    print("   - Events have proper entity_id or host.id for correlation")
    print("   - Events occur within the specified time window")
    print("3. Consider updating attack events to include:")
    print("   - Proper process.parent.name fields")
    print("   - Correct event.type values")
    print("   - Required registry.hive values")


if __name__ == "__main__":
    main()