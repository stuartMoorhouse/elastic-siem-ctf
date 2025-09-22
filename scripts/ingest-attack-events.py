#!/usr/bin/env python3
"""
Ingest attack events into Elasticsearch.
Handles both single event and array formats.
Fixes common field mapping issues to ensure rules trigger correctly.
"""

import json
import glob
import yaml
import os
from datetime import datetime
from elasticsearch import Elasticsearch, helpers


def load_credentials(credentials_file: str) -> dict:
    """Load credentials from YAML file."""
    with open(credentials_file, 'r') as f:
        creds = yaml.safe_load(f)

    if not creds or 'ELASTIC_CLOUD_ID' not in creds or 'EC_API_KEY' not in creds:
        raise ValueError("Invalid credentials file")

    return creds


def create_client(credentials: dict, verify_certs: bool = True) -> Elasticsearch:
    """Create Elasticsearch client."""
    try:
        client = Elasticsearch(
            cloud_id=credentials['ELASTIC_CLOUD_ID'],
            api_key=credentials['EC_API_KEY'],
            verify_certs=verify_certs,
            request_timeout=30
        )

        if not client.ping():
            raise ConnectionError("Failed to connect to Elasticsearch")

        info = client.info()
        print(f"Connected to: {info['cluster_name']} (v{info['version']['number']})")

        return client

    except Exception as e:
        raise ConnectionError(f"Failed to connect: {e}")


def process_event(event):
    """Process a single event for ingestion."""
    # Fix ECS field types - ensure category and type are arrays
    if 'event' in event:
        if 'category' in event['event'] and not isinstance(event['event']['category'], list):
            event['event']['category'] = [event['event']['category']]
        if 'type' in event['event'] and not isinstance(event['event']['type'], list):
            event['event']['type'] = [event['event']['type']]

        # Add event.ingested field if missing
        if 'ingested' not in event['event']:
            event['event']['ingested'] = event.get('@timestamp', '2025-09-22T12:00:00.000Z')

    # Fix registry.data.strings to be an array
    if 'registry' in event and 'data' in event['registry']:
        if 'strings' in event['registry']['data']:
            if not isinstance(event['registry']['data']['strings'], list):
                event['registry']['data']['strings'] = [event['registry']['data']['strings']]

    # Add missing file.name from file.path
    if 'file' in event and 'path' in event['file'] and 'name' not in event['file']:
        event['file']['name'] = os.path.basename(event['file']['path'])

    # Ensure user.id is present (some rules filter by it)
    if 'user' in event and 'id' not in event['user']:
        # Use a default non-system user ID if not specified
        event['user']['id'] = event['user'].get('id', 'S-1-5-21-123456789-1234567890-123456789-1001')

    # Map datasets to correct index patterns based on rules
    dataset_mapping = {
        # Rule 1: Suspicious MS Office Child Process expects logs-system.security*
        'system.security': 'logs-system.security-default',
        # Rule 2: Execution of File Written expects logs-endpoint.events.file-*
        'endpoint.events.file': 'logs-endpoint.events.file-default',
        'endpoint.events.process': 'logs-endpoint.events.process-default',
        # Rule 3: PowerShell Suspicious Payload expects winlogbeat-*
        'windows.powershell_operational': 'winlogbeat-default',
        # Rule 4: Registry Modification expects logs-endpoint.events.registry-*
        'endpoint.events.registry': 'logs-endpoint.events.registry-default',
        # Rule 5: Startup Persistence expects logs-windows.sysmon_operational-*
        'windows.sysmon_operational': 'logs-windows.sysmon_operational-default',
        # Rule 6: Windows Event Logs Cleared expects logs-system.system*
        'system.system': 'logs-system.system-default',
        # Rules 8-12: Various Sysmon events
        'sysmon.operational': 'logs-windows.sysmon_operational-default',
    }

    # Determine the index based on data_stream
    if 'data_stream' in event:
        dataset = event['data_stream']['dataset']

        # Special handling for PowerShell events based on content
        if dataset == 'windows.powershell':
            # Check script block text to determine correct index
            script_text = ''
            if 'powershell' in event and 'file' in event['powershell']:
                if 'script_block_text' in event['powershell']['file']:
                    script_text = event['powershell']['file']['script_block_text']

            # Rule 7: PowerShell Clear Logs needs logs-windows.powershell*
            if 'Clear-EventLog' in script_text or 'Remove-EventLog' in script_text:
                index = 'logs-windows.powershell-default'
            # Rule 3 & 9: PowerShell Encoded/MiniDump need winlogbeat-*
            elif any(x in script_text for x in ['DeflateStream', 'GzipStream', 'FromBase64String',
                                                  'MiniDumpWriteDump', 'MiniDumpWithFullMemory']):
                index = 'winlogbeat-default'
            else:
                # Default PowerShell events to winlogbeat
                index = 'winlogbeat-default'
        elif dataset in dataset_mapping:
            index = dataset_mapping[dataset]
        else:
            namespace = event['data_stream'].get('namespace', 'default')
            dtype = event['data_stream'].get('type', 'logs')
            index = f"{dtype}-{dataset}-{namespace}"
    else:
        # Fallback to generic if no data_stream
        index = "logs-generic-default"

    # Prepare document for bulk ingestion
    return {
        "_op_type": "create",
        "_index": index,
        "_source": event
    }


def main():
    # Load credentials
    creds = load_credentials('credentials.yml')
    client = create_client(creds)

    # Find all attack event files
    attack_files = glob.glob('attack-events/*.json')
    print(f"\nFound {len(attack_files)} attack event files")

    all_events = []
    index_distribution = {}

    for file_path in sorted(attack_files):
        print(f"  Processing: {file_path}")
        with open(file_path, 'r') as f:
            data = json.load(f)

            # Handle both single events and arrays
            if isinstance(data, list):
                events = data
            else:
                events = [data]

            for event in events:
                processed = process_event(event)
                all_events.append(processed)

                # Track index distribution
                idx = processed['_index']
                index_distribution[idx] = index_distribution.get(idx, 0) + 1

    print(f"\nTotal events to ingest: {len(all_events)}")
    print("\nIndex distribution:")
    for idx, count in sorted(index_distribution.items()):
        print(f"  {idx}: {count} events")

    # Bulk ingest
    if all_events:
        success, failed = helpers.bulk(
            client,
            all_events,
            stats_only=False,
            raise_on_error=False,
            raise_on_exception=False
        )

        print(f"\nIngestion complete:")
        print(f"  ✓ Success: {success}")
        print(f"  ✗ Failed: {len(failed) if isinstance(failed, list) else 0}")

        if failed and isinstance(failed, list):
            print("\nFailed events:")
            for item in failed[:5]:  # Show first 5 failures
                print(f"  {item}")

    # Refresh indices
    client.indices.refresh(index="logs-*")
    client.indices.refresh(index="winlogbeat-*")
    print("\nIndices refreshed")

    print("\n🔍 Rule-Index Mapping Summary:")
    print("Rule 1 (Office Child Process) → logs-system.security-default")
    print("Rule 2 (File Execution) → logs-endpoint.events.file-default")
    print("Rule 3 (PowerShell Encoded) → winlogbeat-default")
    print("Rule 4 (Registry Run Key) → logs-endpoint.events.registry-default")
    print("Rule 5 (Startup Folder) → logs-windows.sysmon_operational-default")
    print("Rule 6 (Clear Logs) → logs-system.system-default")
    print("Rule 7 (PowerShell Clear Logs) → logs-windows.powershell-default")
    print("Rule 8 (Mimikatz Log) → logs-windows.sysmon_operational-default")
    print("Rule 9 (PowerShell MiniDump) → winlogbeat-default")
    print("Rule 10 (RunDLL32 Network) → logs-windows.sysmon_operational-default")
    print("Rule 11 (CMD Network) → logs-windows.sysmon_operational-default")
    print("Rule 12 (Process from Unusual Dir) → logs-windows.sysmon_operational-default")


if __name__ == "__main__":
    main()