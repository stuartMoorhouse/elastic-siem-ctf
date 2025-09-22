#!/usr/bin/env python3
"""
Validate that attack events contain required fields for detection rules.
"""

import json
import glob

def validate_event(event, file_path):
    """Validate a single event has required fields."""
    issues = []

    # Check ECS array fields
    if 'event' in event:
        if 'category' in event['event'] and not isinstance(event['event']['category'], list):
            issues.append(f"event.category should be array, not string")
        if 'type' in event['event'] and not isinstance(event['event']['type'], list):
            issues.append(f"event.type should be array, not string")
        if 'ingested' not in event['event']:
            issues.append(f"Missing event.ingested timestamp")

    # Check registry events
    if 'registry' in event:
        if 'data' in event['registry'] and 'strings' in event['registry']['data']:
            if not isinstance(event['registry']['data']['strings'], list):
                issues.append(f"registry.data.strings should be array")

    # Check file events
    if 'file' in event:
        if 'path' in event['file'] and 'name' not in event['file']:
            issues.append(f"Has file.path but missing file.name")

    # Check user.id for non-system users
    if 'user' in event and 'id' not in event['user']:
        issues.append(f"Missing user.id field")

    # Check host.os.type
    if 'host' not in event or 'os' not in event['host'] or 'type' not in event['host']['os']:
        issues.append(f"Missing host.os.type field")

    # Check data_stream
    if 'data_stream' not in event:
        issues.append(f"Missing data_stream object")
    else:
        dataset = event['data_stream'].get('dataset')
        if not dataset:
            issues.append(f"Missing data_stream.dataset")

    return issues

def check_rule_mappings():
    """Check if datasets map to correct indices for rules."""
    rule_mappings = {
        "01-initial-access-office-child-process.json": {
            "expected_dataset": "system.security",
            "rule": "Suspicious MS Office Child Process",
            "index_pattern": "logs-system.security*"
        },
        "02-initial-access-file-execution.json": {
            "expected_dataset": "endpoint.events.file",
            "rule": "Execution of File Written by Office",
            "index_pattern": "logs-endpoint.events.file-*"
        },
        "03-execution-powershell-encoded.json": {
            "expected_dataset": "windows.powershell_operational",
            "rule": "PowerShell Suspicious Payload",
            "index_pattern": "winlogbeat-*"
        },
        "04-persistence-registry-run-key.json": {
            "expected_dataset": "endpoint.events.registry",
            "rule": "Registry Run Key Modification",
            "index_pattern": "logs-endpoint.events.registry-*"
        },
        "05-persistence-startup-folder.json": {
            "expected_dataset": "windows.sysmon_operational",
            "rule": "Startup Persistence",
            "index_pattern": "logs-windows.sysmon_operational-*"
        },
        "06-defense-evasion-clear-logs.json": {
            "expected_dataset": "system.system",
            "rule": "Windows Event Logs Cleared",
            "index_pattern": "logs-system.system*"
        },
        "08-credential-access-mimikatz-log.json": {
            "expected_dataset": "windows.sysmon_operational",
            "rule": "Mimikatz Memssp Log",
            "index_pattern": "logs-windows.sysmon_operational-*"
        },
        "09-credential-access-minidump.json": {
            "expected_dataset": "windows.powershell_operational",
            "rule": "PowerShell MiniDump",
            "index_pattern": "winlogbeat-*"
        },
        "10-c2-rundll32-network.json": {
            "expected_dataset": "windows.sysmon_operational",
            "rule": "Unusual Network via RunDLL32",
            "index_pattern": "logs-windows.sysmon_operational-*"
        },
        "11-c2-cmd-network.json": {
            "expected_dataset": "windows.sysmon_operational",
            "rule": "Command Prompt Network Connection",
            "index_pattern": "logs-windows.sysmon_operational-*"
        },
        "07-defense-evasion-unusual-process-location.json": {
            "expected_dataset": "windows.sysmon_operational",
            "rule": "Process from Unusual Directory",
            "index_pattern": "logs-windows.sysmon_operational-*"
        }
    }

    return rule_mappings

def main():
    attack_files = glob.glob('attack-events/*.json')
    print(f"Validating {len(attack_files)} attack event files\n")

    rule_mappings = check_rule_mappings()

    total_issues = 0
    for file_path in sorted(attack_files):
        filename = file_path.split('/')[-1]
        with open(file_path, 'r') as f:
            data = json.load(f)

            # Handle both single events and arrays
            if isinstance(data, list):
                events = data
            else:
                events = [data]

            file_issues = []
            for i, event in enumerate(events):
                issues = validate_event(event, file_path)
                if issues:
                    file_issues.extend([(i, issue) for issue in issues])

                # Check dataset mapping
                if filename in rule_mappings:
                    mapping = rule_mappings[filename]
                    if 'data_stream' in event:
                        dataset = event['data_stream'].get('dataset', '')
                        if dataset != mapping['expected_dataset']:
                            file_issues.append((i, f"Dataset '{dataset}' doesn't match expected '{mapping['expected_dataset']}' for rule '{mapping['rule']}'"))

            if file_issues:
                print(f"❌ {filename}")
                for event_idx, issue in file_issues:
                    print(f"   Event {event_idx}: {issue}")
                total_issues += len(file_issues)
            else:
                print(f"✅ {filename}")

    print(f"\nTotal issues found: {total_issues}")

    if total_issues == 0:
        print("✅ All events are valid!")
    else:
        print("❌ Please fix the issues above")

if __name__ == "__main__":
    main()