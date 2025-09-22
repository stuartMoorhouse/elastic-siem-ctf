#!/usr/bin/env python3
"""
Generate normal/benign Windows events for Elastic SIEM CTF.
Uses seed documents as templates to create realistic background noise.
"""

import json
import random
import argparse
import os
import glob
from datetime import datetime, timedelta
from typing import List, Dict, Any
import uuid
import hashlib

# Common Windows services and their event patterns
WINDOWS_SERVICES = [
    {"name": "Windows Update", "action": ["started", "stopped"], "param": "wuauserv"},
    {"name": "Windows Defender Antivirus Service", "action": ["started", "running"], "param": "WinDefend"},
    {"name": "Windows Firewall", "action": ["started", "running"], "param": "MpsSvc"},
    {"name": "DHCP Client", "action": ["started", "stopped"], "param": "Dhcp"},
    {"name": "DNS Client", "action": ["running"], "param": "Dnscache"},
    {"name": "Print Spooler", "action": ["started", "stopped"], "param": "Spooler"},
    {"name": "Task Scheduler", "action": ["running"], "param": "Schedule"},
    {"name": "Windows Event Log", "action": ["running"], "param": "EventLog"},
    {"name": "Remote Desktop Services", "action": ["stopped"], "param": "TermService"},
    {"name": "Windows Time", "action": ["started", "stopped"], "param": "W32Time"},
    {"name": "Security Center", "action": ["running"], "param": "wscsvc"},
    {"name": "Cryptographic Services", "action": ["started", "running"], "param": "CryptSvc"},
    {"name": "Background Intelligent Transfer Service", "action": ["started", "stopped"], "param": "BITS"},
    {"name": "Windows Search", "action": ["started", "running"], "param": "WSearch"},
    {"name": "Server", "action": ["running"], "param": "LanmanServer"},
    {"name": "Workstation", "action": ["running"], "param": "LanmanWorkstation"},
    {"name": "Remote Registry", "action": ["stopped"], "param": "RemoteRegistry"},
    {"name": "Windows Management Instrumentation", "action": ["running"], "param": "Winmgmt"},
    {"name": "COM+ Event System", "action": ["running"], "param": "EventSystem"},
    {"name": "Network Location Awareness", "action": ["running"], "param": "NlaSvc"}
]

# Common Windows event IDs for System log
SYSTEM_EVENT_IDS = {
    "7036": "Service state change",  # Most common, used in seed
    "7040": "Service startup type change",
    "7045": "Service installed",
    "1074": "System shutdown/restart",
    "6005": "Event log service started",
    "6006": "Event log service stopped",
    "6013": "System uptime",
    "10016": "DistributedCOM permission",
    "41": "Kernel-Power",
    "1014": "DNS name resolution timeout"
}

# Common Windows processes for Sysmon events
NORMAL_PROCESSES = [
    "svchost.exe", "csrss.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "explorer.exe", "taskhostw.exe", "searchindexer.exe", "dwm.exe",
    "mmc.exe", "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe",
    "msedge.exe", "chrome.exe", "firefox.exe", "teams.exe", "outlook.exe"
]

# Workstations in the environment
WORKSTATIONS = [
    {"hostname": "DESKTOP-SALES042", "ip": "172.16.1.42", "user": "jsmith", "dept": "SALES"},
    {"hostname": "DESKTOP-HR019", "ip": "172.16.1.19", "user": "kbrown", "dept": "SALES"},
    {"hostname": "DESKTOP-IT003", "ip": "172.16.1.3", "user": "admin", "dept": "IT"},
    {"hostname": "DESKTOP-ACCT015", "ip": "172.16.1.15", "user": "mjones", "dept": "ACCOUNTING"},
    {"hostname": "DESKTOP-MGMT008", "ip": "172.16.1.8", "user": "ceo", "dept": "EXECUTIVE"},
    {"hostname": "DESKTOP-DEV021", "ip": "172.16.1.21", "user": "dev1", "dept": "DEVELOPMENT"},
    {"hostname": "DESKTOP-SALES055", "ip": "172.16.1.55", "user": "btaylor", "dept": "SALES"},
    {"hostname": "DESKTOP-HR027", "ip": "172.16.1.27", "user": "hrmanager", "dept": "HR"},
]


class NormalEventGenerator:
    def __init__(self, seed_dir: str, start_time: datetime, end_time: datetime):
        self.seed_dir = seed_dir
        self.start_time = start_time
        self.end_time = end_time
        self.templates = self.load_seed_templates()

    def load_seed_templates(self) -> List[Dict[str, Any]]:
        """Load all seed JSON files from the seed directory."""
        templates = []
        seed_files = glob.glob(os.path.join(self.seed_dir, "*.json"))

        for seed_file in seed_files:
            with open(seed_file, 'r') as f:
                template = json.load(f)
                templates.append(template)

        if not templates:
            # If no seed files found, create a basic template based on known structure
            print(f"Warning: No seed files found in {self.seed_dir}, using default template")
            templates.append(self.get_default_template())

        return templates

    def get_default_template(self) -> Dict[str, Any]:
        """Return a default template based on the seed.json structure."""
        return {
            "_index": "logs-system.system",
            "_source": {
                "@timestamp": "",
                "event": {
                    "kind": "event",
                    "category": ["host"],  # ECS requires array
                    "type": ["info"],  # ECS requires array
                    "dataset": "system.system",
                    "code": "7036"
                },
                "host": {
                    "name": "",
                    "hostname": "",
                    "id": "",
                    "ip": [],
                    "os": {
                        "type": "windows",
                        "family": "windows",
                        "platform": "windows",
                        "name": "Windows 10 Pro",
                        "version": "10.0"
                    }
                },
                "winlog": {
                    "channel": "System",
                    "provider_name": "Service Control Manager",
                    "event_id": "7036",
                    "computer_name": "",
                    "event_data": {}
                },
                "message": "",
                "data_stream": {
                    "dataset": "system.system",
                    "namespace": "default",
                    "type": "logs"
                },
                "ecs": {
                    "version": "8.0.0"
                },
                "agent": {
                    "type": "filebeat",
                    "version": "8.15.0"
                }
            }
        }

    def generate_timestamp(self) -> str:
        """Generate a random timestamp between start_time and end_time."""
        time_diff = self.end_time - self.start_time
        random_seconds = random.randint(0, int(time_diff.total_seconds()))
        timestamp = self.start_time + timedelta(seconds=random_seconds)
        return timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def generate_system_event(self) -> Dict[str, Any]:
        """Generate a Windows System log event."""
        template = self.templates[0] if self.templates else self.get_default_template()
        event = json.loads(json.dumps(template))  # Deep copy

        # Select random workstation
        workstation = random.choice(WORKSTATIONS)

        # Select random service
        service = random.choice(WINDOWS_SERVICES)
        action = random.choice(service["action"])

        # Update event fields
        if "_source" in event:
            source = event["_source"]
        else:
            source = event

        source["@timestamp"] = self.generate_timestamp()

        # Update host information
        source["host"]["name"] = workstation["hostname"]
        source["host"]["hostname"] = workstation["hostname"]
        source["host"]["id"] = str(uuid.uuid4())
        source["host"]["ip"] = [f"fe80::{random.randint(1000, 9999)}:{random.randint(1000, 9999)}", workstation["ip"]]

        # Update winlog information
        if "winlog" in source:
            source["winlog"]["computer_name"] = workstation["hostname"]
            source["winlog"]["event_data"] = {
                "param1": service["name"],
                "param2": action
            }
            source["winlog"]["record_id"] = random.randint(10000, 99999)

        # Update message
        source["message"] = f"The {service['name']} service entered the {action} state."

        # Update event metadata
        source["event"]["created"] = source["@timestamp"]
        source["event"]["ingested"] = source["@timestamp"]

        # Set proper index
        event["_index"] = "logs-system.system-default"

        return event

    def generate_sysmon_process_event(self) -> Dict[str, Any]:
        """Generate a Windows Sysmon process creation event."""
        workstation = random.choice(WORKSTATIONS)
        process = random.choice(NORMAL_PROCESSES)

        event = {
            "_index": "logs-windows.sysmon_operational-default",
            "_source": {
                "@timestamp": self.generate_timestamp(),
                "event": {
                    "kind": "event",
                    "category": ["process"],  # ECS requires array for category
                    "type": ["start"],  # ECS requires array for type
                    "dataset": "windows.sysmon_operational",
                    "code": "1",
                    "action": "Process Create",
                    "ingested": self.generate_timestamp()
                },
                "host": {
                    "name": workstation["hostname"],
                    "hostname": workstation["hostname"],
                    "id": str(uuid.uuid4()),
                    "ip": [workstation["ip"]],
                    "os": {
                        "type": "windows",
                        "family": "windows",
                        "platform": "windows",
                        "name": "Windows 10 Pro",
                        "version": "10.0"
                    }
                },
                "process": {
                    "name": process,
                    "executable": f"C:\\Windows\\System32\\{process}",
                    "pid": random.randint(1000, 9999),
                    "parent": {
                        "name": random.choice(["services.exe", "svchost.exe", "explorer.exe"]),
                        "pid": random.randint(100, 999)
                    }
                },
                "user": {
                    "name": workstation["user"],
                    "domain": workstation["dept"]
                },
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": "1",
                    "provider_name": "Microsoft-Windows-Sysmon",
                    "computer_name": workstation["hostname"]
                },
                "data_stream": {
                    "dataset": "windows.sysmon_operational",
                    "namespace": "default",
                    "type": "logs"
                },
                "ecs": {
                    "version": "8.0.0"
                }
            }
        }

        return event

    def generate_security_logon_event(self) -> Dict[str, Any]:
        """Generate a Windows Security logon event (4624)."""
        workstation = random.choice(WORKSTATIONS)

        event = {
            "_index": "logs-system.security-default",
            "_source": {
                "@timestamp": self.generate_timestamp(),
                "event": {
                    "kind": "event",
                    "category": ["authentication"],  # ECS requires array
                    "type": ["start"],  # ECS requires array
                    "dataset": "system.security",
                    "code": "4624",
                    "action": "Logon",
                    "outcome": "success",
                    "ingested": self.generate_timestamp()
                },
                "host": {
                    "name": workstation["hostname"],
                    "hostname": workstation["hostname"],
                    "id": str(uuid.uuid4()),
                    "ip": [workstation["ip"]],
                    "os": {
                        "type": "windows",
                        "family": "windows",
                        "platform": "windows"
                    }
                },
                "user": {
                    "name": workstation["user"],
                    "domain": workstation["dept"],
                    "id": f"S-1-5-21-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(1000, 9999)}"
                },
                "winlog": {
                    "channel": "Security",
                    "event_id": "4624",
                    "provider_name": "Microsoft-Windows-Security-Auditing",
                    "computer_name": workstation["hostname"],
                    "logon": {
                        "type": random.choice(["2", "3", "10"])  # Interactive, Network, RemoteInteractive
                    }
                },
                "message": f"An account was successfully logged on by {workstation['user']}",
                "data_stream": {
                    "dataset": "system.security",
                    "namespace": "default",
                    "type": "logs"
                },
                "ecs": {
                    "version": "8.0.0"
                }
            }
        }

        return event

    def generate_powershell_event(self) -> Dict[str, Any]:
        """Generate a benign PowerShell script block event."""
        workstation = random.choice(WORKSTATIONS)

        benign_scripts = [
            "Get-Process | Where-Object {$_.WorkingSet -gt 100MB}",
            "Get-Service | Where-Object {$_.Status -eq 'Running'}",
            "Get-EventLog -LogName System -Newest 10",
            "Test-NetConnection -ComputerName localhost -Port 445",
            "Get-WmiObject Win32_LogicalDisk",
            "Get-ChildItem C:\\Windows\\Temp | Remove-Item -Force -ErrorAction SilentlyContinue",
            "Get-Date | Out-File C:\\temp\\timestamp.txt",
            "$PSVersionTable"
        ]

        event = {
            "_index": "logs-windows.powershell_operational-default",
            "_source": {
                "@timestamp": self.generate_timestamp(),
                "event": {
                    "kind": "event",
                    "category": ["process"],  # ECS requires array
                    "type": ["info"],  # ECS requires array
                    "dataset": "windows.powershell",
                    "code": "4104",
                    "action": "Script Block Logging",
                    "ingested": self.generate_timestamp()
                },
                "host": {
                    "name": workstation["hostname"],
                    "hostname": workstation["hostname"],
                    "id": str(uuid.uuid4()),
                    "os": {
                        "type": "windows",
                        "family": "windows",
                        "platform": "windows"
                    }
                },
                "powershell": {
                    "file": {
                        "script_block_text": random.choice(benign_scripts),
                        "script_block_id": str(uuid.uuid4())
                    }
                },
                "winlog": {
                    "channel": "Microsoft-Windows-PowerShell/Operational",
                    "event_id": "4104",
                    "provider_name": "Microsoft-Windows-PowerShell",
                    "computer_name": workstation["hostname"]
                },
                "user": {
                    "name": workstation["user"],
                    "domain": workstation["dept"]
                },
                "data_stream": {
                    "dataset": "windows.powershell",
                    "namespace": "default",
                    "type": "logs"
                },
                "ecs": {
                    "version": "8.0.0"
                }
            }
        }

        return event

    def generate_events(self, count: int) -> List[Dict[str, Any]]:
        """Generate a specified number of normal events."""
        events = []

        # Event type distribution
        event_types = [
            (self.generate_system_event, 0.4),        # 40% system events
            (self.generate_sysmon_process_event, 0.3), # 30% process events
            (self.generate_security_logon_event, 0.2), # 20% logon events
            (self.generate_powershell_event, 0.1)      # 10% PowerShell events
        ]

        for _ in range(count):
            # Select event type based on distribution
            rand = random.random()
            cumulative = 0
            for generator, probability in event_types:
                cumulative += probability
                if rand <= cumulative:
                    events.append(generator())
                    break

        # Sort events by timestamp
        events.sort(key=lambda x: x["_source"]["@timestamp"])

        return events


def main():
    parser = argparse.ArgumentParser(description='Generate normal Windows events for Elastic SIEM CTF')
    parser.add_argument('--seed-dir', default='normal-events', help='Directory containing seed JSON files')
    parser.add_argument('--output', default='normal-events/generated-events.json', help='Output file for generated events')
    parser.add_argument('--count', type=int, default=5000, help='Number of events to generate')
    parser.add_argument('--start-date', default='2025-09-22', help='Start date (YYYY-MM-DD)')
    parser.add_argument('--start-time', default='00:00:00', help='Start time (HH:MM:SS)')
    parser.add_argument('--end-date', default='2025-09-22', help='End date (YYYY-MM-DD)')
    parser.add_argument('--end-time', default='23:59:59', help='End time (HH:MM:SS)')
    parser.add_argument('--format', choices=['json', 'ndjson'], default='ndjson', help='Output format')

    args = parser.parse_args()

    # Parse datetime parameters
    start_datetime = datetime.strptime(f"{args.start_date} {args.start_time}", "%Y-%m-%d %H:%M:%S")
    end_datetime = datetime.strptime(f"{args.end_date} {args.end_time}", "%Y-%m-%d %H:%M:%S")

    print(f"Generating {args.count} normal events between {start_datetime} and {end_datetime}")

    # Generate events
    generator = NormalEventGenerator(args.seed_dir, start_datetime, end_datetime)
    events = generator.generate_events(args.count)

    # Write output
    with open(args.output, 'w') as f:
        if args.format == 'json':
            json.dump(events, f, indent=2)
        else:  # ndjson
            for event in events:
                f.write(json.dumps(event) + '\n')

    print(f"Generated {len(events)} events and saved to {args.output}")

    # Print statistics
    event_types = {}
    for event in events:
        dataset = event["_source"]["event"].get("dataset", "unknown")
        event_types[dataset] = event_types.get(dataset, 0) + 1

    print("\nEvent distribution:")
    for dataset, count in sorted(event_types.items()):
        print(f"  {dataset}: {count} events ({count/len(events)*100:.1f}%)")


if __name__ == "__main__":
    main()