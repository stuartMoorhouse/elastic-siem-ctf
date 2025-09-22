#!/usr/bin/env python3
"""
Execute Elastic Security detection rules with custom lookback period.
This script can force all enabled rules to run immediately with a lookback
that covers the entire attack timeline.
"""

import json
import yaml
import argparse
import sys
import time
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any
import urllib3
import requests
from requests.auth import HTTPBasicAuth

# Disable SSL warnings if needed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RuleExecutor:
    """Execute Elastic Security detection rules with custom settings."""

    def __init__(self, credentials_file: str, verify_ssl: bool = True):
        """Initialize the rule executor with Kibana credentials."""
        self.credentials = self._load_credentials(credentials_file)
        self.verify_ssl = verify_ssl
        self.kibana_url = self._extract_kibana_url()
        self.headers = self._setup_headers()
        self.session = self._create_session()

    def _load_credentials(self, credentials_file: str) -> Dict[str, str]:
        """Load credentials from YAML file."""
        with open(credentials_file, 'r') as f:
            creds = yaml.safe_load(f)

        if not creds or 'EC_API_KEY' not in creds:
            raise ValueError("Credentials file must contain EC_API_KEY")

        return creds

    def _extract_kibana_url(self) -> str:
        """Extract Kibana URL from Elastic Cloud ID."""
        if 'ELASTIC_CLOUD_ID' in self.credentials:
            # Decode cloud ID to get the Kibana URL
            cloud_id = self.credentials['ELASTIC_CLOUD_ID']
            # Cloud ID format: deployment-name:base64(elasticsearch_host$kibana_host$apm_host)
            parts = cloud_id.split(':')
            if len(parts) == 2:
                deployment_name = parts[0]
                encoded_hosts = parts[1]

                try:
                    decoded = base64.b64decode(encoded_hosts).decode('utf-8')
                    hosts = decoded.split('$')
                    if len(hosts) >= 2:
                        # Kibana host is the second part
                        kibana_host = hosts[1] if hosts[1] else hosts[0]
                        return f"https://{kibana_host}"
                except:
                    pass

        # Fallback to localhost if not using cloud
        return "https://localhost:5601"

    def _setup_headers(self) -> Dict[str, str]:
        """Setup API headers with authentication."""
        headers = {
            'Content-Type': 'application/json',
            'kbn-xsrf': 'true'
        }

        # Add API key authentication
        if 'EC_API_KEY' in self.credentials:
            headers['Authorization'] = f"ApiKey {self.credentials['EC_API_KEY']}"

        return headers

    def _create_session(self) -> requests.Session:
        """Create a requests session with proper configuration."""
        session = requests.Session()
        session.headers.update(self.headers)
        session.verify = self.verify_ssl
        return session

    def get_all_rules(self, enabled_only: bool = True) -> List[Dict[str, Any]]:
        """
        Get all detection rules from Kibana.

        Args:
            enabled_only: Only return enabled rules

        Returns:
            List of rule objects
        """
        print(f"Fetching detection rules from {self.kibana_url}...")

        # Use find rules endpoint with pagination
        url = f"{self.kibana_url}/api/detection_engine/rules/_find"
        params = {
            'per_page': 500,
            'page': 1
        }

        all_rules = []

        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()

            rules = data.get('data', [])
            total = data.get('total', 0)

            if enabled_only:
                rules = [r for r in rules if r.get('enabled', False)]

            all_rules.extend(rules)

            print(f"Found {len(all_rules)} {'enabled' if enabled_only else ''} rules (total: {total})")

            # Handle pagination if needed
            while len(all_rules) < total and params['page'] * params['per_page'] < total:
                params['page'] += 1
                response = self.session.get(url, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    rules = data.get('data', [])
                    if enabled_only:
                        rules = [r for r in rules if r.get('enabled', False)]
                    all_rules.extend(rules)
                else:
                    break

            return all_rules

        except requests.exceptions.RequestException as e:
            print(f"Error fetching rules: {e}")
            return []

    def update_rule_schedule(self, rule_id: str, lookback_hours: int = 24*30) -> bool:
        """
        Update a rule's schedule to include a longer lookback period.

        Args:
            rule_id: Rule ID to update
            lookback_hours: Hours to look back (default 30 days)

        Returns:
            True if successful
        """
        url = f"{self.kibana_url}/api/detection_engine/rules"

        # Calculate lookback in format like "now-720h"
        from_time = f"now-{lookback_hours}h"

        # Update rule with new schedule
        payload = {
            "id": rule_id,
            "from": from_time,
            "interval": "5m",  # Keep standard interval
            "meta": {
                "from": "1h"  # Additional lookback
            }
        }

        try:
            response = self.session.patch(url, json=payload, timeout=30)
            if response.status_code in [200, 204]:
                return True
            else:
                print(f"  Failed to update rule {rule_id}: {response.status_code}")
                return False
        except Exception as e:
            print(f"  Error updating rule {rule_id}: {e}")
            return False

    def bulk_update_rules(self, rules: List[Dict[str, Any]],
                         lookback_hours: int = 24*30) -> int:
        """
        Bulk update multiple rules with custom lookback.

        Args:
            rules: List of rule objects
            lookback_hours: Hours to look back

        Returns:
            Number of successfully updated rules
        """
        print(f"\nUpdating {len(rules)} rules with {lookback_hours} hour lookback...")

        url = f"{self.kibana_url}/api/detection_engine/rules/_bulk_action"

        # Prepare bulk action to edit rules
        from_time = f"now-{lookback_hours}h"

        rule_ids = [r['id'] for r in rules]

        payload = {
            "action": "edit",
            "ids": rule_ids,
            "edit": [
                {
                    "type": "set_schedule",
                    "value": {
                        "interval": "5m",
                        "lookback": "5m",
                        "from": from_time
                    }
                }
            ]
        }

        try:
            response = self.session.post(url, json=payload, timeout=60)
            if response.status_code == 200:
                result = response.json()
                success = result.get('attributes', {}).get('summary', {}).get('succeeded', 0)
                failed = result.get('attributes', {}).get('summary', {}).get('failed', 0)
                print(f"  ✓ Updated {success} rules")
                if failed > 0:
                    print(f"  ⚠ Failed to update {failed} rules")
                return success
            else:
                print(f"  ❌ Bulk update failed: {response.status_code}")
                if response.text:
                    print(f"  Response: {response.text[:500]}")
                return 0
        except Exception as e:
            print(f"  ❌ Error during bulk update: {e}")
            return 0

    def execute_rule(self, rule_id: str, rule_name: str = None) -> bool:
        """
        Manually execute a single rule.

        Args:
            rule_id: Rule ID to execute
            rule_name: Optional rule name for display

        Returns:
            True if successful
        """
        # Note: Manual execution via API may require using the Kibana UI
        # or specific internal APIs not publicly documented

        # Alternative: Enable/disable the rule to trigger immediate execution
        url = f"{self.kibana_url}/api/detection_engine/rules/_bulk_action"

        # Disable then re-enable to force execution
        disable_payload = {
            "action": "disable",
            "ids": [rule_id]
        }

        enable_payload = {
            "action": "enable",
            "ids": [rule_id]
        }

        try:
            # Disable
            response = self.session.post(url, json=disable_payload, timeout=30)
            if response.status_code != 200:
                return False

            time.sleep(1)

            # Re-enable (triggers execution)
            response = self.session.post(url, json=enable_payload, timeout=30)
            if response.status_code == 200:
                if rule_name:
                    print(f"  ✓ Triggered: {rule_name}")
                return True
            return False

        except Exception as e:
            if rule_name:
                print(f"  ⚠ Error executing {rule_name}: {e}")
            return False

    def execute_all_rules(self, rules: List[Dict[str, Any]]) -> int:
        """
        Execute all provided rules.

        Args:
            rules: List of rule objects

        Returns:
            Number of successfully executed rules
        """
        print(f"\nTriggering execution of {len(rules)} rules...")

        success_count = 0

        # Batch disable/enable for better performance
        url = f"{self.kibana_url}/api/detection_engine/rules/_bulk_action"
        rule_ids = [r['id'] for r in rules]

        try:
            # Disable all rules
            print("  Disabling rules...")
            disable_payload = {
                "action": "disable",
                "ids": rule_ids
            }
            response = self.session.post(url, json=disable_payload, timeout=60)

            if response.status_code == 200:
                time.sleep(2)

                # Re-enable all rules (triggers execution)
                print("  Re-enabling rules to trigger execution...")
                enable_payload = {
                    "action": "enable",
                    "ids": rule_ids
                }
                response = self.session.post(url, json=enable_payload, timeout=60)

                if response.status_code == 200:
                    result = response.json()
                    success_count = result.get('attributes', {}).get('summary', {}).get('succeeded', 0)
                    print(f"  ✓ Triggered {success_count} rules")

        except Exception as e:
            print(f"  ❌ Error during bulk execution: {e}")

        return success_count

    def check_alerts(self, time_range_hours: int = 24) -> int:
        """
        Check for generated alerts in the specified time range.

        Args:
            time_range_hours: Hours to look back for alerts

        Returns:
            Number of alerts found
        """
        print(f"\nChecking for alerts in the last {time_range_hours} hours...")

        url = f"{self.kibana_url}/api/detection_engine/signals/_find"

        # Calculate time range
        now = datetime.utcnow()
        from_time = now - timedelta(hours=time_range_hours)

        params = {
            'from': from_time.isoformat() + 'Z',
            'to': now.isoformat() + 'Z',
            'per_page': 100
        }

        try:
            response = self.session.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                total = data.get('total', 0)
                print(f"  Found {total} alerts")
                return total
            else:
                print(f"  Could not retrieve alerts: {response.status_code}")
                return 0
        except Exception as e:
            print(f"  Error checking alerts: {e}")
            return 0


def main():
    parser = argparse.ArgumentParser(
        description='Execute Elastic Security detection rules with custom lookback'
    )
    parser.add_argument(
        '--credentials',
        default='credentials.yml',
        help='Path to credentials.yml file'
    )
    parser.add_argument(
        '--lookback-days',
        type=int,
        default=30,
        help='Number of days to look back (default: 30)'
    )
    parser.add_argument(
        '--rule-names',
        nargs='+',
        help='Specific rule names to execute (optional)'
    )
    parser.add_argument(
        '--update-schedule',
        action='store_true',
        help='Update rule schedules with longer lookback'
    )
    parser.add_argument(
        '--execute',
        action='store_true',
        help='Force immediate execution of rules'
    )
    parser.add_argument(
        '--check-alerts',
        action='store_true',
        help='Check for generated alerts after execution'
    )
    parser.add_argument(
        '--no-verify',
        action='store_true',
        help='Disable SSL certificate verification'
    )

    args = parser.parse_args()

    # Initialize executor
    try:
        executor = RuleExecutor(
            credentials_file=args.credentials,
            verify_ssl=not args.no_verify
        )
    except Exception as e:
        print(f"❌ Failed to initialize: {e}")
        sys.exit(1)

    # Get rules
    rules = executor.get_all_rules(enabled_only=True)

    if not rules:
        print("❌ No enabled rules found")
        sys.exit(1)

    # Filter specific rules if requested
    if args.rule_names:
        filtered = []
        for rule in rules:
            rule_name = rule.get('name', '')
            if any(name.lower() in rule_name.lower() for name in args.rule_names):
                filtered.append(rule)
        rules = filtered
        print(f"Filtered to {len(rules)} matching rules")

    # Update rule schedules if requested
    if args.update_schedule:
        lookback_hours = args.lookback_days * 24
        success = executor.bulk_update_rules(rules, lookback_hours)
        print(f"Successfully updated {success} rules with {args.lookback_days} day lookback")

    # Execute rules if requested
    if args.execute:
        success = executor.execute_all_rules(rules)
        print(f"Successfully triggered {success} rules")

        # Wait for rules to process
        if success > 0:
            print("\nWaiting 30 seconds for rules to process...")
            time.sleep(30)

    # Check for alerts
    if args.check_alerts:
        alert_count = executor.check_alerts(time_range_hours=args.lookback_days * 24)

        if alert_count > 0:
            print(f"\n✓ CTF is ready! Found {alert_count} alerts.")
        else:
            print("\n⚠ No alerts found. You may need to:")
            print("  1. Wait a few more minutes for rules to complete")
            print("  2. Check that events were ingested properly")
            print("  3. Verify rule configurations")


if __name__ == "__main__":
    main()