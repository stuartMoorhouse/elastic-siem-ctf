#!/usr/bin/env python3
"""
Delete data from Elasticsearch indices/data streams.
Used to clean up CTF data before re-ingestion.
"""

import json
import yaml
import argparse
import sys
from typing import List
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError


class DataDeleter:
    """Delete data from Elasticsearch indices and data streams."""

    def __init__(self, credentials_file: str, verify_certs: bool = True):
        """Initialize the Elasticsearch client."""
        self.credentials = self._load_credentials(credentials_file)
        self.es_client = self._create_client(verify_certs)

    def _load_credentials(self, credentials_file: str) -> dict:
        """Load credentials from YAML file."""
        with open(credentials_file, 'r') as f:
            creds = yaml.safe_load(f)

        if not creds or 'ELASTIC_CLOUD_ID' not in creds or 'EC_API_KEY' not in creds:
            raise ValueError("Invalid credentials file")

        return creds

    def _create_client(self, verify_certs: bool) -> Elasticsearch:
        """Create Elasticsearch client."""
        try:
            client = Elasticsearch(
                cloud_id=self.credentials['ELASTIC_CLOUD_ID'],
                api_key=self.credentials['EC_API_KEY'],
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

    def delete_by_date_range(self, index_pattern: str, start_date: str, end_date: str) -> int:
        """
        Delete documents within a date range from indices matching pattern.

        Args:
            index_pattern: Index pattern (e.g., "logs-*")
            start_date: Start date (e.g., "2025-09-22T00:00:00Z")
            end_date: End date (e.g., "2025-09-22T23:59:59Z")

        Returns:
            Number of documents deleted
        """
        query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": start_date,
                        "lte": end_date
                    }
                }
            }
        }

        try:
            # Delete by query
            response = self.es_client.delete_by_query(
                index=index_pattern,
                body=query,
                conflicts='proceed',
                wait_for_completion=True,
                refresh=True
            )

            deleted = response.get('deleted', 0)
            print(f"  Deleted {deleted} documents from {index_pattern}")
            return deleted

        except NotFoundError:
            print(f"  No indices found matching: {index_pattern}")
            return 0
        except Exception as e:
            print(f"  Error deleting from {index_pattern}: {e}")
            return 0

    def delete_all_from_indices(self, index_patterns: List[str]) -> int:
        """
        Delete all documents from indices matching patterns.

        Args:
            index_patterns: List of index patterns

        Returns:
            Total number of documents deleted
        """
        total_deleted = 0

        for pattern in index_patterns:
            query = {"query": {"match_all": {}}}

            try:
                response = self.es_client.delete_by_query(
                    index=pattern,
                    body=query,
                    conflicts='proceed',
                    wait_for_completion=True,
                    refresh=True
                )

                deleted = response.get('deleted', 0)
                if deleted > 0:
                    print(f"  Deleted {deleted} documents from {pattern}")
                total_deleted += deleted

            except NotFoundError:
                print(f"  No indices found matching: {pattern}")
            except Exception as e:
                print(f"  Error deleting from {pattern}: {e}")

        return total_deleted

    def delete_indices(self, index_patterns: List[str]) -> int:
        """
        Delete entire indices matching patterns.
        WARNING: This deletes the entire index, not just documents!

        Args:
            index_patterns: List of index patterns

        Returns:
            Number of indices deleted
        """
        deleted_count = 0

        for pattern in index_patterns:
            try:
                # Get matching indices
                indices = list(self.es_client.indices.get(index=pattern).keys())

                if indices:
                    # Delete the indices
                    self.es_client.indices.delete(index=pattern)
                    print(f"  Deleted indices: {', '.join(indices)}")
                    deleted_count += len(indices)
                else:
                    print(f"  No indices found matching: {pattern}")

            except NotFoundError:
                print(f"  No indices found matching: {pattern}")
            except Exception as e:
                print(f"  Error deleting indices {pattern}: {e}")

        return deleted_count

    def list_indices(self, pattern: str = "logs-*") -> None:
        """List indices matching pattern with document counts."""
        try:
            indices = self.es_client.cat.indices(index=pattern, format='json')

            if indices:
                print(f"\nIndices matching '{pattern}':")
                for idx in sorted(indices, key=lambda x: x['index']):
                    docs = idx.get('docs.count', '0')
                    size = idx.get('store.size', 'N/A')
                    print(f"  {idx['index']}: {docs} docs, {size}")
            else:
                print(f"No indices found matching: {pattern}")

        except Exception as e:
            print(f"Error listing indices: {e}")


def main():
    parser = argparse.ArgumentParser(description='Delete data from Elasticsearch')
    parser.add_argument(
        '--credentials',
        default='credentials.yml',
        help='Path to credentials file'
    )
    parser.add_argument(
        '--pattern',
        default='logs-*',
        help='Index pattern to delete from (default: logs-*)'
    )
    parser.add_argument(
        '--start-date',
        help='Start date for deletion (e.g., 2025-09-22T00:00:00Z)'
    )
    parser.add_argument(
        '--end-date',
        help='End date for deletion (e.g., 2025-09-22T23:59:59Z)'
    )
    parser.add_argument(
        '--delete-all',
        action='store_true',
        help='Delete all documents from matching indices'
    )
    parser.add_argument(
        '--delete-indices',
        action='store_true',
        help='Delete entire indices (WARNING: removes index structure)'
    )
    parser.add_argument(
        '--list-only',
        action='store_true',
        help='Only list indices, do not delete'
    )
    parser.add_argument(
        '--no-verify',
        action='store_true',
        help='Disable SSL certificate verification'
    )
    parser.add_argument(
        '--yes',
        action='store_true',
        help='Skip confirmation prompt'
    )

    args = parser.parse_args()

    # Initialize deleter
    try:
        deleter = DataDeleter(
            credentials_file=args.credentials,
            verify_certs=not args.no_verify
        )
    except Exception as e:
        print(f"❌ Failed to initialize: {e}")
        sys.exit(1)

    # Handle different patterns for CTF
    if args.pattern == 'ctf' or args.pattern == 'all':
        patterns = [
            'logs-system.security*',
            'logs-system.system*',
            'logs-endpoint.events.*',
            'logs-windows.sysmon_operational*',
            'logs-windows.powershell*',
            'winlogbeat-*'
        ]
    else:
        patterns = [args.pattern]

    # List indices if requested
    if args.list_only:
        for pattern in patterns:
            deleter.list_indices(pattern)
        sys.exit(0)

    # Confirm deletion
    if not args.yes:
        print("\n⚠️  WARNING: This will delete data from Elasticsearch!")
        print(f"Patterns: {', '.join(patterns)}")

        if args.delete_indices:
            print("Action: DELETE ENTIRE INDICES")
        elif args.delete_all:
            print("Action: Delete all documents")
        elif args.start_date and args.end_date:
            print(f"Action: Delete documents from {args.start_date} to {args.end_date}")
        else:
            print("Action: No deletion criteria specified")
            sys.exit(1)

        confirm = input("\nProceed? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Cancelled")
            sys.exit(0)

    # Perform deletion
    print("\nDeleting data...")

    if args.delete_indices:
        # Delete entire indices
        count = deleter.delete_indices(patterns)
        print(f"\n✓ Deleted {count} indices")

    elif args.delete_all:
        # Delete all documents from indices
        count = deleter.delete_all_from_indices(patterns)
        print(f"\n✓ Deleted {count} documents total")

    elif args.start_date and args.end_date:
        # Delete by date range
        total = 0
        for pattern in patterns:
            count = deleter.delete_by_date_range(
                pattern,
                args.start_date,
                args.end_date
            )
            total += count
        print(f"\n✓ Deleted {total} documents total")

    else:
        print("❌ No deletion criteria specified")
        print("Use --delete-all, --delete-indices, or specify date range")
        sys.exit(1)

    # Show remaining indices
    print("\nRemaining indices:")
    for pattern in patterns:
        deleter.list_indices(pattern)


if __name__ == "__main__":
    main()