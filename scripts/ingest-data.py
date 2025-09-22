#!/usr/bin/env python3
"""
Ingest events into Elasticsearch data streams for Elastic SIEM CTF.
Follows Elasticsearch best practices for bulk ingestion into data streams.
"""

import json
import yaml
import argparse
import os
import sys
import time
from typing import Dict, List, Any, Generator, Tuple
from datetime import datetime
from pathlib import Path
from collections import defaultdict

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk, parallel_bulk, BulkIndexError
    from elasticsearch.exceptions import ConnectionError, NotFoundError
except ImportError:
    print("Error: elasticsearch module not installed. Please run: pip install elasticsearch")
    sys.exit(1)


class ElasticsearchIngestor:
    """Handle ingestion of events into Elasticsearch data streams."""

    def __init__(self, credentials_file: str, verify_certs: bool = True):
        """
        Initialize the Elasticsearch client with credentials.

        Args:
            credentials_file: Path to credentials.yml file
            verify_certs: Whether to verify SSL certificates
        """
        self.credentials = self._load_credentials(credentials_file)
        self.es_client = self._create_client(verify_certs)
        self.stats = defaultdict(int)

    def _load_credentials(self, credentials_file: str) -> Dict[str, str]:
        """Load credentials from YAML file."""
        if not os.path.exists(credentials_file):
            raise FileNotFoundError(f"Credentials file not found: {credentials_file}")

        with open(credentials_file, 'r') as f:
            creds = yaml.safe_load(f)

        if not creds or 'ELASTIC_CLOUD_ID' not in creds or 'EC_API_KEY' not in creds:
            raise ValueError("Invalid credentials file. Must contain ELASTIC_CLOUD_ID and EC_API_KEY")

        return creds

    def _create_client(self, verify_certs: bool) -> Elasticsearch:
        """Create Elasticsearch client with cloud credentials."""
        try:
            client = Elasticsearch(
                cloud_id=self.credentials['ELASTIC_CLOUD_ID'],
                api_key=self.credentials['EC_API_KEY'],
                verify_certs=verify_certs,
                request_timeout=30,
                max_retries=3,
                retry_on_timeout=True
            )

            # Test connection
            if not client.ping():
                raise ConnectionError("Failed to connect to Elasticsearch cluster")

            info = client.info()
            print(f"Connected to Elasticsearch cluster: {info['cluster_name']} (version {info['version']['number']})")

            return client

        except Exception as e:
            raise ConnectionError(f"Failed to create Elasticsearch client: {e}")

    def ensure_data_streams(self, data_streams: List[str]) -> None:
        """
        Ensure required data streams exist.

        For data streams, Elasticsearch automatically creates them when documents
        are indexed if the matching index template exists.
        """
        print("\nChecking data streams...")

        for stream in data_streams:
            try:
                # Check if data stream exists
                response = self.es_client.indices.get_data_stream(name=stream)
                if response.get('data_streams'):
                    print(f"  ✓ Data stream exists: {stream}")

            except NotFoundError:
                print(f"  ℹ Data stream will be auto-created: {stream}")
                # Data streams are auto-created on first document ingestion if template exists

            except Exception as e:
                print(f"  ⚠ Warning checking data stream {stream}: {e}")

    def _prepare_bulk_action(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare a document for bulk ingestion into a data stream.

        Data streams only support the 'create' action.
        """
        # Extract the index/data stream name
        index_name = doc.get('_index', 'logs-generic-default')

        # Get the source document
        source = doc.get('_source', doc)

        # Ensure @timestamp exists (required for data streams)
        if '@timestamp' not in source:
            source['@timestamp'] = datetime.utcnow().isoformat() + 'Z'

        # For data streams, use 'create' action
        action = {
            '_op_type': 'create',
            '_index': index_name,
            '_source': source
        }

        # Optionally add _id if present (but auto-generated is recommended for data streams)
        if '_id' in doc:
            action['_id'] = doc['_id']

        return action

    def _document_generator(self, documents: List[Dict[str, Any]],
                           chunk_size: int) -> Generator[Dict[str, Any], None, None]:
        """
        Generate documents for bulk ingestion.

        Args:
            documents: List of documents to ingest
            chunk_size: Number of documents per chunk

        Yields:
            Prepared bulk actions
        """
        for doc in documents:
            try:
                action = self._prepare_bulk_action(doc)
                self.stats['prepared'] += 1
                yield action

            except Exception as e:
                print(f"  ⚠ Error preparing document: {e}")
                self.stats['errors'] += 1

    def ingest_bulk(self, documents: List[Dict[str, Any]],
                   chunk_size: int = 500,
                   parallel: bool = False,
                   threads: int = 4) -> Tuple[int, int]:
        """
        Ingest documents using bulk API.

        Args:
            documents: List of documents to ingest
            chunk_size: Documents per bulk request
            parallel: Use parallel bulk for better performance
            threads: Number of threads for parallel bulk

        Returns:
            Tuple of (success_count, error_count)
        """
        print(f"\nIngesting {len(documents)} documents...")
        print(f"  Chunk size: {chunk_size}")
        print(f"  Parallel: {parallel} ({threads} threads)" if parallel else "  Parallel: No")

        success_count = 0
        error_count = 0

        try:
            if parallel:
                # Use parallel_bulk for better performance with large datasets
                for success, info in parallel_bulk(
                    self.es_client,
                    self._document_generator(documents, chunk_size),
                    chunk_size=chunk_size,
                    thread_count=threads,
                    raise_on_error=False,
                    raise_on_exception=False
                ):
                    if success:
                        success_count += 1
                        if success_count % 1000 == 0:
                            print(f"  Ingested {success_count} documents...")
                    else:
                        error_count += 1
                        print(f"  ⚠ Error ingesting document: {info}")

            else:
                # Use standard bulk for smaller datasets or debugging
                success, failed = bulk(
                    self.es_client,
                    self._document_generator(documents, chunk_size),
                    chunk_size=chunk_size,
                    raise_on_error=False,
                    raise_on_exception=False,
                    stats_only=False
                )

                success_count = success
                error_count = len(failed) if isinstance(failed, list) else 0

                if failed and isinstance(failed, list):
                    for item in failed[:5]:  # Show first 5 errors
                        print(f"  ⚠ Error: {item}")

        except BulkIndexError as e:
            print(f"  ⚠ Bulk indexing error: {e}")
            # Extract successful and failed counts from exception
            for error in e.errors[:5]:  # Show first 5 errors
                print(f"    - {error}")
            error_count += len(e.errors)

        except Exception as e:
            print(f"  ❌ Unexpected error during bulk ingestion: {e}")
            error_count += len(documents) - success_count

        return success_count, error_count

    def refresh_indices(self, indices: List[str] = None) -> None:
        """
        Refresh indices to make documents immediately searchable.

        Args:
            indices: List of index patterns to refresh, or None for all
        """
        try:
            if indices:
                for index in indices:
                    self.es_client.indices.refresh(index=index)
                    print(f"  ✓ Refreshed index: {index}")
            else:
                self.es_client.indices.refresh(index="logs-*")
                print("  ✓ Refreshed all logs-* indices")

        except Exception as e:
            print(f"  ⚠ Warning: Could not refresh indices: {e}")

    def get_cluster_health(self) -> Dict[str, Any]:
        """Get cluster health status."""
        try:
            health = self.es_client.cluster.health()
            return health
        except Exception as e:
            print(f"  ⚠ Could not get cluster health: {e}")
            return {}


def load_events_from_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Load events from a JSON or NDJSON file.

    Args:
        file_path: Path to the events file

    Returns:
        List of event dictionaries
    """
    events = []
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"Events file not found: {file_path}")

    with open(file_path, 'r') as f:
        content = f.read().strip()

        # Try to parse as JSON array first
        if content.startswith('['):
            events = json.loads(content)
        else:
            # Parse as NDJSON (one JSON object per line)
            for line in content.split('\n'):
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        print(f"  ⚠ Skipping invalid JSON line: {e}")

    return events


def extract_unique_indices(events: List[Dict[str, Any]]) -> List[str]:
    """Extract unique index/data stream names from events."""
    indices = set()

    for event in events:
        index = event.get('_index')
        if index:
            indices.add(index)

    return sorted(list(indices))


def main():
    parser = argparse.ArgumentParser(
        description='Ingest events into Elasticsearch data streams for CTF'
    )
    parser.add_argument(
        'files',
        nargs='+',
        help='Event files to ingest (JSON or NDJSON format)'
    )
    parser.add_argument(
        '--credentials',
        default='credentials.yml',
        help='Path to credentials.yml file (default: credentials.yml)'
    )
    parser.add_argument(
        '--chunk-size',
        type=int,
        default=500,
        help='Number of documents per bulk request (default: 500)'
    )
    parser.add_argument(
        '--parallel',
        action='store_true',
        help='Use parallel bulk ingestion for better performance'
    )
    parser.add_argument(
        '--threads',
        type=int,
        default=4,
        help='Number of threads for parallel bulk (default: 4)'
    )
    parser.add_argument(
        '--no-refresh',
        action='store_true',
        help='Do not refresh indices after ingestion'
    )
    parser.add_argument(
        '--no-verify',
        action='store_true',
        help='Do not verify SSL certificates'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Load and validate events without ingesting'
    )

    args = parser.parse_args()

    # Initialize the ingestor
    try:
        print("Initializing Elasticsearch connection...")
        ingestor = ElasticsearchIngestor(
            credentials_file=args.credentials,
            verify_certs=not args.no_verify
        )

        # Check cluster health
        health = ingestor.get_cluster_health()
        if health:
            print(f"Cluster status: {health.get('status', 'unknown')}")

    except Exception as e:
        print(f"❌ Failed to initialize Elasticsearch client: {e}")
        sys.exit(1)

    # Process each file
    total_success = 0
    total_errors = 0
    all_indices = set()

    for file_path in args.files:
        print(f"\nProcessing file: {file_path}")

        try:
            # Load events
            events = load_events_from_file(file_path)
            print(f"  Loaded {len(events)} events")

            if not events:
                print("  ⚠ No events found in file")
                continue

            # Extract unique indices
            indices = extract_unique_indices(events)
            all_indices.update(indices)
            print(f"  Target indices/data streams: {', '.join(indices)}")

            if args.dry_run:
                print("  ℹ Dry run - skipping ingestion")
                continue

            # Ensure data streams exist
            ingestor.ensure_data_streams(indices)

            # Ingest events
            success, errors = ingestor.ingest_bulk(
                events,
                chunk_size=args.chunk_size,
                parallel=args.parallel,
                threads=args.threads
            )

            total_success += success
            total_errors += errors

            print(f"  ✓ Successfully ingested: {success}")
            if errors > 0:
                print(f"  ⚠ Failed: {errors}")

        except Exception as e:
            print(f"  ❌ Error processing file: {e}")
            continue

    # Refresh indices to make documents searchable
    if not args.no_refresh and not args.dry_run and total_success > 0:
        print("\nRefreshing indices...")
        ingestor.refresh_indices(list(all_indices))

    # Print summary
    print("\n" + "="*50)
    print("INGESTION SUMMARY")
    print("="*50)
    print(f"Total documents processed: {total_success + total_errors}")
    print(f"  ✓ Successfully ingested: {total_success}")
    if total_errors > 0:
        print(f"  ⚠ Failed: {total_errors}")
    print(f"Target indices: {', '.join(sorted(all_indices))}")

    # Exit with appropriate code
    if total_errors > 0:
        sys.exit(1)
    elif total_success == 0:
        print("\n⚠ Warning: No documents were ingested")
        sys.exit(2)
    else:
        print("\n✓ Ingestion completed successfully!")
        sys.exit(0)


if __name__ == "__main__":
    main()