# CTF Scripts

This directory contains scripts for generating and ingesting events for the Elastic SIEM CTF.

## Prerequisites

Install required Python dependencies:

```bash
pip install -r requirements.txt
```

## Scripts

### 1. generate-normal-events.py

Generates normal/benign Windows events as background noise for the CTF.

**Usage:**

```bash
python3 scripts/generate-normal-events.py \
  --count 5000 \
  --start-date 2025-09-22 \
  --start-time 00:00:00 \
  --end-date 2025-09-22 \
  --end-time 23:59:59 \
  --output normal-events/background.ndjson \
  --format ndjson
```

**Options:**
- `--count`: Number of events to generate (default: 5000)
- `--start-date`, `--end-date`: Date range (YYYY-MM-DD)
- `--start-time`, `--end-time`: Time range (HH:MM:SS)
- `--output`: Output file path
- `--format`: Output format (json or ndjson)
- `--seed-dir`: Directory with seed templates (default: normal-events)

### 2. ingest-data.py

Ingests events into Elasticsearch data streams following best practices.

**Usage:**

```bash
# Ingest attack events
python3 scripts/ingest-data.py attack-events/*.json \
  --credentials credentials.yml \
  --parallel

# Ingest normal events
python3 scripts/ingest-data.py normal-events/background.ndjson \
  --credentials credentials.yml \
  --chunk-size 1000 \
  --parallel \
  --threads 8
```

**Options:**
- `files`: One or more event files (JSON or NDJSON)
- `--credentials`: Path to credentials.yml file
- `--chunk-size`: Documents per bulk request (default: 500)
- `--parallel`: Use parallel bulk ingestion
- `--threads`: Number of threads for parallel bulk (default: 4)
- `--no-refresh`: Don't refresh indices after ingestion
- `--no-verify`: Don't verify SSL certificates
- `--dry-run`: Validate without ingesting

## Data Stream Requirements

The ingestion script automatically handles the following data streams:
- `logs-system.security` - Windows Security events
- `logs-system.system` - Windows System events
- `logs-windows.sysmon_operational` - Sysmon events
- `logs-windows.powershell` - PowerShell events
- `logs-endpoint.events.file` - File events
- `logs-endpoint.events.process` - Process events
- `logs-endpoint.events.registry` - Registry events
- `winlogbeat-*` - WinLogBeat events

## Best Practices

1. **Bulk Size**: Use 500-1000 documents per chunk for optimal performance
2. **Parallel Ingestion**: Enable for datasets > 10,000 documents
3. **Thread Count**: Use 4-8 threads based on cluster capacity
4. **Memory**: Monitor memory usage for large datasets
5. **Error Handling**: Script includes retry logic and error reporting

## Workflow Example

```bash
# 1. Generate normal background events
python3 scripts/generate-normal-events.py --count 5000

# 2. Ingest all events
python3 scripts/ingest-data.py \
  attack-events/*.json \
  normal-events/background.ndjson \
  --parallel

# 3. Verify ingestion
python3 scripts/ingest-data.py events.json --dry-run
```

## Troubleshooting

- **Connection errors**: Verify credentials.yml has valid ELASTIC_CLOUD_ID and EC_API_KEY
- **Timeout errors**: Reduce chunk-size or threads
- **Memory errors**: Use NDJSON format and reduce chunk-size
- **SSL errors**: Use --no-verify flag (not recommended for production)