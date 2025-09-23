# Product Requirements: Elasticsearch Security CTF

## Executive Summary
Create a Capture The Flag (CTF) environment using Elasticsearch Security that simulates a realistic enterprise attack scenario focused on PowerShell-based attacks. The CTF uses 4 key Elastic prebuilt detection rules to detect critical attack behaviors. 

## 1. CTF Attack Story

### Timeline: September 22, 2025
### Attack Narrative

**08:45 AM** - John Smith (jsmith) in Sales receives a phishing email disguised as an urgent invoice from a major client. The email contains a malicious Excel attachment named "Q3_Invoice_Review.xlsx" with embedded macros.

**08:52 AM** - John opens the attachment and enables macros after seeing a convincing message about "document protection." The macro executes PowerShell code that downloads and runs a payload from the attacker's C2 server (185.220.101.45).

**09:05 AM** - The PowerShell payload establishes persistence by creating a registry run key and dropping a malicious executable in the Windows Startup folder disguised as "WindowsUpdateHelper.exe"

**09:15 AM** - Attacker begins reconnaissance, running commands through cmd.exe to enumerate the network, user privileges, and installed software.

**09:30 AM** - Attacker clears Windows Security event logs to cover initial tracks.

**10:00 AM** - Attacker deploys Mimikatz to dump credentials from LSASS memory, successfully harvesting domain credentials including those of Karen Brown (kbrown) from HR who recently accessed a shared drive from John's machine.

**10:45 AM** - Using harvested credentials, attacker moves laterally to DESKTOP-HR019 (Karen's workstation) via RDP.

**11:00 AM** - On the HR machine, attacker establishes secondary persistence using similar registry modifications and searches for sensitive HR files containing employee data.

**11:15 AM** - Attacker initiates data exfiltration to C2 server, focusing on employee records, salary information, and confidential company documents.

**11:30 AM** - Continuous beaconing to C2 server via rundll32.exe and cmd.exe maintains command and control channel.

**12:00 PM** - Attack remains active with periodic check-ins to C2 infrastructure.

### 2. Compromised Assets
- **Primary Target**: DESKTOP-SALES042 (Sales department workstation, user: jsmith)
- **Secondary Target**: DESKTOP-HR019 (HR department workstation, user: kbrown)
- **C2 Server**: 185.220.101.45


## 3. Active Detection Rules (4 Rules Total)

### Execution Detection
1. **PowerShell Suspicious Payload Encoded and Compressed**
Description: Identifies the use of .NET functionality for decompression and base64 decoding combined in PowerShell scripts, which malware and security tools heavily use to deobfuscate payloads and load them directly in memory to bypass defenses.
MITRE ATT&CK: 
Defense Evasion (TA0005)
(external, opens in a new tab or window)
Obfuscated Files or Information (T1027)
Deobfuscate/Decode Files or Information (T1140)
Execution (TA0002)
(external, opens in a new tab or window)
Command and Scripting Interpreter (T1059)
PowerShell (T1059.001)

index pattern: winlogbeat-* 
filters:     NOT {"wildcard":{"file.path":{"case_insensitive":true,"value":"?:\\\\ProgramData\\\\Microsoft\\\\Windows Defender Advanced Threat Protection\\\\Downloads\\\\*"}}}
KQL query: event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    (
      "System.IO.Compression.DeflateStream" or
      "System.IO.Compression.GzipStream" or
      "IO.Compression.DeflateStream" or
      "IO.Compression.GzipStream"
    ) and
    FromBase64String
  ) and
  not user.id : "S-1-5-18"


### Defense Evasion Detection
2. **Windows Event Logs Cleared**
Description:Identifies attempts to clear Windows event log stores. This is often done by attackers in an attempt to evade detection or destroy forensic evidence on a system.
MITRE ATT&CK:    
Defense Evasion (TA0005)
Indicator Removal (T1070)
Clear Windows Event Logs (T1070.001) 

Index pattern: logs-system.system*
KQL Query: 
    host.os.type:windows and event.action:("audit-log-cleared" or "Log clear") and
      not winlog.provider_name:"AD FS Auditing"


3. **PowerShell Script with Log Clear Capabilities**
Description: Identifies the use of Cmdlets and methods related to Windows event log deletion activities. This is often done by attackers in an attempt to evade detection or destroy forensic evidence on a system.
MITRE ATT&CK: 
Defense Evasion (TA0005)
Indicator Removal (T1070)
Clear Windows Event Logs (T1070.001)

Index pattern: logs-windows.powershell* 
Filters:
NOT {"wildcard":{"file.path":{"case_insensitive":true,"value":"?:\\\\Windows\\\\system32\\\\WindowsPowerShell\\\\v1.0\\\\Modules\\\\Microsoft.PowerShell.Management\\\\*.psd1"}}}

NOT {"wildcard":{"file.path":{"case_insensitive":true,"value":"?:\\\\Program Files\\\\Microsoft Monitoring Agent\\\\Agent\\\\Health Service State\\\\Resources\\\\*\\\\M365Library.ps1"}}}
KQL Query: 
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "Clear-EventLog" or
    "Remove-EventLog" or
    ("Eventing.Reader.EventLogSession" and ".ClearLog") or
    ("Diagnostics.EventLog" and ".Clear")
  ) and
  not powershell.file.script_block_text : (
    "CmdletsToExport=@(\"Add-Content\""
  ) and
  not file.directory : "C:\Program Files\WindowsAdminCenter\PowerShellModules\Microsoft.WindowsAdminCenter.Configuration"


### Credential Access Detection

4. **PowerShell MiniDump Script**
Description: This rule detects PowerShell scripts capable of dumping process memory using WindowsErrorReporting or Dbghelp.dll MiniDumpWriteDump. Attackers can use this tooling to dump LSASS and get access to credentials.
MITRE ATT&CK: 
Credential Access (TA0006)
OS Credential Dumping (T1003)
LSASS Memory (T1003.001)
Execution (TA0002)
Command and Scripting Interpreter (T1059)
PowerShell (T1059.001)

Index pattern: logs-windows.powershell*
KQL Query:     
event.category:process and host.os.type:windows and powershell.file.script_block_text:(MiniDumpWriteDump or MiniDumpWithFullMemory or pmuDetirWpmuDiniM) and not user.id : "S-1-5-18"







## 5. Success Criteria

### Minimum Requirements
- [ ] Generate security alerts for each Rule 
- [ ] All MITRE ATT&CK phases detected
- [ ] Clear attack timeline visible in alerts
- [ ] Both compromised hosts identified

### Data Requirements
- [ ] 5,000+ background events (normal activity)
- [ ] 50+ attack events across all phases
- [ ] Events use proper ECS field structure
- [ ] All events have host.os.type: "windows"
- [ ] Events distributed across correct data streams

### Alert Distribution
- Execution: 3-5 alerts (PowerShell encoded payload)
- Defense Evasion: 4-6 alerts (Event log clearing)
- Credential Access: 2-3 alerts (PowerShell MiniDump)
- Total: ~10-15 alerts

## 6. Implementation Notes

### Data Generation Priority
1. Ensure all events include required ECS fields
2. Use exact field names that prebuilt rules expect
3. Generate realistic background noise to avoid false positives
4. Include proper process parent-child relationships
5. Maintain temporal consistency in attack timeline

### Common Pitfalls to Avoid
- Missing `host.os.type: "windows"` field
- Using wrong index patterns
- Creating events that don't match prebuilt rule queries
- Forgetting to enable prebuilt rules
- Using custom rules when prebuilt rules exist

### Testing Approach
1. Generate and upload background data first
2. Generate and upload attack data
3. Enable all relevant prebuilt rules
4. Trigger rule execution manually if needed
5. Verify alerts cover all attack phases

## 7. Participant Experience

### What Participants Should Discover

1. **Initial Compromise Vector**: Phishing email with malicious Excel attachment delivered to Sales department
2. **Patient Zero**: John Smith (jsmith) on DESKTOP-SALES042 opened malicious document at 08:52 AM
3. **Attack Progression**:
   - Macro execution triggered PowerShell download
   - Persistence established via registry and startup folder
   - Credentials harvested using Mimikatz
   - Lateral movement to HR workstation
   - Sensitive data exfiltration to external C2
4. **Attacker Infrastructure**: C2 server at 185.220.101.45 used for command and control
5. **Data at Risk**: Employee records, salary information, and confidential company documents from HR department

### Investigation Flow

1. **Start with PowerShell Alerts**: Encoded and compressed PowerShell payload alerts reveal initial compromise
2. **Trace Defense Evasion**: Event log clearing alerts show attacker covering tracks
3. **Discover Credential Theft**: PowerShell MiniDump alerts reveal credential harvesting attempts
4. **Map Timeline**: Correlate timestamps to understand attack progression from DESKTOP-SALES042 to DESKTOP-HR019


### Key Questions to Answer
- How did the attacker gain initial access?
- What persistence mechanisms were established?
- Which credentials were compromised?
- What data was potentially exposed?
- What is the C2 infrastructure?
- How far did the attacker spread?

## 8. Validation Checklist

Before declaring CTF ready:
- [ ] All prebuilt rules listed above are enabled
- [ ] Test data triggers expected alerts
- [ ] Alert timeline matches attack story
- [ ] Both compromised hosts show in alerts
- [ ] C2 communication is detected
- [ ] Mimikatz activity is detected
- [ ] No excessive false positives from background data
- [ ] Alert names are professional (no test/debug names)
- [ ] Total alert count is appropriate (10-15)
- [ ] Attack chain is fully traceable through alerts

## Development guide
Makes sure that the Rules match the CTF Attack Story. 

Create one Python script to generate Attack events. Base these on the Elasticsearch prebuilt Rules on GitHub: https://github.com/elastic/detection-rules/tree/main/rules
AND the seed.json was is an actual Elasticsearch ECS document. All synthetic data should match this model. 

Make sure that the Attack events are sent to standard Elasticsearch data streams. Make sure that the Attack events are valid Elastic Common Schema and contain all expected fields to trigger the rules. 

Also create a script background-events.py to create 5,000 background events "around" the attacks, that are from the same data source and written to the same index. They must be valid ECS and follow best-practice Elasticsearch Event format. Please use seed.json as a guide for what an Elasticsearch ECS Event should look like. 

Assume that the user has enabled the prebuilt Rules. Then: 

Create one Python script to add the custom rules, called add-custom-rules.py. 

Add the custom Rules using the API. 

Upload the data using today's date as the "end" of the event timeline. 
Check that the expected Alerts have been triggered, so the CTF story can be followed. 

Use the credentials in credentials.yml to connect to Elastic Cloud.

## Important Implementation Notes (Lessons Learned)

### 1. Elasticsearch Data Stream Naming Convention
**CRITICAL**: Elasticsearch data streams follow a specific naming pattern:
- Format: `{type}-{dataset}-{namespace}`
- Default namespace is "default"
- Example: `logs-system.security-default`, `logs-windows.sysmon_operational-default`
- Detection rules use wildcard patterns like `logs-system.security*` which will NOT match `logs-system.security` but WILL match `logs-system.security-default`

### 2. ECS Field Type Requirements
According to Elastic Common Schema (ECS), certain fields MUST be arrays, not strings:
- `event.category` - Must be an array (e.g., `["process"]` not `"process"`)
- `event.type` - Must be an array (e.g., `["start"]` not `"start"`)
- These fields use `keyword` mapping type, NOT `text`

### 3. Required Fields for Detection Rules
Many detection rules require specific fields to function:
- `event.ingested` - Timestamp field required by many rules for time-based queries
- `file.name` - Required for file-related detections (not just `file.path`)
- `process.name`, `process.executable` - Required for process detections
- All fields must match ECS field naming exactly

### 4. Index Creation and Mapping Conflicts
**CRITICAL**: Avoid creating indices without proper naming:
- NEVER create indices like `logs-system.security` (missing namespace)
- Always use the full pattern: `logs-system.security-default`
- Incorrect indices cause field mapping conflicts (e.g., `text` vs `keyword`)
- Delete any incorrectly named indices immediately to prevent rule failures

### 5. Data Ingestion Best Practices
When ingesting events:
- Always set `event.category` and `event.type` as arrays
- Always include `event.ingested` timestamp
- Use `data_stream` object to specify dataset, namespace, and type
- The ingestion script should automatically fix/add missing fields
- Use the `create` action for bulk API to ensure proper data stream handling

### 6. Detection Rule Execution
- Rules have default 5-minute intervals with 1-minute lookback
- For historical data (like September 2025 events), manually trigger rules with extended lookback
- Rules may fail with "verification_exception" if field mappings are incorrect
- Check rule errors in Kibana for specific field mapping issues

### 7. Common Pitfalls to Avoid
- Don't mix indices with and without `-default` suffix
- Don't use string values for `event.category` or `event.type`
- Don't forget `event.ingested` field
- Don't create indices manually - let data streams auto-create with correct mappings
- Always check for and delete problematic indices before re-ingestion

### 8. Script Requirements
All Python scripts should:
- Handle both single events and arrays of events
- Automatically fix ECS field types (convert strings to arrays where needed)
- Add missing required fields like `event.ingested`
- Ensure proper index naming with `-default` suffix
- Use `data_stream` object for proper routing

### 9. Alert Diagnostic Process

When alerts aren't firing as expected, use this diagnostic approach:

#### Step 1: Verify Rule Execution Status
```bash
python3 scripts/execute-rules.py --check-status
```
Check for:
- ✅ succeeded: Rule ran successfully
- ❌ failed: Field mapping conflicts or query errors
- ⚠️ partial failure: Some shards unavailable

#### Step 2: Test Rule Queries Directly
```bash
python3 scripts/diagnose-rules.py
```
This script:
- Tests each rule's query against the actual data
- Shows which events match and which don't
- Identifies missing fields or conditions

#### Step 3: Common Issues and Solutions

**Issue: Rules execute but don't generate alerts**
- Cause: Events don't match exact query conditions
- Solution: Check these specific requirements:

1. **Office Child Process Rule**: Requires `process.parent.name` field
   - Fix: Ensure events have parent process information

2. **File Execution Rule**: Requires EQL sequence correlation
   - Fix: Events need matching `host.id` and occur within time window

3. **Registry Rules**: Requires exact `registry.path` format
   - Fix: Path must include full registry key with backslashes

4. **Network Rules**: Requires process AND network events with same `entity_id`
   - Fix: Ensure both event types exist with matching correlation ID

5. **Mimikatz Rule**: Requires exact file and process names
   - Fix: `file.name: "mimilsa.log"` AND `process.name: "lsass.exe"`

6. **Startup Persistence**: Requires exact path matching
   - Fix: Path must match pattern exactly, including wildcards

**Issue: Field mapping conflicts**
- Cause: Same field has different types across indices
- Solution: Ensure all indices use consistent ECS mappings
- Common conflicts:
  - `event.category`: Must be `keyword` not `text`
  - `event.type`: Must be `keyword` not `text`
  - `process.args_count`: Must be `long` not `text`

#### Step 4: Why Alerts Don't Fire Despite Matching Data

Even when events exist that seem to match rule conditions, alerts may not fire because:

1. **Timing Issues**
   - Rules have already processed the time window
   - Solution: Disable and re-enable the rule to force re-processing

2. **EQL Sequence Requirements**
   - Sequence rules need events in exact order with correlation IDs
   - Events must occur within the specified `maxspan` time window
   - Solution: Verify `process.entity_id` or `host.id` matches between events

3. **Exact String Matching**
   - KQL uses exact matches for some fields
   - Example: `process.parent.name: "EXCEL.EXE"` won't match `"excel.exe"`
   - Solution: Check case sensitivity and exact values

4. **Array vs Single Value**
   - Some fields expect arrays: `event.type: ["start"]` not `"start"`
   - Solution: Ensure fields are properly formatted as arrays

5. **Missing Correlation Fields**
   - Network rules need `process.entity_id` for correlation
   - File rules need `host.id` for sequence matching
   - Solution: Add required correlation fields to events

#### Step 5: Debug Specific Rules
```python
# Test why a specific rule isn't matching
from elasticsearch import Elasticsearch

client = Elasticsearch(...)

# Example: Test Office Child Process rule
result = client.search(
    index="logs-system.security-default",
    query={
        "bool": {
            "must": [
                {"match": {"host.os.type": "windows"}},
                {"match": {"event.type": "start"}},
                {"exists": {"field": "process.parent.name"}}
            ]
        }
    }
)
print(f"Matching events: {result['hits']['total']['value']}")
```

### 10. Manual Rule Execution Process

Since Elastic detection rules run on a schedule (typically every 5 minutes with 1-minute lookback), historical events from September 2025 won't be detected automatically. You must manually trigger rule execution with extended lookback:

#### Option 1: Using Kibana UI (Recommended)
1. Navigate to Security → Rules in Kibana
2. Select all relevant rules (use filters to find CTF rules)
3. Click "Bulk Actions" → "Schedule backfill"
4. Set time range to cover September 22, 2025
5. Execute the backfill

#### Option 2: Using Detection Engine API
```bash
# Update rule schedules to look back further
curl -X POST "${KIBANA_URL}/api/detection_engine/rules/_bulk_action" \
  -H "kbn-xsrf: true" \
  -H "Authorization: ApiKey ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "edit",
    "ids": ["rule-id-1", "rule-id-2"],
    "edit": [{
      "type": "set_schedule",
      "value": {
        "interval": "5m",
        "lookback": "90d",
        "from": "now-90d"
      }
    }]
  }'

# Then disable and re-enable rules to trigger execution
curl -X POST "${KIBANA_URL}/api/detection_engine/rules/_bulk_action" \
  -H "kbn-xsrf: true" \
  -H "Authorization: ApiKey ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"action": "disable", "ids": ["rule-id-1", "rule-id-2"]}'

sleep 2

curl -X POST "${KIBANA_URL}/api/detection_engine/rules/_bulk_action" \
  -H "kbn-xsrf: true" \
  -H "Authorization: ApiKey ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"action": "enable", "ids": ["rule-id-1", "rule-id-2"]}'
```

#### Option 3: Using Python Script (execute-rules.py)
```bash
# Run the provided script with extended lookback
python3 scripts/execute-rules.py --update-schedule --execute --lookback-days 90
```

#### Important Notes:
- Rules need time to process after triggering (typically 1-5 minutes)
- Check alerts in Security → Alerts or using `.siem-signals-*` index
- If no alerts appear, verify:
  - Events are in correct indices with proper field mappings
  - Rules are enabled and have correct index patterns
  - Time range covers the event timestamps
  - No filters are blocking the detection

