# Product Requirements: Elasticsearch Security CTF

## Executive Summary
Create a Capture The Flag (CTF) environment using Elasticsearch Security that simulates a realistic enterprise attack scenario. The CTF should only use  Elastic prebuilt detection rules to detect attack behaviors. 

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


## 3. Prebuilt Detection Rules (Must Be Enabled)

### Initial Access Detection
1. **Suspicious MS Office Child Process**
Description: Identifies suspicious child processes of frequently targeted Microsoft Office applications (Word, PowerPoint, Excel). These child processes are often launched during exploitation of Office applications or from documents with malicious macros. 
MITRE ATT&CK:     
Initial Access (TA0001)
Phishing (T1566)
Spearphishing Attachment (T1566.001)
Execution (TA0002)
Command and Scripting Interpreter (T1059)
PowerShell (T1059.001)
Windows Command Shell (T1059.003)
Defense Evasion (TA0005)
System Binary Proxy Execution (T1218)

index pattern: logs-system.security* 
KQL query:   
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : (
      "eqnedt32.exe", "excel.exe", "fltldr.exe", "msaccess.exe",
      "mspub.exe", "powerpnt.exe", "winword.exe", "outlook.exe"
  ) and
  process.name : (
      "Microsoft.Workflow.Compiler.exe", "arp.exe", "atbroker.exe", "bginfo.exe", "bitsadmin.exe", "cdb.exe",
      "certutil.exe", "cmd.exe", "cmstp.exe", "control.exe", "cscript.exe", "csi.exe", "dnx.exe", "dsget.exe",
      "dsquery.exe", "forfiles.exe", "fsi.exe", "ftp.exe", "gpresult.exe", "hostname.exe", "ieexec.exe", "iexpress.exe",
      "installutil.exe", "ipconfig.exe", "mshta.exe", "msxsl.exe", "nbtstat.exe", "net.exe", "net1.exe", "netsh.exe",
      "netstat.exe", "nltest.exe", "odbcconf.exe", "ping.exe", "powershell.exe", "pwsh.exe", "qprocess.exe",
      "quser.exe", "qwinsta.exe", "rcsi.exe", "reg.exe", "regasm.exe", "regsvcs.exe", "regsvr32.exe", "sc.exe",
      "schtasks.exe", "systeminfo.exe", "tasklist.exe", "tracert.exe", "whoami.exe", "wmic.exe", "wscript.exe",
      "xwizard.exe", "explorer.exe", "rundll32.exe", "hh.exe", "msdt.exe"
  ) and
  not (
    process.parent.name : "outlook.exe" and
    process.name : "rundll32.exe" and
    process.args : "shell32.dll,Control_RunDLL" and
    process.args : "srchadmin.dll"
  )


2. **Execution of File Written or Modified by Microsoft Office**
Description: Identifies an executable created by a Microsoft Office application and subsequently executed. These processes are often launched via scripts inside documents or during exploitation of Microsoft Office applications.
MITRE ATT&CK: 
Execution (TA0002)
Initial Access (TA0001)
Phishing (T1566)
Spearphishing Attachment (T1566.001)
index pattern: logs-endpoint.events.file-* 
EQL query: 
sequence with maxspan=2h
  [file where host.os.type == "windows" and event.type != "deletion" and file.extension : "exe" and
     (process.name : "WINWORD.EXE" or
      process.name : "EXCEL.EXE" or
      process.name : "OUTLOOK.EXE" or
      process.name : "POWERPNT.EXE" or
      process.name : "eqnedt32.exe" or
      process.name : "fltldr.exe" or
      process.name : "MSPUB.EXE" or
      process.name : "MSACCESS.EXE")
  ] by host.id, file.path
  [process where host.os.type == "windows" and event.type == "start" and 
   not (process.name : "NewOutlookInstaller.exe" and process.code_signature.subject_name : "Microsoft Corporation" and process.code_signature.trusted == true) and 
   not (process.name : "ShareFileForOutlook-v*.exe" and process.code_signature.subject_name : "Citrix Systems, Inc." and process.code_signature.trusted == true)
  ] by host.id, process.executable



### Execution Detection
3. **PowerShell Suspicious Payload Encoded and Compressed**
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


### Persistence Detection
4. **Startup or Run Key Registry Modification**
Description: Identifies run key or startup key registry modifications. In order to survive reboots and other system interrupts, attackers will modify run keys within the registry or leverage startup folder items as a form of persistence.
MITRE ATT&CK: 
Persistence (TA0003)
Boot or Logon Autostart Execution (T1547)
Registry Run Keys / Startup Folder (T1547.0)

index patterns: logs-endpoint.events.registry-*
EQL query: registry where host.os.type == "windows" and event.type == "change" and 
 registry.data.strings != null and registry.hive : ("HKEY_USERS", "HKLM") and
 registry.path : (
     /* Machine Hive */
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
     "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*",
     /* Users Hive */
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*"
     ) and
  /* add common legitimate changes without being too restrictive as this is one of the most abused AESPs */
  not registry.data.strings : "ctfmon.exe /n" and
  not (registry.value : "Application Restart #*" and process.name : "csrss.exe") and
  not user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
  not registry.data.strings : ("?:\\Program Files\\*.exe", "?:\\Program Files (x86)\\*.exe") and
  not process.executable : ("?:\\Windows\\System32\\msiexec.exe", "?:\\Windows\\SysWOW64\\msiexec.exe") and
  not (
    /* Logitech G Hub */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name == "Logitech Inc" and
      (
        process.name : "lghub_agent.exe" and registry.data.strings : (
          "\"?:\\Program Files\\LGHUB\\lghub.exe\" --background",
          "\"?:\\Program Files\\LGHUB\\system_tray\\lghub_system_tray.exe\" --minimized"
        )
      ) or
      (
        process.name : "LogiBolt.exe" and registry.data.strings : (
          "?:\\Program Files\\Logi\\LogiBolt\\LogiBolt.exe --startup",
          "?:\\Users\\*\\AppData\\Local\\Logi\\LogiBolt\\LogiBolt.exe --startup"
        )
      )
    ) or

    /* Google Drive File Stream, Chrome, and Google Update */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name == "Google LLC" and
      (
        process.name : "GoogleDriveFS.exe" and registry.data.strings : (
        "\"?:\\Program Files\\Google\\Drive File Stream\\*\\GoogleDriveFS.exe\" --startup_mode"
        ) or

        process.name : "chrome.exe" and registry.data.strings : (
          "\"?:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --no-startup-window /prefetch:5",
          "\"?:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe\" --no-startup-window /prefetch:5"
        ) or

        process.name : ("GoogleUpdate.exe", "updater.exe") and registry.data.strings : (
          "\"?:\\Users\\*\\AppData\\Local\\Google\\Update\\*\\GoogleUpdateCore.exe\"",
          "\"?:\\Users\\*\\AppData\\Local\\Google\\GoogleUpdater\\*\\updater.exe\" --wake"
        )
      )
    ) or

    /* MS Programs */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name in ("Microsoft Windows", "Microsoft Corporation") and
      (
        process.name : "msedge.exe" and registry.data.strings : (
          "\"?:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window --win-session-start /prefetch:5",
          "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --win-session-start",
          "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window --win-session-start"
        ) or

        process.name : ("Update.exe", "Teams.exe", "ms-teamsupdate.exe") and registry.data.strings : (
          "?:\\Users\\*\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart \"Teams.exe\" --process-start-args \"--system-initiated\"",
          "?:\\ProgramData\\*\\Microsoft\\Teams\\Update.exe --processStart \"Teams.exe\" --process-start-args \"--system-initiated\"",
          "ms-teamsupdate.exe -UninstallT20"
        ) or

        process.name : ("OneDrive*.exe", "Microsoft.SharePoint.exe") and registry.data.strings : (
            "?:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background *",
            "?:\\Program Files (x86)\\Microsoft OneDrive\\OneDrive.exe /background*",
            "\"?:\\Program Files (x86)\\Microsoft OneDrive\\OneDrive.exe\" /background*",
            "\"?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background",
            "?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\??.???.????.????\\Microsoft.SharePoint.exe",
            "?:\\Windows\\system32\\cmd.exe /q /c * \"?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\*\""
        ) or

        process.name : "MicrosoftEdgeUpdate.exe" and registry.data.strings : (
          "\"?:\\Users\\*\\AppData\\Local\\Microsoft\\EdgeUpdate\\*\\MicrosoftEdgeUpdateCore.exe\""
        ) or
        
        process.executable : "?:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\*\\Installer\\setup.exe" and
        registry.data.strings : (
          "\"?:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\*\\Installer\\setup.exe\" --msedgewebview --delete-old-versions --system-level --verbose-logging --on-logon"
        ) or

        process.name : "BingWallpaper.exe" and registry.data.strings : (
          "C:\\Users\\*\\AppData\\Local\\Temp\\*\\UnInstDaemon.exe"
        ) or

        /* Discord Update.exe via reg.exe */
        process.name : "reg.exe" and registry.data.strings : (
          "\"C:\\Users\\*\\AppData\\Local\\Discord\\Update.exe\" --processStart Discord.exe"
        )
      )
    ) or

    /* Slack */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name in (
       "Slack Technologies, Inc.", "Slack Technologies, LLC"
      ) and process.name : "slack.exe" and registry.data.strings : (
        "\"?:\\Users\\*\\AppData\\Local\\slack\\slack.exe\" --process-start-args --startup",
        "\"?:\\ProgramData\\*\\slack\\slack.exe\" --process-start-args --startup",
        "\"?:\\Program Files\\Slack\\slack.exe\" --process-start-args --startup"
      )
    ) or

    /* Cisco */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name in ("Cisco WebEx LLC", "Cisco Systems, Inc.") and
      (
        process.name : "WebexHost.exe" and registry.data.strings : (
          "\"?:\\Users\\*\\AppData\\Local\\WebEx\\WebexHost.exe\" /daemon /runFrom=autorun"
        )
      ) or
      (
        process.name : "CiscoJabber.exe" and registry.data.strings : (
          "\"?:\\Program Files (x86)\\Cisco Systems\\Cisco Jabber\\CiscoJabber.exe\" /min"
        )
      )
    ) or

    /* Loom */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name == "Loom, Inc." and
      process.name : "Loom.exe" and registry.data.strings : (
        "?:\\Users\\*\\AppData\\Local\\Programs\\Loom\\Loom.exe --process-start-args \"--loomHidden\""
      )
    ) or

    /* Adobe */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name == "Adobe Inc." and
      process.name : ("Acrobat.exe", "FlashUtil32_*_Plugin.exe") and registry.data.strings : (
        "\"?:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\AdobeCollabSync.exe\"",
        "\"?:\\Program Files (x86)\\Adobe\\Acrobat DC\\Acrobat\\AdobeCollabSync.exe\"",
        "?:\\WINDOWS\\SysWOW64\\Macromed\\Flash\\FlashUtil32_*_Plugin.exe -update plugin"
      )
    ) or

    /* CCleaner */
    (
      process.code_signature.trusted == true and
      process.code_signature.subject_name in ("PIRIFORM SOFTWARE LIMITED", "Gen Digital Inc.") and
      process.name : ("CCleanerBrowser.exe", "CCleaner64.exe") and registry.data.strings : (
        "\"C:\\Program Files (x86)\\CCleaner Browser\\Application\\CCleanerBrowser.exe\" --check-run=src=logon --auto-launch-at-startup --profile-directory=\"Default\"",
        "\"C:\\Program Files\\CCleaner\\CCleaner64.exe\" /MONITOR"
      )
    ) or

    /* Opera */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name == "Opera Norway AS" and
      process.name : ("opera.exe", "assistant_installer.exe") and registry.data.strings : (
        "?:\\Users\\*\\AppData\\Local\\Programs\\Opera\\launcher.exe",
        "?:\\Users\\*\\AppData\\Local\\Programs\\Opera\\opera.exe",
        "?:\\Users\\*\\AppData\\Local\\Programs\\Opera GX\\launcher.exe",
        "?:\\Users\\*\\AppData\\Local\\Programs\\Opera GX\\opera.exe",
        "?:\\Users\\*\\AppData\\Local\\Programs\\Opera\\assistant\\browser_assistant.exe"
      )
    ) or

    /* Avast */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name == "Avast Software s.r.o." and
      process.name : "AvastBrowser.exe" and registry.data.strings : (
        "\"?:\\Users\\*\\AppData\\Local\\AVAST Software\\Browser\\Application\\AvastBrowser.exe\" --check-run=src=logon --auto-launch-at-startup*",
        "\"?:\\Program Files (x86)\\AVAST Software\\Browser\\Application\\AvastBrowser.exe\" --check-run=src=logon --auto-launch-at-startup*",
        ""
      )
    ) or

    /* Grammarly */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name == "Grammarly, Inc." and
      process.name : "GrammarlyInstaller.exe" and registry.data.strings : (
        "?:\\Users\\*\\AppData\\Local\\Grammarly\\DesktopIntegrations\\Grammarly.Desktop.exe",
        "\"?:\\Users\\*\\AppData\\Local\\Grammarly\\DesktopIntegrations\\Grammarly.Desktop.exe\""
      )
    ) or

    /* AVG */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name == "AVG Technologies USA, LLC" and
      process.name : "AVGBrowser.exe" and registry.data.strings : (
        "\"C:\\Program Files\\AVG\\Browser\\Application\\AVGBrowser.exe\"*",
        "\"C:\\Users\\*\\AppData\\Local\\AVG\\Browser\\Application\\AVGBrowser.exe\"*"
      )
    ) or

    /* HP */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name == "HP Inc." and
      process.name : "ScanToPCActivationApp.exe" and registry.data.strings : (
        "\"C:\\Program Files\\HP\\HP*"
      )
    ) or

    /* 1Password */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name == "Agilebits" and
      process.name : "1PasswordSetup*.exe" and registry.data.strings : (
        "\"C:\\Users\\*\\AppData\\Local\\1Password\\app\\?\\1Password.exe\" --silent"
      )
    ) or

    /* OpenVPN */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name == "OpenVPN Inc." and
      process.name : "OpenVPNConnect.exe" and registry.data.strings : (
        "C:\\Program Files\\OpenVPN Connect\\OpenVPNConnect.exe --opened-at-login --minimize"
      )
    ) or

    /* Docker */
    (
      process.code_signature.trusted == true and process.code_signature.subject_name == "Docker Inc" and
      process.name: "com.docker.backend.exe" and registry.data.strings : (
        "C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe -Autostart"
      )
    )
  )




5. **Startup Persistence by a Suspicious Process**
Description: Identifies files written to or modified in the startup folder by commonly abused processes. Adversaries may use this technique to maintain persistence.
MITRE ATT&CK: 
Persistence (TA0003)
Boot or Logon Autostart Execution (T1547)
Registry Run Keys / Startup Folder (T1547.001)

Index pattern: logs-windows.sysmon_operational-* 
KQL query: 
file where host.os.type == "windows" and event.type != "deletion" and
  user.domain != "NT AUTHORITY" and
  file.path : ("C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
               "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*") and
  process.name : ("cmd.exe",
                  "powershell.exe",
                  "wmic.exe",
                  "mshta.exe",
                  "pwsh.exe",
                  "cscript.exe",
                  "wscript.exe",
                  "regsvr32.exe",
                  "RegAsm.exe",
                  "rundll32.exe",
                  "EQNEDT32.EXE",
                  "WINWORD.EXE",
                  "EXCEL.EXE",
                  "POWERPNT.EXE",
                  "MSPUB.EXE",
                  "MSACCESS.EXE",
                  "iexplore.exe",
                  "InstallUtil.exe")


### Defense Evasion Detection
6. **Windows Event Logs Cleared**
Description:Identifies attempts to clear Windows event log stores. This is often done by attackers in an attempt to evade detection or destroy forensic evidence on a system.
MITRE ATT&CK:    
Defense Evasion (TA0005)
Indicator Removal (T1070)
Clear Windows Event Logs (T1070.001) 

Index pattern: logs-system.system*
KQL Query: 
    host.os.type:windows and event.action:("audit-log-cleared" or "Log clear") and
      not winlog.provider_name:"AD FS Auditing"


7. **PowerShell Script with Log Clear Capabilities**
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
8. **Mimikatz Memssp Log File Detected**
Description: Identifies the password log file from the default Mimikatz memssp module.
MITRE ATT&CK: 
Credential Access (TA0006)
OS Credential Dumping (T1003)

Index pattern: logs-windows.sysmon_operational-*
Query:     file where host.os.type == "windows" and file.name : "mimilsa.log" and process.name : "lsass.exe"


9. **PowerShell MiniDump Script**
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


### Command and Control Detection
10. **Unusual Network Connection via RunDLL32**
Description: Identifies unusual instances of rundll32.exe making outbound network connections. This may indicate adversarial Command and Control activity.
MITRE ATT&CK: 
Defense Evasion (TA0005)
System Binary Proxy Execution (T1218)
Rundll32 (T1218.011)
Command and Control (TA0011)
Application Layer Protocol (T1071)
Web Protocols (T1071.001)

Index pattern: logs-windows.sysmon_operational-*
Query: 
sequence by host.id, process.entity_id with maxspan=1m
  [process where host.os.type == "windows" and event.type == "start" and process.name : "rundll32.exe" and
  (
    process.args_count == 1 and

    /* Excludes bug where a missing closing quote sets args_count to 1 despite extra args */
    not process.command_line regex~ """\".*\.exe[^\"].*"""
  )]
  [network where host.os.type == "windows" and process.name : "rundll32.exe" and
   not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
       "FE80::/10", "FF00::/8")]

11. **Command Prompt Network Connection**
Description: Identifies cmd.exe making a network connection. Adversaries could abuse cmd.exe to download or execute malware from a remote URL.
MITRE ATT&CK: 
Execution (TA0002)
Command and Scripting Interpreter (T1059)
Command and Control (TA0011)
Ingress Tool Transfer (T1105

Index pattern: logs-windows.sysmon_operational-* 
EQL Query: 
sequence by process.entity_id
  [process where host.os.type == "windows" and process.name : "cmd.exe" and event.type == "start"]
  [network where host.os.type == "windows" and process.name : "cmd.exe" and
     not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
                                  "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32",
                                  "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
                                  "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
                                  "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
                                  "FE80::/10", "FF00::/8") and
    not dns.question.name : (
          "wpad", "localhost", "ocsp.comodoca.com", "ocsp.digicert.com", "ocsp.sectigo.com", "crl.comodoca.com"
    )]




12. **Process Execution from an Unusual Directory**
Description: Identifies process execution from suspicious default Windows directories. This is sometimes done by adversaries to hide malware in trusted paths.
MITRE ATT&CK: 
Defense Evasion (TA0005)
Masquerading (T1036)
Match Legitimate Name or Location (T1036.005)

Index pattern: logs-windows.sysmon_operational-*
EQL Query: 
process where host.os.type == "windows" and event.type == "start" and
  /* add suspicious execution paths here */
  process.executable : (
    "?:\\PerfLogs\\*.exe", "?:\\Users\\Public\\*.exe", "?:\\Windows\\Tasks\\*.exe",
    "?:\\Intel\\*.exe", "?:\\AMD\\Temp\\*.exe", "?:\\Windows\\AppReadiness\\*.exe",
    "?:\\Windows\\ServiceState\\*.exe", "?:\\Windows\\security\\*.exe", "?:\\Windows\\IdentityCRL\\*.exe",
    "?:\\Windows\\Branding\\*.exe", "?:\\Windows\\csc\\*.exe", "?:\\Windows\\DigitalLocker\\*.exe",
    "?:\\Windows\\en-US\\*.exe", "?:\\Windows\\wlansvc\\*.exe", "?:\\Windows\\Prefetch\\*.exe",
    "?:\\Windows\\Fonts\\*.exe", "?:\\Windows\\diagnostics\\*.exe", "?:\\Windows\\TAPI\\*.exe",
    "?:\\Windows\\INF\\*.exe", "?:\\Windows\\System32\\Speech\\*.exe", "?:\\windows\\tracing\\*.exe",
    "?:\\windows\\IME\\*.exe", "?:\\Windows\\Performance\\*.exe", "?:\\windows\\intel\\*.exe",
    "?:\\windows\\ms\\*.exe", "?:\\Windows\\dot3svc\\*.exe", "?:\\Windows\\panther\\*.exe",
    "?:\\Windows\\RemotePackages\\*.exe", "?:\\Windows\\OCR\\*.exe", "?:\\Windows\\appcompat\\*.exe",
    "?:\\Windows\\apppatch\\*.exe", "?:\\Windows\\addins\\*.exe", "?:\\Windows\\Setup\\*.exe",
    "?:\\Windows\\Help\\*.exe", "?:\\Windows\\SKB\\*.exe", "?:\\Windows\\Vss\\*.exe",
    "?:\\Windows\\Web\\*.exe", "?:\\Windows\\servicing\\*.exe", "?:\\Windows\\CbsTemp\\*.exe",
    "?:\\Windows\\Logs\\*.exe", "?:\\Windows\\WaaS\\*.exe", "?:\\Windows\\ShellExperiences\\*.exe",
    "?:\\Windows\\ShellComponents\\*.exe", "?:\\Windows\\PLA\\*.exe", "?:\\Windows\\Migration\\*.exe",
    "?:\\Windows\\debug\\*.exe", "?:\\Windows\\Cursors\\*.exe", "?:\\Windows\\Containers\\*.exe",
    "?:\\Windows\\Boot\\*.exe", "?:\\Windows\\bcastdvr\\*.exe", "?:\\Windows\\assembly\\*.exe",
    "?:\\Windows\\TextInput\\*.exe", "?:\\Windows\\security\\*.exe", "?:\\Windows\\schemas\\*.exe",
    "?:\\Windows\\SchCache\\*.exe", "?:\\Windows\\Resources\\*.exe", "?:\\Windows\\rescache\\*.exe",
    "?:\\Windows\\Provisioning\\*.exe", "?:\\Windows\\PrintDialog\\*.exe", "?:\\Windows\\PolicyDefinitions\\*.exe",
    "?:\\Windows\\media\\*.exe", "?:\\Windows\\Globalization\\*.exe", "?:\\Windows\\L2Schemas\\*.exe",
    "?:\\Windows\\LiveKernelReports\\*.exe", "?:\\Windows\\ModemLogs\\*.exe",
    "?:\\Windows\\ImmersiveControlPanel\\*.exe"
  ) and
  
  not process.name : (
    "SpeechUXWiz.exe", "SystemSettings.exe", "TrustedInstaller.exe",
    "PrintDialog.exe", "MpSigStub.exe", "LMS.exe", "mpam-*.exe"
  ) and
  not process.executable :
            ("?:\\Intel\\Wireless\\WUSetupLauncher.exe",
             "?:\\Intel\\Wireless\\Setup.exe",
             "?:\\Intel\\Move Mouse.exe",
             "?:\\windows\\Panther\\DiagTrackRunner.exe",
             "?:\\Windows\\servicing\\GC64\\tzupd.exe",
             "?:\\Users\\Public\\res\\RemoteLite.exe",
             "?:\\Users\\Public\\IBM\\ClientSolutions\\*.exe",
             "?:\\Users\\Public\\Documents\\syspin.exe",
             "?:\\Users\\Public\\res\\FileWatcher.exe")


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
- Initial Access: 3-5 alerts
- Execution: 5-7 alerts
- Persistence: 2-3 alerts
- Defense Evasion: 3-5 alerts
- Credential Access: 2-3 alerts
- Command & Control: 20+ alerts

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

1. **Start with C2 Alerts**: Multiple rundll32.exe and cmd.exe network connection alerts point to suspicious external communication
2. **Trace Back to Origin**: PowerShell execution alerts reveal the initial compromise through Office application
3. **Identify Persistence**: Registry modification and startup folder alerts show how attacker maintained access
4. **Discover Credential Theft**: Mimikatz alerts (mimilsa.log file creation and PowerShell MiniDump) reveal credential harvesting
5. **Map Lateral Movement**: Timeline analysis shows progression from DESKTOP-SALES042 to DESKTOP-HR019
6. **Assess Impact**: Process execution from unusual directories and log clearing activities indicate scope of compromise


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
- [ ] Total alert count is appropriate (40-50)
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

