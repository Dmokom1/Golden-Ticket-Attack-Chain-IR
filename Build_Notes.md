# Build Notes: Golden-Ticket-Attack-Chain-IR

*This document provides detailed technical context for the lab build.*
*Generated: 2026-06-03*

---

# Build Notes
# Golden Ticket Attack Chain: Incident Response and Forensic Evidence Lab

This file provides supporting build context for the main README. It is not meant to repeat the full project write-up. The goal is to document the lab sequence, important artifacts, validation points, and evidence interpretation notes.

---

## Purpose of This File

The README explains the full project story. These build notes provide extra context on how the lab was built and what each major artifact supports.

This file focuses on:

- Lab sequence
- Important paths and artifacts
- Key validation points
- Screenshot evidence
- Evidence interpretation
- Improvements for a future version

---

## Corrected Lab Sequence

The final workflow followed this order:

1. Captured memory with FTK Imager.
2. Disabled Defender real-time protection for controlled lab execution.
3. Extracted and launched Mimikatz.
4. Enabled debug privilege with `privilege::debug`.
5. Extracted the KRBTGT hash and domain SID.
6. Created a Golden Ticket and saved it as `golden.kirbi`.
7. Injected the ticket using pass-the-ticket behavior.
8. Validated the loaded Kerberos ticket with `klist`.
9. Verified session context and group membership.
10. Tested access to the Domain Controller administrative share.
11. Reviewed Mimikatz-related evidence in Elastic.
12. Reset the KRBTGT account password.
13. Reviewed Event ID 4724 and Event ID 4738 evidence.
14. Reviewed high-volume file activity telemetry in Elastic.
15. Reviewed Microsoft Edge browser history through the SQLite History database.
16. Used Volatility 3 `windows.pslist` for basic memory process review.

---

## Lab Environment Notes

| Component | Details |
|---|---|
| Domain Controller | Windows Server 2022 |
| Hostname | `WIN-HS48GJMN0GP` |
| Domain | `cs.local` |
| SIEM / Log Review | Elastic / Kibana and Windows Security logs |
| Memory Capture | FTK Imager |
| Memory Review | Volatility 3 |
| Browser Artifact Review | DB Browser for SQLite |
| Attack Simulation Tool | Mimikatz |

---

## Important Artifacts and Paths

| Artifact | Value / Path |
|---|---|
| Memory image | `/mnt/hgfs/ForensicShare/memdump.mem` |
| Edge History database | `C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\Default\History` |
| Golden Ticket file | `golden.kirbi` |
| Administrative share tested | `\\WIN-HS48GJMN0GP\C$` |
| KRBTGT NTLM hash used in lab | `4c89c456b825f173d94aefc94d8718bd` |
| Domain SID | `S-1-5-21-426635828-459186537-2548376310` |
| Volume serial number observed | `844D-396C` |
| Volatility plugin used | `windows.pslist` |

---

## Key Validation Points

### Memory Capture

FTK Imager was used to capture memory from the Windows Server system. The memory capture completed successfully and produced an output file for later review.

This supported the forensic portion of the lab, but the memory work should be described as basic memory triage, not full memory malware analysis.

---

### Mimikatz Execution

Mimikatz was extracted, launched from an elevated session, and debug privilege was enabled.

The `privilege::debug` result confirmed that Mimikatz had the required access level for the credential access portion of the lab.

From a defender perspective, this is where process execution, LSASS access, and endpoint telemetry become important.

---

### KRBTGT Hash Extraction

The KRBTGT hash and domain SID were captured for the Golden Ticket simulation.

The KRBTGT account is important because it signs Kerberos Ticket Granting Tickets. If its hash is compromised, forged Kerberos tickets can be created and may be trusted by the domain.

---

### Golden Ticket Creation and Injection

A forged Kerberos ticket was created and saved as `golden.kirbi`.

The ticket was then injected into the current session using pass-the-ticket behavior.

The important validation point was not only creating the ticket, but confirming that it was loaded and usable.

---

### Kerberos Ticket Validation

`klist` confirmed that the forged ticket was loaded in the current session.

The screenshot filename uses the older wording `God_Mode_Verification`, but the professional description is Kerberos ticket validation.

---

### Administrative Share Access

Access to `\\WIN-HS48GJMN0GP\C$` was tested after ticket injection.

The successful directory listing confirmed that the forged ticket was usable against a privileged domain resource in the lab.

---

### Elastic Review

Elastic was used to review Mimikatz-related evidence.

This should be described carefully. The screenshot supports investigation and search activity, but it should not be treated as proof of complete attack-chain detection coverage.

Useful investigation areas for this kind of activity include:

- Suspicious process execution
- LSASS access
- Mimikatz-related artifacts
- Directory service access
- Kerberos ticket behavior
- SMB administrative share access
- Privileged account activity
- KRBTGT reset and account modification events

---

### KRBTGT Remediation Review

The KRBTGT account password was reset in Active Directory.

Windows Security logs showed:

- **Event ID 4724:** An attempt was made to reset an account’s password.
- **Event ID 4738:** A user account was changed.

These events helped validate that remediation activity created Windows log evidence.

In a real environment, KRBTGT remediation should be handled carefully because Active Directory keeps current and previous KRBTGT password material for Kerberos validation.

---

### File Activity Telemetry

Elastic showed a high-volume file activity spike under a `RansomwareTest` path.

The screenshot showed 40,000 file activity events.

This should be described as ransomware-style file activity telemetry, not confirmed ransomware impact by itself. File volume alone does not prove ransomware without more context.

Useful follow-up context would include:

- Responsible process
- File paths affected
- File extensions
- Whether files were encrypted, deleted, renamed, or modified
- User account context
- Timeline correlation
- Backup or recovery impact

---

### Edge Browser History Review

The Microsoft Edge History database was reviewed as a supporting forensic artifact.

The History file is a SQLite database.

Query used:

```sql
SELECT url, title, visit_count, last_visit_time
FROM urls
ORDER BY last_visit_time DESC;
```

This artifact can support timeline reconstruction, but it was not the main proof of the Golden Ticket activity.

---

### Volatility 3 Memory Review

Volatility 3 was used to inspect a captured memory image.

The plugin used was:

`windows.pslist`

The visible output showed normal Windows processes such as:

- `System`
- `Registry`
- `smss.exe`
- `csrss.exe`
- `wininit.exe`
- `services.exe`
- `lsass.exe`
- `svchost.exe`
- `winlogon.exe`

This confirmed that Volatility successfully parsed the memory image and returned process-list output.

This phase should be described as basic memory triage, not full memory malware analysis.

---

## Evidence Interpretation Notes

These notes help keep the public explanation accurate:

- The Elastic screenshot supports Mimikatz-related investigation, not complete automatic detection of the entire attack chain.
- The file activity screenshot supports high-volume file telemetry, not confirmed ransomware by itself.
- The Volatility screenshot supports process-list review, not deep memory forensics.
- The Edge History artifact supports timeline reconstruction practice, not direct proof of the Golden Ticket activity.
- Event IDs 4724 and 4738 are supported by screenshots and can be safely discussed.
- The original screenshot filename `10_God_Mode_Verification.png` should remain unchanged for path compatibility, but the professional explanation should be Kerberos ticket validation.

---

## Key Lessons Learned

1. Golden Ticket attacks are serious because they abuse Kerberos trust through the KRBTGT account.
2. Creating a ticket is not enough. The ticket must be validated and tested against a resource.
3. Elastic evidence must be interpreted carefully and not overstated.
4. Remediation actions create logs that can support an investigation timeline.
5. High-volume file activity needs context before calling it ransomware.
6. Browser history can support timeline reconstruction, but it is supporting evidence.
7. Volatility `windows.pslist` is useful for basic triage, but deeper memory analysis requires more plugins and correlation.

---

## Improvements for a Future Version

If this project were expanded, useful improvements would include:

- Clear separate filenames for pre-attack and post-attack memory captures
- Sysmon logging for stronger process and command-line visibility
- More specific Elastic screenshots for each major event type
- A cleaner timeline mapping attack action to log evidence
- Kerberos-specific event review
- Better documentation of KRBTGT reset timing
- More Volatility plugins beyond `windows.pslist`
- Stronger separation between core Golden Ticket evidence and supporting forensic exercises

---

## Screenshot Map

| Screenshot | What It Supports |
|---|---|
| `screenshots/01_FTK_Baseline_Memory_Capture.png` | FTK memory capture setup |
| `screenshots/02_FTK_Memory_Capture_Success.png` | Memory capture completed successfully |
| `screenshots/03_Windows_Defender_Disabled.png` | Defender disabled for controlled lab execution |
| `screenshots/04_Mimikatz_Files_Extracted.png` | Mimikatz files extracted |
| `screenshots/05_Mimikatz_Initialization.png` | Mimikatz launched |
| `screenshots/06_Mimikatz_Debug_Privilege_Enabled.png` | Debug privilege enabled |
| `screenshots/07_KRBTGT_Hash_Dumped.png` | KRBTGT hash and domain SID evidence |
| `screenshots/08_Golden_Ticket_Forged.png` | Golden Ticket created and saved as `golden.kirbi` |
| `screenshots/09_Golden_Ticket_Injected.png` | Ticket injected with `kerberos::ptt` |
| `screenshots/10_God_Mode_Verification.png` | Kerberos ticket validation with `klist` |
| `screenshots/11_Golden_Ticket_Injection_Verification.png` | Session/group validation after ticket injection |
| `screenshots/12_Post_Exploitation_Access_Validation.png` | Administrative share access validation |
| `screenshots/13_SIEM_Alert_Mimikatz_Detection.png` | Elastic review of Mimikatz-related evidence |
| `screenshots/14_KRBTGT_Password_Reset_Remediation.png` | KRBTGT password reset action |
| `screenshots/15_KRBTGT_Remediation_Log_Validation.png` | Event ID 4724 password reset evidence |
| `screenshots/16_KRBTGT_Account_Modified_Event_4738.png` | Event ID 4738 account modification evidence |
| `screenshots/17_Ransomware_Telemetry_Spike_T1490.png` | High-volume file activity telemetry |
| `screenshots/18_Edge_History_Database_Extraction.png` | Edge History database location |
| `screenshots/19_Edge_History_Artifact_Analysis.png` | Edge History reviewed in DB Browser for SQLite |
| `screenshots/20_Volatility_Process_List_Analysis.png` | Volatility `windows.pslist` output |