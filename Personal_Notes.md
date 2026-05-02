---

# Operator Notes - Golden-Ticket-Ticket-Attack-Chain-IR Lab

### Phase 1: Elastic SIEM — Mimikatz & T1490 Ransomware Query

**Objective:** Query Elastic SIEM for indicators of credential dumping (Mimikatz) and ransomware inhibition of system recovery (MITRE T1490).

**Execution:**
- Opened Kibana → Discover tab, set index pattern to target log dataset.
- Queried for Mimikatz-related events using process name and command-line field filters.
- Queried for T1490 indicators (shadow copy deletion, bcdedit/wbadmin abuse) in event logs.
- Total documents scanned: **~40,000**.

**Observations:**
- Results returned process execution events and relevant Windows Security/Sysmon log entries matching the query criteria.
- No fabricated hits — findings were limited to what the dataset surfaced.

---

### Phase 2: SQLite Forensics — Microsoft Edge Browser History

**Objective:** Extract and examine browser history artifacts from Edge's SQLite `History` database.

**Target File:**
```
C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\Default\History
```

**Execution:**
- Copied `History` file to analysis directory to avoid locking the live database.
- Opened with SQLite browser / sqlite3 CLI.
- Queried `urls` and `visits` tables:

```sql
SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC;
```

**Observations:**
- Returned URL records with associated visit timestamps and visit counts.
- Timestamps stored in Chrome/Edge epoch format (microseconds since 1601-01-01); converted as needed.

---

### Phase 3: Volatility 3 — Memory Analysis (pslist)

**Objective:** Enumerate running processes from a raw memory image to identify suspicious or expected system processes.

**Command Executed:**
```bash
python3 vol.py -f /mnt/hgfs/ForensicShare/memdump.mem windows.pslist
```

**Observations:**
- `lsass.exe` — observed in process list; noted for credential material relevance in context of Mimikatz indicators from Phase 1.
- `svchost.exe` — multiple instances observed; consistent with normal Windows service host behavior.
- Output reviewed for anomalous parent-child relationships and unexpected process names; findings limited to what pslist surfaced.

---

### Phase 4: KRBTGT Double-Tap Remediation

**Objective:** Execute and verify KRBTGT account password reset procedure (double-reset) to invalidate forged Kerberos tickets (Golden Ticket remediation).

**Execution:**
- Performed KRBTGT password reset — **Reset 1**.
- Waited per environment replication requirements.
- Performed KRBTGT password reset — **Reset 2** (double-tap to ensure both current and previous password hashes are rotated).

**Tracking Event IDs:**
- **Event ID 4724** — An attempt was made to reset an account's password. Monitored to confirm both reset operations were logged against the KRBTGT account.
- **Event ID 4738** — A user account was changed. Monitored as secondary confirmation of account attribute modification following each reset.

**Observations:**
- Both Event IDs confirmed present in Security event log following each reset operation.
- Remediation logged and verified; no additional anomalies noted beyond expected reset activity.

---

