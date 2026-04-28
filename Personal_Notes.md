---
# Operator Notes — Golden Ticket Lab: Troubleshooting Log

**Format:** Raw working notes, unedited — documented as encountered during the engagement.

---

## Issue 1 — Kerberos Encryption Downgrade Conflict

**Problem:** 
Initial ticket forgery attempts using `/aes256` failed with a `KRB_AP_ERR_MODIFIED` error when the forged ticket was presented to the SMB service. The ticket was being rejected at the AP_REQ stage despite a valid krbtgt hash.

**Root Cause:** 
The target server's Kerberos stack expected an AES256-encrypted session key within the PAC, but the forged ticket's session key was being generated using the RC4 key schedule when `/aes256` and `/rc4` flags were both omitted (Mimikatz defaults vary by build version). The mismatch between the PAC session key and the service's expected encryption type caused AP validation to fail silently.

**Resolution:** 
Explicitly specified `/rc4:[hash]` without mixing `/aes256` in the same command. RC4-HMAC (`0x17`) is sufficient for PAC trust validation against unpatched DCs and avoids the encryption negotiation mismatch. For AES256 forgery, the `krbtgt` AES256 key (not NTLM hash) must be extracted separately via `lsadump::dcsync /user:krbtgt /csv` and passed via `/aes256:[key]`.

**Lesson:** 
Always match the encryption type of the forged ticket to the DC's supported and expected types. Do not assume Mimikatz will select the correct algorithm automatically. When in doubt, check the Kerberos supported encryption types via: `klist tickets` and inspect the `EType` field.

---

## Issue 2 — Hostname Syntax Errors Breaking SMB Validation

**Problem:** 
After injecting the ticket with `/ptt`, `dir \\DC01\C$` returned `System error 5: Access is denied` consistently, despite `kerberos::list` confirming the forged TGT was present in the logon session cache.

**Root Cause:** 
The SMB access attempt was using the NetBIOS short name (`DC01`) rather than the fully qualified domain name (`DC01.lab.local`). Kerberos SPN resolution is DNS-FQDN-dependent — the service principal being requested was `cifs/DC01` instead of `cifs/DC01.lab.local`. Since the forged TGT is presented to the KDC to request a service ticket, the SPN must resolve correctly against the directory. Alternatively, if no KDC is contacted (ticket already present), NTLM fallback was being attempted, which failed because the forged identity doesn't exist.

**Resolution:** 
Switched to the FQDN: `dir \\DC01.lab.local\C$`. Immediate successful access. The Kerberos SPN lookup resolved correctly, and the cached service ticket for `cifs/DC01.lab.local` was issued and accepted.

**Lesson:** 
Always use FQDN syntax when validating Pass-the-Ticket scenarios. NetBIOS name resolution can trigger NTLM fallback, which will fail for non-existent forged identities. If NTLM fallback is disabled via GPO (`LAN Manager authentication level: Send NTLMv2 response only, refuse LM & NTLM`), the failure mode is even more obvious, but in default lab configs, the silent NTLM fallback masks the root cause.

---

## Issue 3 — SIEM Log Ingestion Delays Causing False Negatives in Alert Timing

**Problem:** 
After executing `privilege::debug` + `lsadump::lsa /patch`, the expected Sysmon Event ID 10 alert did not fire in Kibana within the expected 60-second window. Manually querying the index showed no documents from the DC for a ~7-minute period.

**Root Cause:** 
Winlogbeat's `harvester_limit` and `close_inactive` settings were set to their defaults, and a prior high-volume log burst (generated during Zerologon simulation) had saturated the Elasticsearch bulk ingest queue. Winlogbeat was buffering events locally and the ingest pipeline backpressure caused a queue hold without dropping events.

**Resolution:** 
Increased Elasticsearch ingest node heap allocation from 1GB to 4GB and tuned Winlogbeat's `bulk_max_size` from 50 to 200, with `worker: 4`. Also explicitly set `index.refresh_interval: 5s` on the `winlogbeat-*` index template to force faster segment visibility. After these changes, alert latency dropped from ~7 minutes to ~4 seconds.

**Lesson:** 
Default Elastic Stack configurations are not production-ready for high-throughput adversary simulation. Always pre-tune ingest pipeline capacity before running detection validation. A log gap during active adversary simulation is indistinguishable from a real attacker clearing logs — the tooling must keep up.

---

## Issue 4 — Mimikatz Blocked by Windows Defender (Evasion Required)

**Problem:** 
Initial Mimikatz execution on the DC was terminated before `privilege::debug` could complete. Windows Defender flagged the binary based on static PE signature matching.

**Resolution:** 
Recompiled Mimikatz from source with modified PE headers (changed section names, stripped debug symbols, randomized export table ordering). Additionally, loaded the binary via a reflective DLL injection loader to avoid touching disk. In a production red team context, Cobalt Strike's `mimikatz` module or `execute-assembly` with an obfuscated assembly would be the operationally sound approach.

**Lesson:** 
Stock Mimikatz binaries are near-universally signature-detected. Any serious engagement requires either BYOL (Bring Your Own Loader), in-memory execution, or leveraging built-in Windows tooling (`comsvcs.dll MiniDump`, `Task Manager memory dump`) to achieve the same outcome without triggering AV.

---

## Issue 5 — KRBTGT Password Last Set Timestamp Invalidated Forged Ticket

**Problem:** 
In a second iteration test (after a deliberate KRBTGT rotation to simulate incident response), forged tickets from the previous hash were correctly rejected. However, the new ticket forged with the rotated hash was also being rejected with `KRB_AP_ERR_TKT_NYV` (Ticket not yet valid).

**Root Cause:** 
The DC's system clock and the attack workstation's clock had drifted by ~6 minutes, exceeding the default Kerberos clock skew tolerance of 5 minutes. Kerberos is extremely sensitive to time synchronization — a clock delta beyond the tolerance window causes all ticket validation to fail regardless of cryptographic correctness.

**Resolution:** 
Forced NTP sync on the attacker workstation: `w32tm /resync /force`. Clock delta dropped to <1 second. Subsequent ticket forgery and validation succeeded immediately.

**Lesson:** 
Always validate time synchronization before beginning Kerberos-based attack phases. In air-gapped or isolated lab environments, the hypervisor's time sync may drift from the DC's authoritative NTP source. A `w32tm /stripchart /computer:DC01.lab.local` will expose any meaningful skew before it becomes a troubleshooting rabbit hole.

