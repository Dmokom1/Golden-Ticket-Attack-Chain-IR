---

# Personal_Notes.md

## Troubleshooting Log — Real Issues Faced During This Lab

The following is a candid account of the actual problems encountered during the lab build and attack execution. These notes are kept for personal reference and to improve future lab iterations.

---

### Issue 1: RC4 vs AES256 Encryption Mismatch Causing Ticket Rejection

This was the first major blocker and cost several hours of debugging. The initial Golden Ticket was forged using the default RC4 encryption type (0x17), but the domain controller WIN-HS48GJMNOGP.cs.local had a Group Policy setting that enforced AES256 (0x12) for Kerberos ticket encryption on certain service accounts. When the RC4 forged ticket was presented to services that required AES256, the KDC rejected the ticket with a KRB_AP_ERR_MODIFIED error, which at first looked like the ticket itself was invalid or the hash was wrong.

Root cause: mixed encryption policy across the domain — some services accepted RC4, others did not.

Fix: Identified which services enforced AES256, then re-forged the ticket explicitly specifying /aes256 flag in Mimikatz after extracting the AES256 KRBTGT key separately via lsadump::dcsync. Confirmed that the /crypto:aes256 flag must be paired with the correct AES256 hash, not the NTLM hash.

Lesson: Always verify the Kerberos encryption type supported by target services before forging. If the environment enforces AES256 via GPO, RC4 tickets will silently fail on specific SPNs.

---

### Issue 2: Hostname FQDN Requirement for Kerberos SPN Resolution

SMB access to \\WIN-HS48GJMNOGP\C$ using only the NetBIOS hostname failed silently — the connection fell back to NTLM authentication instead of using the forged Kerberos ticket, which defeated the point of the exercise. No error was thrown; it simply authenticated via a different mechanism.

Root cause: Kerberos SPN resolution requires the fully qualified domain name (FQDN). When only the short hostname is used, Windows automatically downgrades to NTLM, bypassing the Kerberos cache entirely.

Fix: Changed all post-exploitation commands to use the full FQDN: \\WIN-HS48GJMNOGP.cs.local\C$ — this forced Kerberos ticket usage and the forged ticket was correctly consumed.

Lesson: Always use FQDN in post-exploitation access commands when operating in Kerberos-authenticated environments. NetBIOS name resolution silently triggers NTLM fallback, which will not use injected Kerberos tickets.

---

### Issue 3: SIEM Log Ingestion Delays

Elastic SIEM was not showing expected Event ID 4769 and 4624 alerts in real time. Events appeared in the raw index (winlogbeat-*) but were not surfacing in the SIEM detection rules dashboard for 3-8 minutes after the actual attack events occurred.

Root cause: Winlogbeat forwarding interval was set to 10 seconds, but the Elastic ingest pipeline had a backlog due to insufficient heap memory allocated to the Elasticsearch node (running on a 4GB RAM VM). The detection rule refresh interval was also set to 5 minutes instead of 1 minute.

Fix: Increased Elasticsearch JVM heap to 2GB (half of available RAM per Elastic guidance), reduced the detection rule polling interval in Kibana to 1 minute, and tuned the Winlogbeat bulk_max_size from 2048 to 512 to reduce ingest batch latency.

Lesson: In resource-constrained lab environments, SIEM detection latency is a real operational variable. Tuning ingest pipeline heap and rule polling intervals is essential for near-real-time detection validation.

---

### Issue 4: Mimikatz AV Evasion

Even with Windows Defender disabled at the policy level, Windows Smart App Control and some residual AMSI hooks in PowerShell were flagging Mimikatz execution when called from a PowerShell session. Running Mimikatz directly from cmd.exe as a standalone binary was more reliable than invoking it via PowerShell Invoke-Mimikatz scripts.

Root cause: AMSI (Antimalware Scan Interface) in PowerShell inspects script content and memory buffers regardless of Defender real-time protection state. Smart App Control added an additional layer of reputation-based blocking on unsigned binaries.

Fix: Executed Mimikatz directly as a compiled binary from an elevated cmd.exe session rather than through PowerShell. In future iterations, will test obfuscated or compiled variants (e.g., SafetyKatz, custom-compiled Mimikatz with modified PE headers) to simulate realistic adversary evasion.

Lesson: Disabling Windows Defender real-time protection does not disable AMSI. These are separate subsystems. For realistic lab simulations, both must be addressed independently.

---

### Issue 5: Time Sync Drift Causing Ticket Validation Failures

Intermittently, the forged Kerberos ticket was being rejected with a KRB_AP_ERR_SKEW error, which indicates a clock skew greater than 5 minutes between the client machine and the KDC (WIN-HS48GJMNOGP.cs.local).

Root cause: The Kali attacker VM and the Windows lab VMs were running on the same hypervisor but had diverged in system time by approximately 7 minutes due to the VMs being suspended and resumed at different intervals. Kerberos has a strict 5-minute clock skew tolerance by default (RFC 4120), and exceeding this threshold causes ticket validation to fail entirely.

Fix: Forced NTP synchronization on both VMs:
    On Windows: w32tm /resync /force
    On Kali: ntpdate -u pool.ntp.org (then timedatectl set-ntp true)

Confirmed time delta was within 60 seconds before re-injecting the ticket, which resolved the KRB_AP_ERR_SKEW errors immediately.

Lesson: Time synchronization is a prerequisite for any Kerberos-based attack or defense exercise. Always verify system clock alignment across all lab machines before beginning. In production environments, adversaries may also deliberately manipulate clock skew as an anti-forensics technique to invalidate Kerberos log timestamps.

---

End of Personal_Notes.md
