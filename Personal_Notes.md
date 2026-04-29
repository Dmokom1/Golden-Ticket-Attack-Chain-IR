---

# Operator Notes - Golden Ticket Lab: Troubleshooting Log

1. The 0x17 Encryption Downgrade Anomaly
During the threat hunting phase, I initially queried Elastic for Event ID 4769 looking for Ticket Encryption Type 0x17 (RC4-HMAC), which is a standard IOC for Golden Ticket forgery. However, the SIEM returned zero 0x17 events. Rather than burning time hunting for a missing cryptographic downgrade artifact, I recognized the lab environment wasn't generating the legacy encryption log and immediately pivoted to process-level memory access detection instead.

2. Alert Fatigue and the LSASS Pivot
My initial broad search for "mimikatz" across the SIEM generated 531 hits, creating severe alert fatigue. To isolate the actual credential dumping phase, I refined the KQL query to specifically track process interactions targeting lsass.exe. This cut through the noise and provided a definitive, high-fidelity alert for the memory extraction phase.

3. Execution Context Validation
Extracting the KRBTGT hash required absolute elevated context. Before interacting with LSASS, I had to explicitly assert privilege::debug in the terminal. Validating this token manipulation step is critical, as memory read operations against LSASS will fail even from a standard elevated shell without debug privileges asserted.
---

End of Personal_Notes.md
