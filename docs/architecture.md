# Golden Ticket Attack Lab Architecture

```mermaid
graph TB
    subgraph "Attack Simulation"
        A1[Windows Server 2022 DC]
        A2[Active Directory Domain]
        A3[KRBTGT Account]
        A4[LSASS Process]
    end
    
    subgraph "Tools & Techniques"
        B1[FTK Imager<br/>Memory Capture]
        B2[Mimikatz<br/>Credential Dumping]
        B3[Kerberos Ticket Forging]
        B4[Golden Ticket Injection]
    end
    
    subgraph "Detection & Investigation"
        C1[Windows Event Logs]
        C2[Elastic SIEM]
        C3[Volatility 3]
        C4[Browser Artifacts]
    end
    
    subgraph "Remediation"
        D1[KRBTGT Password Reset]
        D2[Event ID 4724/4738]
        D3[Authentication Monitoring]
        D4[Environment Hardening]
    end
    
    A1 --> A2
    A2 --> A3
    A3 --> B2
    B2 --> B3
    B3 --> B4
    B4 --> C1
    C1 --> C2
    C2 --> C3
    C3 --> D1
    D1 --> D2
```

## Component Details

### 1. Active Directory Environment
- **Domain Controller**: Windows Server 2022
- **Domain**: cs.local  
- **KRBTGT Account**: Special AD account that signs Kerberos TGTs
- **Test System**: WIN-HS48GJMN0GP

### 2. Attack Tools
- **FTK Imager**: Memory capture for forensic analysis
- **Mimikatz**: Credential dumping and ticket manipulation
- **Kerberos Utilities**: klist for ticket validation

### 3. Detection Stack
- **Windows Event Logs**: Security events (4724, 4738, etc.)
- **Elastic SIEM**: Centralized log analysis
- **Volatility 3**: Memory forensic analysis
- **SQLite Browser**: Browser artifact examination

### 4. Investigation Workflow
1. Memory capture and baseline evidence collection
2. Defender configuration review
3. Credential dumping simulation
4. Golden Ticket creation and validation
5. Detection evidence review in SIEM
6. Remediation activity and log validation
7. Supporting forensic artifact analysis
