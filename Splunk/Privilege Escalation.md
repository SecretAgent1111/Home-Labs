🔴 Privilege Escalation Detection — sudo to root (Splunk Lab)

---

## 📌 Objective

To simulate and detect a **Privilege Escalation attack** where a standard user gains root access using `sudo su`, and analyze the activity using Splunk SIEM.

---

## 🧪 Lab Environment

| Component | Details |
|----------|--------|
| SIEM | Splunk Enterprise (Windows 11) |
| Attacker Machine | Kali Linux |
| Victim Machine | Ubuntu |
| Log Source | `/var/log/auth.log` |
| Log Forwarding | Splunk Universal Forwarder |

---

## ⚔️ Attack Simulation

The attacker (logged-in user) executed the following command on the Ubuntu system:

```bash
sudo su

This command allows a normal user (bluevarun) to escalate privileges and obtain a root shell.

🖼️ Evidence — Attack Execution

User bluevarun executed sudo su
Authentication successful
Root shell (#) obtained
📊 Detection in Splunk
🔍 Search Query
index=* sourcetype=auth ("sudo" OR "su") 
("session opened for user root" OR "COMMAND=/usr/bin/su")
🖼️ Evidence — Splunk Logs

Key Log Evidence:
sudo: bluevarun : USER=root ; COMMAND=/usr/bin/su
pam_unix(sudo:session): session opened for user root
🚨 Alert Classification
✅ TRUE POSITIVE
🕒 Time of Activity

2026-03-26 16:17:41

👤 List of Affected Entities
User: bluevarun
Host: bluevarun-VirtualBox
Source: /var/log/auth.log
✅ Reason for Classifying as True Positive
The user executed sudo su, which is a direct privilege escalation technique
Logs confirm that a root session was successfully opened
This indicates elevation from a normal user to root privileges
Such behavior is considered high-risk and aligns with known attack patterns
🚀 Reason for Escalating the Alert
The user gained full administrative (root) access
This enables complete system control
Potential risks include persistence, lateral movement, and system compromise
Classified as Critical Severity in SOC environments
🔍 List of Attack Indicators
COMMAND=/usr/bin/su
session opened for user root
sudo: USER=root
pam_unix(sudo:session)
🛡️ Recommended Remediation Actions
Verify whether the activity was authorized
Restrict unnecessary sudo privileges
Review /etc/sudoers file for misconfigurations
Enforce least privilege principle
Monitor and alert on repeated privilege escalation attempts
Correlate with login activity (SSH logs)
🎯 MITRE ATT&CK Mapping
Technique	ID
Abuse Elevation Control Mechanism (sudo)	T1548.003
