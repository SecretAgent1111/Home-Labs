# Password Spray Attack Detection using Splunk (SOC L2 Lab)

---

## Objective

Simulate a Password Spray attack using Kali Linux and detect malicious authentication behavior in Splunk by analyzing Linux SSH logs.

---

## Lab Architecture

| Role     | System                         |
|----------|------------------------------|
| Attacker | Kali Linux                   |
| Victim   | Ubuntu Server                |
| SIEM     | Splunk Enterprise (Windows 11)|

---

## Attack Simulation

- A password spray attack was executed from Kali Linux targeting SSH service on the Ubuntu server.

### Attack Command Used:

hydra -L user.txt -p Password123 ssh://192.168.1.65 -V

### Attack Behavior:

- Single password used across multiple accounts
- Multiple usernames targeted (user1, user2, user3, admin1, ubuntu)
- Same source IP performing all attempts
- Sequential authentication attempts

## Attack Evidence (Kali Linux)

👉 Upload your Hydra attack screenshot here:

## Log Source

- Log File: /var/log/auth.log
- Log Type: SSH Authentication Logs
- Forwarded via Splunk Universal Forwarder

## Detection in Splunk

SPL Query Used:
index=* sourcetype=auth "Failed password"


| rex "Failed password for (invalid user )?(?<user>\w+)"


| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"


| stats count by user, src_ip


## Detection Evidence (Splunk)


👉 Upload your Splunk detection screenshot here:

## Analysis

### Key Observations:
- Source IP: 192.168.1.229
- Targeted Users:
ubuntu,
user1,
user2,
user3,
admin1,

### Behavior Identified:

- Single IP attempting authentication across multiple users
- Repeated failed login attempts
- Presence of "invalid user" logs (username enumeration)
- Pattern matches password spray attack technique

🎯 Affected Entities:
ubuntu
user1
user2
user3
admin1
🌐 Source of Attack:
IP Address: 192.168.1.229
Origin: Kali Linux (Attacker Machine)
🧠 Reason for Classification:
Confirmed attack execution from attacker machine
Same password used across multiple accounts
Multiple authentication failures within short time frame
Same source IP targeting multiple users
Matches known Password Spray attack pattern
🚨 Reason for Escalation:
Indicates active credential access attempt
High risk of account compromise if successful
Attack can bypass traditional account lockout controls
Evidence of username enumeration increases threat level
🧬 MITRE ATT&CK Mapping:
Technique: Password Spraying (T1110.003)
🧾 Indicators of Compromise (IOCs):
Source IP: 192.168.1.229
Multiple failed SSH login attempts
Authentication attempts across multiple users
Repeated use of common password
🛡️ Recommended Remediation Actions
Block or isolate the attacking IP address
Implement Multi-Factor Authentication (MFA)
Enforce strong password policies
Configure account lockout thresholds
Monitor authentication logs for similar patterns
Deploy intrusion detection or prevention systems
📚 Key Learnings
Password Spray attacks target multiple accounts with a single password
Detection relies on identifying patterns across users, not just failed attempts
Field extraction (rex) is essential when logs are unstructured
Even unsuccessful attacks are valid security incidents
