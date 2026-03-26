# Privilege Escalation Detection — sudo to root (Splunk Lab)

---

## 1. Objective

In this lab, I'm simulating a privilege escalation attack where a normal user tries to gain root access using the `sudo su` command. The goal is to detect this attack in real-time using Splunk and understand how to identify suspicious privilege escalation attempts.

---

## 2. Lab Architecture

| Component | Details |
|-----------|----------|
| SIEM | Splunk Enterprise (Windows 11) |
| Attacker Machine | Kali Linux |
| Victim Machine | Ubuntu |
| Log Source | `/var/log/auth.log` |
| Log Forwarding | Splunk Universal Forwarder |

---

## 3. Attack Simulation

The attacker (logged-in user) executed the following command on the Ubuntu system:

```bash
sudo su
```

This command lets a standard user (bluevarun) escalate to root privileges, effectively giving full system access. It's a classic privilege escalation technique that attackers commonly use.

### Evidence Screenshot
![Attack Screenshot](./images/ubuntupsa.png)
---

## 4. Evidence — Attack Execution

- User bluevarun executed sudo su
- Authentication successful
- Root shell (#) obtained

---

## 5. Detection in Splunk

### Search Query

```
index=* sourcetype=auth ("sudo" OR "su") ("session opened for user root" OR "COMMAND=/usr/bin/su")
```

### Evidence — Splunk Logs

**Key Log Evidence:**

- `sudo: bluevarun : USER=root ; COMMAND=/usr/bin/su`
- `pam_unix(sudo:session): session opened for user root`

---

## 6. Alert Classification

TRUE POSITIVE

### Time of Activity

2026-03-26 16:17:41

### List of Affected Entities

- User: bluevarun
- Host: bluevarun-VirtualBox
- Source: /var/log/auth.log

---

## 7. Reason for Classifying as True Positive

- We saw the user run sudo su, which is basically skipping straight to the privilege escalation
- The logs show that a root session was successfully opened
- This means the user went from a normal account directly to root access
- That kind of behavior is definitely high-risk and matches known attack patterns

---

## 8. Reason for Escalating the Alert

- The user gained full administrative (root) access
- This enables complete system control
- This could lead to persistence mechanisms, lateral movement to other systems, or complete system compromise
- Classified as Critical Severity in SOC environments

---

## 9. List of Attack Indicators

- COMMAND=/usr/bin/su
- session opened for user root
- sudo: USER=root
- pam_unix(sudo:session)

---

## 10. Recommended Remediation Actions

- Verify whether the activity was authorized
- Restrict unnecessary sudo privileges
- Review /etc/sudoers file for misconfigurations
- Enforce **least** privilege principle
- Monitor and alert on repeated privilege escalation attempts
- Correlate with login activity (SSH logs)

---

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Privilege Escalation | Abuse Elevation Control Mechanism (sudo) | T1548.003 |
