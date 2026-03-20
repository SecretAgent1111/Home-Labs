**Brute Force Attack Investigation**

**Description**- In this lab, I used IBM QRadar SIEM to investigate a brute force attack targeting a Linux server.
The analysis focuses on identifying failed login patterns, correlating events into offenses, and validating the alert as a true positive.

**Lab Environment**
SIEM: IBM QRadar Community Edition
Log Source: Linux Server
Attack Type: SSH Brute Force

**Investigation Workflow**

**Step 1: Log Analysis**
Applied filter to identify failed SSH login attempts:




**Step 2: Event Investigation**
Analyzed logs to identify suspicious activity patterns:




**Key Observations:**
Multiple failed login attempts
Same destination IP: 192.168.0.15
Multiple usernames targeted
High frequency of attempts

**Step 3: Offense Correlation**
QRadar correlated events into a security offense:




**Offense Details:**

Rule: Brute Force Attack
Multiple login failures detected
High magnitude score
Thousands of events generated

**Detection Logic**

The attack was identified based on:
Repeated failed login attempts
Multiple usernames targeted
Same destination host
High event volume in a short time

**MITRE ATT&CK**
T1110 — Brute Force

**Incident Report**

**Time of Activity:** 20 March 2026 (~02:00 AM – 02:06 AM)

**Affected Entities**: Host: 192.168.0.15

**Users**: root, admin, db, operator

**Source IPs:** Multiple external IPs

**Reason for True Positive:**
High volume of failed login attempts
Multiple usernames targeted
QRadar offense triggered
Matches brute force attack behavior

**Reason for Escalation:**
Critical service targeted (SSH)
Risk of unauthorized access
Persistent attack pattern

**Recommended Actions:**
Block attacker IPs
Disable root SSH login
Enable MFA

**Indicators of Compromise:**
Multiple failed SSH logins
External IP addresses
High event count
Target port 22
