# Account Lockout Detection using Splunk

## Objective

This lab demonstrates detection of **account lockout events** caused by repeated failed login attempts, helping to differentiate between:

- User mistakes  
- Brute-force attacks  

The objective is to simulate a real attack and validate detection capabilities in **Splunk Enterprise**.

---

## Lab Environment

| Component    | Description                  |
|--------------|------------------------------|
| **Attacker** | Kali Linux                   |
| **Victim**   | Ubuntu 22.04                 |
| **SIEM**     | Splunk Enterprise (Windows 11) |
| **Log Source**| `/var/log/auth.log`         |

---

## Configuration (Security Control)

**Account lockout enabled using `pam_faillock` (modern Linux PAM module):**

| Parameter           | Value         |
|---------------------|---------------|
| Max failed attempts | 5             |
| Lockout duration    | 120 seconds   |

This ensures accounts are temporarily locked after repeated failed login attempts.

---

## Attack Simulation

### Step 1 — Brute Force Attack

Attacker executed **Hydra** against target:

```bash
hydra -l user1 -P small.txt ssh://192.168.1.66 -t 4
```

**Behavior:**
- Rapid login attempts from same IP
- Targets single user account (`user1`)
- Simulates realistic brute-force attack

**Screenshot 1 — Attack Execution (Hydra)**  
*(Upload your 3rd screenshot here)*

### Attack Result

- Multiple failed login attempts generated
- System triggered account lockout
- Further authentication attempts blocked

**Screenshot 2 — Account Lockout Evidence (faillock)**  
*(Upload your 2nd screenshot here)*

**Analysis from faillock output:**
- Source IP: `192.168.1.64`
- Multiple failed attempts within seconds
- All attempts marked valid
- **Indicates automated attack (not human error)**

---

## Splunk Detection

### Detection Query

```spl
index=* sourcetype=linux:auth
("pam_faillock" OR "authentication failure" OR "Failed password")
```

**Screenshot 3 — Splunk Detection Output**  
*(Upload your 1st screenshot here)*

**SPL Query Explanation**

| Component              | Purpose                          |
|------------------------|----------------------------------|
| `pam_faillock`         | Detect lockout events            |
| `authentication failure` | General login failure patterns |
| `Failed password`      | SSH brute-force attempts         |

**This query correlates:**
- Failed authentication attempts
- Lockout trigger events
- Suspicious authentication behavior

---

## SOC Analysis

**Key Findings:**
- Single IP (`192.168.1.64`) performed multiple rapid login attempts
- High-speed authentication failures (same timestamp)
- Account lockout triggered after threshold exceeded

**Conclusion:**  
**Brute Force Attack leading to Account Lockout**  
**Classification: TRUE POSITIVE**

**Time of Activity:** *(Add from Splunk timeline)*

**Affected Entities:**

| Entity     | Value              |
|------------|--------------------|
| **User**   | user1              |
| **Source IP**| 192.168.1.64     |
| **Host**   | Ubuntu Server      |

**Reason for Classification:**
- Rapid repeated login failures from single IP
- Automated attack pattern detected
- Lockout mechanism successfully triggered

---

## Reason for Escalation

- Active brute-force attempt detected
- Account compromise risk identified
- Potential precursor to lateral movement

---

## Recommended Remediation

1. **Enforce account lockout policies** (pam_faillock configuration)
2. **Enable MFA for SSH access**
3. **Disable password authentication** (use SSH keys only)
4. **Monitor failed login patterns** via SIEM alerts
5. **Implement IP blocking** (Fail2Ban deployment)

---

## Indicators of Compromise (IOCs)

- Multiple failed SSH login attempts from single IP
- Same IP targeting specific account repeatedly
- `pam_faillock` lockout events triggered
- Authentication failures concentrated in short time window

---

## MITRE ATT&CK Mapping

| Technique            | ID    |
|----------------------|-------|
| Brute Force          | T1110 |
| Valid Accounts       | T1078 |
| Remote Services (SSH)| T1021 |
