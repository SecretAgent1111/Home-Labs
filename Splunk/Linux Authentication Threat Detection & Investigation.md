# Linux Authentication Threat Detection & Investigation

---

## Overview

This project demonstrates the detection and analysis of an **SSH brute force attack** using Splunk Enterprise in a controlled home lab environment.

The attack was simulated using Hydra from an attacker machine, while logs were collected from a Linux victim system and analyzed in Splunk.

---

## Lab Architecture

| Component  | Role                     |
|------------|--------------------------|
| Windows 11 | Splunk Enterprise (SIEM) |
| Ubuntu     | Victim (SSH Server)      |
| Kali Linux | Attacker (Hydra Tool)    |

---

## Attack Simulation

```bash
hydra -l ubuntu -p rockyou.txt ssh://192.168.1.66
```

![Hydra Attack](images/1la.png)

**Figure 1:** SSH brute force attack executed using Hydra from Kali Linux.

### Observations

- Multiple failed login attempts generated
- Targeted user: `ubuntu`
- Attacker IP identified: `192.168.1.64`
- No valid credentials discovered

---

## Log Ingestion Verification

```spl
index=* sourcetype=linux:auth
```

![Splunk Detection](images/2la.png)

**Figure 2:** Authentication logs successfully ingested into Splunk.

### Explanation

- Confirms successful ingestion of logs
- Filters Linux authentication events
- Serves as the baseline query

---

## Failed Login Detection

```spl
index=* sourcetype=linux:auth "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| sort - count
```

![Splunk Detection](images/3la.png)

**Figure 3:** Aggregated failed login attempts by source IP.

### Explanation

- Detects failed SSH authentication attempts
- Extracts attacker IP using regex
- Aggregates attempts per IP

### Findings

| Field       | Value        |
|-------------|--------------|
| Attacker IP | 192.168.1.64 |
| Attempts    | 3            |

---

## Severity Classification

```spl
index=* sourcetype=linux:auth
| eval severity=case(
    searchmatch("Failed password"), "Medium",
    searchmatch("Accepted password"), "High",
    true(), "Low"
)
| stats count by severity
```

![Splunk Detection](images/7la.png)

**Figure 4:** Events categorized by severity levels.

### Explanation

- Assigns severity dynamically
- Helps prioritize security events

---

## Raw Log Evidence

```spl
index=* sourcetype=linux:auth ("Failed password" OR "Accepted password")
| table _time, host, _raw
```

![Splunk Detection](images/6la.png)

**Figure 5:** Raw authentication logs showing failed SSH attempts.

### Explanation

- Displays original logs
- Used for validation and investigation

---

## Time-Based Attack Analysis

```spl
index=* sourcetype=linux:auth "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| timechart count by src_ip span=1m
```

![Splunk Detection](images/5la.png)

**Figure 6:** Time-based visualization of attack activity.

### Explanation

- Shows attack frequency over time
- Helps identify automated behavior

---

## Attack Correlation

```spl
index=* sourcetype=linux:auth ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval action=if(searchmatch("Failed password"),"Failed","Success")
| stats count by src_ip, action
```

![Splunk Detection](images/4la.png)

**Figure 7:** Correlation of failed vs successful login attempts.

### Explanation

- Combines failed and successful events
- Helps determine compromise

### Findings

- Only failed attempts observed
- No successful login detected

---

## SOC Analysis

| Attribute       | Value           |
|-----------------|-----------------|
| Attack Type     | SSH Brute Force |
| MITRE Technique | T1110           |
| Source IP       | 192.168.1.64    |
| Target System   | Ubuntu          |
| Outcome         | No compromise   |

---

## Alert Classification

- **Type:** True Positive
- **Severity:** Medium
- **Reason:** Repeated failed authentication attempts

---

## Recommendations

- Implement account lockout policies
- Use SSH key-based authentication
- Disable password login
- Enable MFA
- Restrict SSH access

---

## MITRE ATT&CK Mapping

| Technique            | ID        | Description                                  |
|----------------------|-----------|----------------------------------------------|
| Brute Force          | T1110     | Repeated login attempts to guess credentials |
| Password Spraying    | T1110.003 | Common passwords across accounts             |
| Valid Accounts       | T1078     | Use of compromised credentials               |
| Remote Services: SSH | T1021.004 | Exploiting SSH access                        |

---

## Conclusion

This project demonstrates:

- Threat detection using Splunk
- Log analysis and validation
- Regex-based field extraction
- Attack correlation
- SOC-level investigation workflow
