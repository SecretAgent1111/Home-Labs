# High Number of Connections to Multiple Destinations from Single Source

---

## Project Overview

This detection identifies anomalous network behavior where a single source IP communicates with a high number of unique destination IPs within a short time window. Such behavior is commonly associated with reconnaissance, network scanning, or early-stage lateral movement.

The detection is built using FortiGate firewall traffic logs ingested into Splunk Enterprise Security and operationalized as a correlation search that generates notable events.

---

## Why This Detection Was Chosen

Network-based reconnaissance is often one of the earliest observable indicators of an attacker inside or outside the network. Detecting this activity early allows SOC teams to:

- Identify compromised hosts performing internal scanning
- Detect external scanning attempts targeting internal assets
- Prevent escalation into lateral movement or exploitation

This detection provides strong visibility into abnormal connection patterns that deviate from normal user or system behavior.

---

## Objective

To detect potential scanning or brute-force behavior by identifying source IPs that connect to an unusually high number of unique destination IPs within a defined time window.

---

## 1. Detection Logic

### SPL Query

```spl
sourcetype=fortigate_traffic
| stats count dc(dstip) as unique_targets by srcip
| where unique_targets > 50
```

### Explanation of SPL

`sourcetype=fortigate_traffic` filters events to only include FortiGate firewall traffic logs, ensuring that only network-level connection data is analyzed.

`| stats count dc(dstip) as unique_targets by srcip`

- `count` — total number of connection events per source IP
- `dc(dstip)` — counts distinct destination IPs contacted by each source
- `as unique_targets` — renames the field for clarity
- `by srcip` — groups results by each source IP

This step identifies how many unique systems each source is communicating with.

`| where unique_targets > 50` filters results to only include source IPs that contacted more than 50 unique destinations. This threshold is critical for distinguishing normal behavior from scanning activity.

---

## 2. Detection Validation

[photo1]

Validation confirms that certain source IPs are communicating with an abnormally high number of unique destinations, which is not typical for standard user or server behavior.

---

## 3. Scheduling Configuration

[photo2]

| Setting | Value |
|---|---|
| Time Range | Last 5 minutes (-5m to now) |
| Cron Schedule | `*/5 * * * *` (every 5 minutes) |
| Scheduling Mode | Real-time |
| Priority | Highest |

Running this detection frequently ensures near real-time visibility into scanning behavior.

---

## 4. MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique ID | T1046 |
| Technique Name | Network Service Scanning |

This detection aligns with adversaries attempting to discover services and hosts within a network.

---

## 5. Trigger Conditions and Throttling

[photo3]

| Setting | Value |
|---|---|
| Trigger Condition | Number of results > 0 |
| Trigger Mode | Once per search execution |
| Throttling Window | 60 seconds |
| Throttling Field | `srcip` |

Throttling prevents alert fatigue by suppressing duplicate alerts for the same source IP within a short window.

---

## 6. Notable Event Configuration

[photo4]

| Setting | Value |
|---|---|
| Title | Multiple Destination Connections Detected |
| Security Domain | Network |
| Severity | Medium |

Severity is set to Medium because this activity is suspicious but requires further validation before escalation.

---
## 8. Field Enrichment

[photo6]

| Enrichment Type | Fields |
|---|---|
| Identity | `src_user`, `user`, `user_id` |
| Asset | `src`, `dest`, `dvc`, `orig_host` |

Enrichment helps correlate IPs with users, systems, and roles, improving investigation context.

---

## Detection Tuning and False Positives

This detection may generate alerts in legitimate scenarios, including:

- Vulnerability scanners (e.g., Nessus, Qualys)
- Network monitoring tools
- Patch management systems
- Load balancers or proxy servers
- Internal services communicating with multiple endpoints

### Tuning Strategies

- Exclude known scanner IPs using lookup tables
- Increase threshold based on environment baseline
- Restrict detection to internal-to-internal or external-to-internal traffic
- Add time-based thresholds (e.g., bursts within 1 minute)

---

## Investigation Workflow

When this alert is triggered, a SOC analyst should follow these steps:

1. Identify the flagged `srcip`
2. Check asset inventory for system ownership
3. Determine if the IP belongs to a legitimate scanner, a user endpoint, or a server
4. Review connection patterns including ports targeted and destination distribution
5. Pivot using the drill-down search
6. Check for authentication attempts and lateral movement indicators
7. Escalate if behavior is confirmed malicious

---

## Severity Tuning

| Severity | Condition |
|---|---|
| Low | Known scanner or expected behavior |
| Medium | Unknown internal system scanning |
| High | External IP scanning internal network |
| Critical | Confirmed compromise performing lateral movement |

---

## Use Cases Covered

- Detect internal reconnaissance post-compromise
- Identify external scanning attempts
- Monitor abnormal service discovery behavior
- Detect worm-like propagation patterns

---

## Potential Improvements

- Add geo-location enrichment for external IPs
- Correlate with IDS/IPS alerts
- Integrate threat intelligence feeds
- Add port-based analysis
- Implement risk scoring

---

## Key Learnings

- Distinct count (`dc`) is powerful for anomaly detection
- Threshold tuning is critical to reduce noise
- Context enrichment significantly improves triage efficiency
- Correlation searches should always include drill-down capabilities

---

## Conclusion

This detection provides strong visibility into early-stage reconnaissance activity. By focusing on connection patterns rather than signatures, it enables detection of both known and unknown threats.

When properly tuned, this rule becomes a valuable component of a SOC's network threat detection strategy.
