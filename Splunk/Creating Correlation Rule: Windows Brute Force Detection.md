# Splunk Correlation Rule: Windows Brute Force Detection
 
---
 
## Project Overview
 
This project demonstrates the design and implementation of a correlation rule in **Splunk Enterprise Security (ES)** to detect potential **Windows brute force login attempts**.
 
The detection is based on identifying abnormal spikes in failed authentication events (Event ID 4625), which are commonly associated with password guessing attacks.
 
---
 
## Why This Detection Was Chosen
 
Brute force attacks are one of the most frequently observed attack techniques in real-world SOC environments. This use case was selected because:
 
- It is a common and practical attack scenario
- It helps build understanding of Windows authentication logs
- It maps directly to **MITRE ATT&CK T1110.001 – Password Guessing**
- It demonstrates core detection engineering concepts such as aggregation, thresholding, and alert tuning
---
 
## 1. Correlation Rule Creation (Detection Logic)
 
**[Screenshot: Photo3 – Correlation search configuration with rule name and SPL query]**
 
### SPL Query
 
```spl
vendor_product="Microsoft Windows" EventCode=4625
| stats count by user
| where count > 10
```
 
### Rationale
 
- `EventCode 4625` represents failed login attempts on Windows systems
- Aggregating events per user identifies behavioral patterns rather than isolated failures
- The threshold of greater than 10 reduces noise from routine login mistakes
This logic ensures the detection focuses on suspicious behavior rather than incidental authentication failures.
 
---
 
## 2. Detection Validation
 
**[Screenshot: Photo4 – Search results showing users with high failed login counts]**
 
Before deploying any detection, results must be reviewed to:
 
- Verify that the output is meaningful and accurate
- Confirm that the threshold is appropriate for the environment
- Ensure that the detection does not produce excessive noise
---
 
## 3. Scheduling Configuration
 
**[Screenshot: Photo1 – Time range and cron scheduling settings]**
 
| Setting | Value |
|---|---|
| Run frequency | Every 2 minutes |
| Time range | -2 minutes to now |
| Real-time scheduling | Enabled |
 
Brute force attacks occur rapidly, requiring near real-time detection to enable a timely response.
 
---
 
## 4. MITRE ATT&CK Mapping
 
**[Screenshot: Photo2 – Annotations showing MITRE ATT&CK mapping]**
 
| Field | Value |
|---|---|
| Technique | T1110.001 – Password Guessing |
| Tactic | Credential Access |
 
Mapping detections to the MITRE ATT&CK framework standardizes detection across environments, aligns alerts with known attacker techniques, and improves reporting and threat intelligence integration.
 
---
 
## 5. Trigger Conditions and Throttling
 
**[Screenshot: Photo7 – Trigger condition and throttling settings]**
 
| Setting | Value |
|---|---|
| Trigger condition | Results greater than 0 |
| Throttling field | `user` |
 
Throttling by user prevents duplicate alerts for the same account across polling intervals, minimizing alert fatigue while preserving meaningful detection coverage.
 
---
 
## 6. Notable Event Configuration (Dynamic Title)
 
**[Screenshot: Photo6 – Notable event title using $user$]**
 
Using dynamic field references such as `$user$` in the notable event title allows analysts to:
 
- Immediately identify the affected user from the alert title
- Produce more meaningful and readable alerts in the incident queue
---
 
## 7. Notable Event Full Configuration
 
**[Screenshot: Photo9 – Severity, domain, and drilldown settings]**
 
| Setting | Value |
|---|---|
| Severity level | Configured per threat context |
| Security domain | Endpoint |
| Drill-down search | Enabled |
 
This configuration transforms a detection into an actionable SOC alert with sufficient context for investigation.
 
---
 
## 8. Drill-Down Search
 
```spl
"Windows" EventCode=4625 user=$user$
```
 
The drill-down search allows analysts to:
 
- Quickly retrieve all related events for a specific user
- Analyze full login failure patterns in context
- Reduce the time required to begin an investigation
---
 
## 10. Field Enrichment
 
**[Screenshot: Photo11 – Identity and asset extraction fields]**
 
| Enrichment Type | Fields |
|---|---|
| Identity | `user`, `role` |
| Asset | `src`, `dest`, `host` |
 
Field enrichment provides additional investigative context, enabling analysts to quickly understand the scope and impact of an alert without switching between multiple tools.
 
---
## 12. Final Enabled Rule
 
**[Screenshot: Photo10 – Final saved and enabled correlation rule]**
 
Confirming the rule is enabled ensures the detection is active and continuously monitoring for brute force activity.
 
---
 
## Detection Tuning and False Positives
 
This detection may generate alerts in legitimate scenarios, including:
 
- Users repeatedly entering incorrect passwords
- Expired or cached credentials
- Misconfigured service accounts
- Internal vulnerability scans or penetration tests
### Mitigation Strategies
 
- Exclude known service accounts from the detection scope
- Adjust the failure count threshold based on baseline behavior in the environment
- Correlate with successful login events (Event ID 4624) to assess whether access was ultimately gained
- Include source IP analysis to differentiate internal from external activity
---
 
## Investigation Workflow
 
When this alert is triggered, a SOC analyst should follow these steps:
 
1. Identify the source IP address of the failed login attempts
2. Determine whether the activity originates from an internal or external source
3. Search for any corresponding successful login events (Event ID 4624)
4. Determine whether the targeted account is privileged
5. Correlate with other suspicious activity in the same timeframe
---
 
## Severity Tuning
 
| Severity | Condition |
|---|---|
| Low | Internal user login failures with no privilege escalation indicators |
| Medium | Multiple accounts targeted from the same source |
| High | External source targeting privileged or administrative accounts |
 
---
 
## Use Cases Covered
 
- Brute force attacks
- Password spraying
- Unauthorized login attempts
- Misconfigured services generating authentication noise
---
 
## Potential Improvements
 
- Add source IP correlation to identify attack origin
- Implement anomaly-based dynamic thresholds using baseline modeling
- Integrate with a SOAR platform for automated response and ticket creation
---
 
## Key Learnings
 
- SPL query development and aggregation techniques
- Windows Security Event Log analysis
- Detection tuning and alert optimization
- MITRE ATT&CK framework mapping
- SOC alert lifecycle management
---
 
## Conclusion
 
This project demonstrates a practical approach to detection engineering by combining technical implementation with operational considerations including tuning, investigation workflows, and alert management. The resulting rule provides a reliable, low-noise mechanism for detecting Windows brute force login attempts within a Splunk Enterprise Security environment.
