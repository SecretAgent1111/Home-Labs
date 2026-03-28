 Impossible Travel Detection using Splunk Enterprise

## Overview

This project demonstrates the detection of *Impossible Travel*, a behavioral security use case commonly implemented in cloud and identity security platforms.

Impossible travel occurs when a user logs in from two geographically distant locations within a time frame that is physically impossible. This behavior is a strong indicator of potential credential compromise or unauthorized access.

Detection is implemented using Splunk Search Processing Language (SPL) by correlating login events based on user identity, location, and timestamp.

---

## Objective

- Detect abnormal login behavior across multiple geolocations  
- Identify potential account compromise scenarios  
- Perform behavioral analysis using event correlation  
- Build a practical SOC detection use case using Splunk  

---

## Lab Environment

| Component        | Details                |
|-----------------|-----------------------|
| SIEM            | Splunk Enterprise     |
| Data Source     | Simulated login logs  |
| Detection Type  | Behavioral Detection  |
| Technique       | Event Correlation     |

---

## Attack Simulation

The following login activity was simulated:


2026-03-28T10:00:00 user=varun ip=8.8.8.8 location=USA
2026-03-28T10:30:00 user=varun ip=1.1.1.1 location=India
2026-03-28T11:00:00 user=alex ip=5.5.5.5 location=UK
2026-03-28T18:00:00 user=alex ip=5.5.5.5 location=UK


In this scenario, the user `varun` logs in from the USA and India within 30 minutes, which is not physically possible and indicates suspicious activity.

---

## Data Ingestion

The log file was ingested into Splunk with the following configuration:

- Index: `main`  
- Sourcetype: `login_logs`  

---

## Detection Logic (SPL)

```spl
index=main sourcetype=login_logs
| rex "user=(?<user>\S+)"
| rex "location=(?<location>\S+)"
| sort 0 user _time
| streamstats current=f last(location) as prev_location last(_time) as prev_time by user
| eval time_diff=round((_time - prev_time)/60,2)
| where isnotnull(prev_location)
| where location!=prev_location AND time_diff < 120
| table user prev_location location time_diff
SPL Query Explanation
1. Search Scope
index=main sourcetype=login_logs

Retrieves login events from the relevant dataset.

2. Field Extraction
| rex "user=(?<user>\S+)"
| rex "location=(?<location>\S+)"

Extracts structured fields from raw logs:

user → username
location → login location
3. Event Ordering
| sort 0 user _time

Sorts events chronologically per user to ensure correct sequence for correlation.

4. Previous Event Correlation
| streamstats current=f last(location) as prev_location last(_time) as prev_time by user

Tracks the previous login event for each user:

Previous location
Previous timestamp
5. Time Difference Calculation
| eval time_diff=round((_time - prev_time)/60,2)

Calculates the time difference (in minutes) between consecutive logins.

6. Filtering Valid Events
| where isnotnull(prev_location)

Removes the first login event per user since it has no previous reference.

7. Detection Condition
| where location!=prev_location AND time_diff < 120

Flags suspicious activity where:

Login location changes
Time difference is less than 120 minutes
8. Output Formatting
| table user prev_location location time_diff

Displays the final detection output.

Detection Output

![Splunk Detection](images/splunkit.png)

/screenshots/impossible_travel_detection.png
Incident Analysis
Field	Value
User	varun
Previous Location	USA
Current Location	India
Time Difference	30 min
True Positive Analysis

Time of Activity:
2026-03-28

Affected Entity:
User: varun

Reason for Classification:

Login from geographically distant locations
Unrealistic travel time
Indicates possible credential compromise

Reason for Escalation:

Potential account takeover
Unauthorized system access

Recommended Actions:

Force password reset
Enable multi-factor authentication (MFA)
Review login history and sessions
Block or monitor suspicious IP addresses


MITRE ATT&CK Mapping
Technique	ID
Valid Accounts	T1078
