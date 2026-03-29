# Web Attack Detection (XSS) using Apache Logs

---

## Lab Overview

This lab demonstrates the detection of a **Cross-Site Scripting (XSS)** attack using Apache web server logs ingested into Splunk. The objective is to identify malicious web requests by analyzing encoded payloads and applying detection logic within Splunk.

---

## Environment Setup

| Component      | Details                          |
|----------------|----------------------------------|
| Attacker       | Kali Linux                       |
| Target System  | Apache Web Server (Kali)         |
| SIEM           | Splunk Enterprise (Windows)      |
| Log Source     | `/var/log/apache2/access.log`    |

---

## Attack Simulation

The attack was simulated by sending crafted HTTP requests containing XSS payloads to the Apache server.

### XSS Payload Execution

```bash
curl "http://192.168.1.64/index.html?q=<script>alert(1)</script>"
```

---

### Log Evidence (Apache Access Log)

The following entries were captured in the Apache access log:

![Splunk Detection](images/kaliwa.png)

```
GET /index.html?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
```

**Observation:**

- The payload is URL encoded
- `<script>` → `%3Cscript%3E`
- `'` → `%27`

This encoding is commonly used to bypass detection mechanisms.

---

## Detection in Splunk

### SPL Query Used

```spl
index=* source="/var/log/apache2/access.log"
| eval decoded=urldecode(_raw)
| search decoded="*script*" OR decoded="*OR 1=1*"
| table _time, decoded
```
![Splunk Detection](images/splunkwa.png)

---

### SPL Query Breakdown

#### 1. Data Source Selection

```spl
index=* source="/var/log/apache2/access.log"
```

- Searches across all indexes
- Filters specifically for Apache access logs

---

#### 2. URL Decoding

```spl
| eval decoded=urldecode(_raw)
```

- Converts encoded payloads into readable format
- Example: `%3Cscript%3E` → `<script>`
- Enables accurate detection of obfuscated attacks

---

#### 3. Detection Logic

```spl
| search decoded="*script*" OR decoded="*OR 1=1*"
```

- Identifies:
  - XSS patterns (`<script>`)
  - SQL Injection patterns (`OR 1=1`)
- Uses wildcard matching to capture variations

---

#### 4. Output Formatting

```spl
| table _time, decoded
```

- Displays:
  - Event timestamp
  - Decoded raw log data

---

### Detection Evidence (Splunk)

The decoded log clearly shows the injected XSS payload:

```
GET /index.html?q=<script>alert(1)</script> HTTP/1.1
```

---

## Incident Analysis

**Time of Activity:** `2026-03-30 00:37:12`

**Affected Entity:** Apache Web Server (Kali Linux)

**Source:** `192.168.1.229`

**Classification: TRUE POSITIVE**

**Reason:**

- The HTTP request contains a JavaScript payload (`<script>alert(1)</script>`)
- Payload is embedded within a query parameter
- Matches known XSS attack patterns
- URL encoding indicates an attempt to evade detection

---

## Escalation Justification

XSS can lead to:

- Session hijacking
- Credential theft
- Client-side exploitation

This indicates probing or exploitation attempt on web application.

---

## Recommended Actions

- Implement input validation and sanitization
- Deploy Web Application Firewall (WAF)
- Block or monitor source IP
- Enable logging and alerting for similar patterns

---

## Indicators of Compromise (IOCs)

- `%3Cscript%3Ealert(1)%3C/script%3E`
- `<script>alert(1)</script>`
- Suspicious query parameter (`q=`)
