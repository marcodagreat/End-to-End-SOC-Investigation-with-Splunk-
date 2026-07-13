# SOC Investigation Playbook

## Brute Force Detection & Response

---

## Purpose

Provide a standardized workflow for detecting, investigating, containing, remediating, and validating brute-force attacks against Windows Active Directory endpoints.

---

# Alert Trigger

Initiate this playbook when one or more of the following conditions are observed:

- Multiple Windows Event ID **4625** events
- Authentication failures from the same source IP
- Spike in failed logons over a short period
- Multiple targeted user accounts
- Authentication activity following reconnaissance

---

# MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1046 | Network Service Discovery |
| T1110 | Brute Force |
| T1078 | Valid Accounts |

---

# Detection

### Data Sources

- Windows Security Logs
- Sysmon
- Splunk Enterprise
- Active Directory
- Group Policy

### Indicators

- Event ID 4625
- Event ID 4624
- Sysmon Event ID 3
- Repeated RDP authentication attempts
- Single source attacking multiple accounts

---

# Initial Triage

Identify:

- Source IP
- Destination Host
- Target Account
- Number of failed attempts
- Timeframe
- Authentication protocol

Determine:

- Was reconnaissance observed?
- Was there a successful authentication?
- Was an interactive session established?
- Does the activity appear malicious?

---

# Investigation

Review:

- Windows Event ID 4625
- Windows Event ID 4624
- Sysmon network events
- Splunk dashboard
- Authentication timeline

Correlate:

- Source IP
- Target host
- Target account
- Event sequence
- MITRE ATT&CK techniques

---

# Containment

Immediate Actions

- Reset compromised credentials
- Restrict Remote Desktop through Group Policy
- Configure Account Lockout Policy
- Force Group Policy update

```cmd
gpupdate /force
```

Optional Network Containment

- Block TCP 3389
- Block attacker IP on firewall or router

---

# Remediation

- Password reset
- Account lockout policy
- RDP restriction
- Verify Group Policy application
- Remove unnecessary Remote Desktop permissions
- Continue monitoring

---

# Validation

Verify:

- Unauthorized RDP login denied
- Group Policy applied successfully
- Password reset completed
- Splunk continues receiving logs
- No additional unauthorized logons observed

---

# Recovery

- Restore business functionality
- Continue monitoring
- Document actions taken
- Close incident

---

# Lessons Learned

- Authentication does not equal authorization.
- SIEM dashboards support investigation, not just monitoring.
- Layered controls improve security.
- Manual validation is required after remediation.

---

# Deliverables

- Splunk Dashboard
- SPL Detection Searches
- Incident Response Report
- MITRE ATT&CK Mapping
- Security Recommendations
