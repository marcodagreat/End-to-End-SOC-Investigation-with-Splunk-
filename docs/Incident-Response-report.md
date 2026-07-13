# Incident Response Report

## Active Directory RDP Brute Force Investigation

---

# Executive Summary

A simulated RDP brute-force attack was conducted from a Kali Linux system against a Windows 11 domain-joined endpoint within an isolated cybersecurity homelab.

Splunk Enterprise successfully detected reconnaissance activity, repeated authentication failures, and successful authentication events. The investigation correlated Windows Security logs, Sysmon telemetry, and Active Directory activity to identify the attacker, targeted endpoint, and affected account.

Containment actions included credential reset, Active Directory account lockout configuration, and Remote Desktop restrictions through Group Policy. Manual validation confirmed that unauthorized interactive Remote Desktop access was denied after remediation.

---

# Incident Information

| Item | Value |
|------|------|
| Incident Type | RDP Brute Force |
| Severity | High |
| Status | Contained |
| Environment | Active Directory Homelab |
| SIEM | Splunk Enterprise |

---

# Affected Assets

| Asset | Details |
|-------|---------|
| Source | Kali Linux |
| Source IP | 10.30.30.6 |
| Target | Windows 11 Target-PC |
| Target IP | 10.20.20.15 |
| Domain | myvrhomelab.local |
| Target Account | rsmith |

---

# Timeline

## Phase 1

Reconnaissance

- Network discovery performed
- Sysmon telemetry generated
- Splunk detected network activity

---

## Phase 2

Credential Attack

Hydra initiated repeated RDP authentication attempts.

Evidence

- Windows Event ID 4625
- Failed authentication timeline

---

## Phase 3

Credential Validation

Hydra identified a valid credential.

Windows Event ID 4624 was reviewed.

MITRE ATT&CK

- T1110
- T1078

---

## Phase 4

Investigation

Analyst identified

- Source IP
- Target host
- Target account
- Authentication timeline
- Reconnaissance activity

---

## Phase 5

Containment

Completed:

- Password reset
- Account lockout configuration
- RDP restriction
- Group Policy deployment
- Group Policy validation

---

## Phase 6

Validation

Manual Remote Desktop testing confirmed:

> The connection was denied because the user account is not authorized for remote login.

Splunk continued receiving authentication events throughout the investigation.

---

# Detection Sources

- Windows Security Logs
- Sysmon
- Splunk Enterprise
- Active Directory
- Group Policy
- Hydra output

---

# MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1046 | Network Service Discovery |
| T1110 | Brute Force |
| T1078 | Valid Accounts |

---

# Evidence Collected

- Splunk Dashboard
- Failed Login Timeline
- Security Timeline
- Reconnaissance Timeline
- Top Source IP
- Destination Port Analysis
- Active Directory
- Group Policy
- Password Reset
- Account Lockout Policy
- Manual RDP Validation

---

# Root Cause

Weak credentials allowed the simulated brute-force attack to discover a valid password.

Although the credentials were valid, Group Policy prevented the account from establishing an interactive Remote Desktop session after remediation.

---

# Containment Actions

- Password reset
- Restricted Remote Desktop permissions
- Account lockout policy
- Group Policy deployment
- Continued Splunk monitoring

---

# Remediation

Implemented:

- Password reset
- Account lockout threshold
- Account lockout duration
- Group Policy hardening
- Remote Desktop restrictions

Recommended:

- MFA
- Windows Firewall RDP rule
- MikroTik firewall rule
- Continuous monitoring

---

# Validation

Completed:

- Group Policy applied
- Unauthorized RDP denied
- Password reset verified
- Splunk monitoring confirmed
- Authentication activity reviewed

---

# Lessons Learned

- Authentication and authorization are separate security processes.
- SIEM dashboards should support analyst investigation.
- Layered security controls improve containment.
- Manual validation is required after remediation.
- MITRE ATT&CK mapping improves investigation quality.

---

# Recommendations

## Immediate

- Enable MFA
- Increase password complexity
- Restrict RDP
- Continue monitoring Event ID 4625

## Future Improvements

- Integrate Suricata IDS
- Add MikroTik firewall logging
- Create Splunk alerting
- Automate incident response using SOAR
- Correlate endpoint, firewall, and IDS telemetry

---

# Conclusion

This project demonstrated the complete SOC incident lifecycle:

- Detection
- Investigation
- Triage
- MITRE ATT&CK Mapping
- Containment
- Remediation
- Validation
- Documentation

The project provided practical experience with Splunk Enterprise, Windows Security Events, Sysmon, Active Directory, Group Policy, incident response, and security operations workflows within a realistic enterprise-style homelab.
