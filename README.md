# End-to-End SOC Investigation with Splunk

## Active Directory Reconnaissance, RDP Brute-Force Detection, Triage, Containment, Remediation, and Incident Response

This project documents an end-to-end SOC investigation performed in an authorized and isolated cybersecurity homelab.

The goal was to move beyond basic log collection and dashboard creation by demonstrating the complete incident-handling lifecycle:

> **Attack Simulation → Detection → Triage → Containment → Remediation → Validation → Incident Reporting**

The lab focused on detecting reconnaissance activity and a simulated RDP brute-force attack against a domain-joined Windows 11 endpoint. Splunk Enterprise was used to centralize Windows Security and Sysmon telemetry, correlate attacker behavior, identify affected systems and accounts, map activity to MITRE ATT&CK, support analyst triage, and validate the effectiveness of Active Directory and Group Policy remediation controls.

> **Disclaimer:** All attack activity documented in this repository was performed only against systems that I own and control inside a private cybersecurity homelab. The project was created for defensive security education, detection validation, and incident-response practice.

---

# Table of Contents

1. [Project Objectives](#project-objectives)
2. [Lab Environment](#lab-environment)
3. [Network and System Details](#network-and-system-details)
4. [Attack Scenario](#attack-scenario)
5. [SOC Investigation Workflow](#soc-investigation-workflow)
6. [Data Sources](#data-sources)
7. [Important Windows Event IDs](#important-windows-event-ids)
8. [Splunk Dashboard Capabilities](#splunk-dashboard-capabilities)
9. [Detection Logic](#detection-logic)
10. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
11. [Triage Process](#triage-process)
12. [Investigation Findings](#investigation-findings)
13. [Containment Actions](#containment-actions)
14. [Remediation and Hardening](#remediation-and-hardening)
15. [Validation Results](#validation-results)
16. [Incident Response Summary](#incident-response-summary)
17. [Screenshots and Evidence](#screenshots-and-evidence)
18. [Repository Structure](#repository-structure)
19. [Skills Demonstrated](#skills-demonstrated)
20. [Lessons Learned](#lessons-learned)
21. [Future Enhancements](#future-enhancements)

---

## Project Evidence and Documentation

- [View Investigation Screenshots](Screenshots/README.md)
- [Read the Incident Response Report](docs/Incident-Response-report.md)
- [Read the SOC Investigation Playbook](docs/soc-investigation-playbook.md)

---

# Project Objectives

The main objectives of this project were to:

- Centralize Windows Security and Sysmon telemetry in Splunk Enterprise
- Detect network reconnaissance originating from Kali Linux
- Detect repeated RDP authentication failures
- Identify the attacking source IP
- Identify the targeted endpoint
- Identify the affected domain account
- Review successful authentication events following repeated failures
- Distinguish authentication success from authorization success
- Map attacker behavior to MITRE ATT&CK
- Build a centralized SOC threat-detection dashboard
- Perform identity-based containment in Active Directory
- Restrict unauthorized RDP access using Group Policy
- Configure an Active Directory account lockout policy
- Reset compromised credentials
- Validate that unauthorized interactive RDP access was denied
- Create a reusable SOC investigation playbook
- Produce a formal incident response report

---

# Lab Environment

| Component | Purpose |
|---|---|
| Kali Linux | Authorized attack-simulation host |
| Windows 11 Target-PC | Domain-joined endpoint and RDP target |
| Windows Server ADDC01 | Active Directory, DNS, and Group Policy |
| Splunk Enterprise | SIEM, searching, dashboards, and investigation |

---

# Network and System Details

| Asset | Address or Identifier |
|---|---|
| Kali Linux attack host | `10.30.30.6` |
| Active Directory server | `10.20.20.10` |
| Windows 11 target endpoint | `10.20.20.15` |
| Splunk Enterprise server | `10.40.40.30:8000` |
| Active Directory domain | `myvrhomelab.local` |
| Domain controller | `ADDC01.myvrhomelab.local` |
| Target endpoint | `Target-PC.myvrhomelab.local` |
| Targeted test account | `rsmith` |
| Attack protocol | RDP |
| RDP port | TCP `3389` |

---

# Attack Scenario

The simulated incident followed this sequence:

1. Kali Linux performed reconnaissance against Windows systems in the lab.
2. Sysmon and Windows logs were forwarded into Splunk.
3. Splunk displayed reconnaissance-related network activity.
4. Hydra generated repeated RDP authentication attempts against `Target-PC`.
5. Windows Security Event ID `4625` recorded the failed logons.
6. Hydra eventually identified a valid password for the test account.
7. Windows Security Event ID `4624` was reviewed during successful-authentication analysis.
8. Splunk was used to correlate:
   - Source IP
   - Target host
   - Targeted account
   - Event timeline
   - Failed and successful authentication activity
9. The observed behavior was mapped to MITRE ATT&CK.
10. The affected account password was reset.
11. Account lockout controls were configured in Active Directory.
12. RDP access was restricted through Group Policy.
13. A standard Remote Desktop client was used to verify that unauthorized interactive access was denied.
14. Splunk remained active throughout containment and remediation.

---

# SOC Investigation Workflow
```
Kali Linux Reconnaissance
          ↓
Sysmon and Windows Telemetry
          ↓
Splunk Enterprise Ingestion
          ↓
Repeated Event ID 4625 Failures
          ↓
Successful Authentication Review
          ↓
Source IP, Host, Account, and Timeline Correlation
          ↓
MITRE ATT&CK Mapping
          ↓
Identity Containment
          ↓
RDP Restriction Through Group Policy
          ↓
Account Lockout Hardening
          ↓
Credential Reset
          ↓
Manual RDP Validation
          ↓
Incident Response Documentation


```
# Data Sources
The following telemetry sources were used during the project:

- Windows Security event logs
- Windows System event logs
- Sysmon Operational logs
- Splunk Universal Forwarder
- Active Directory authentication events
- Group Policy results
- Kali Linux command-line output
- Hydra authentication testing
- Splunk dashboards and searches
- Remote Desktop client validation
- Active Directory Users and Computers
- Group Policy Management Console

  ---

 # Splunk Dashboard Capabilities

## The centralized SOC dashboard includes:

- Time-range filtering
- Host filtering
- Event-type filtering
- Security event timeline
- Reconnaissance activity timeline
- Failed logons over time
- Top failed-login usernames
- Failed logons by host
- Top source IPs
- Top destination ports
- Failure-reason analysis
- Recent high-value events
- Successful login after failed attempts
- MITRE ATT&CK validation
- Reporting-host visibility
- Raw event review for analyst validation

---

# Detection Logic
## Failed Logon Detection

index=* EventCode=4625
| eval User=coalesce(Account_Name, TargetUserName, user)
| eval Source_IP=coalesce(Source_Network_Address, SourceIp, src_ip)
| table _time host ComputerName User Source_IP Failure_Reason
| sort - _time

This search identifies failed Windows authentication attempts and displays the affected account, source address, endpoint, failure reason, and event time.

--- 

# Failed Logons Over Time

index=* EventCode=4625
| timechart span=5m count as Failed_Logins

This panel highlights spikes in authentication failures during the brute-force simulation.

---

# Top Targeted Accounts

index=* EventCode=4625
| eval User=coalesce(Account_Name, TargetUserName, user)
| stats count by User
| sort - count

This panel identifies the accounts receiving the highest number of failed logon attempts.

---

# Failed Logons by Host

index=* EventCode=4625
| stats count by ComputerName
| sort - count

This panel identifies the systems receiving the most authentication failures

---

# Reconnaissance Activity

index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| eval Source_IP=coalesce(SourceIp, src_ip)
| eval Destination_IP=coalesce(DestinationIp, dest_ip)
| eval Destination_Port=coalesce(DestinationPort, dest_port)
| stats count by Source_IP Destination_IP Destination_Port host
| sort - count

This search analyzes Sysmon network-connection telemetry and identifies source addresses, destination addresses, ports, and event volume.

---

# Top Source IPs

index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| stats count by SourceIp
| sort - count

The Kali Linux system at 10.30.30.6 appeared as the main source of the simulated suspicious network activity

---

# Top Destination Ports

index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| stats count by DestinationPort
| sort - count

This panel identifies the destination services receiving the most connection attempts.

---

# Successful Authentication Review

index=* (EventCode=4624 OR EventCode=4625)
| eval User=coalesce(Account_Name, TargetUserName, user)
| eval Source_IP=coalesce(Source_Network_Address, SourceIp, src_ip)
| stats
    count(eval(EventCode=4625)) as Failed_Logons
    count(eval(EventCode=4624)) as Successful_Logons
    values(EventCode) as EventCodes
    earliest(_time) as First_Seen
    latest(_time) as Last_Seen
    by User ComputerName Source_IP
| where Failed_Logons > 0 AND Successful_Logons > 0
| eval Verdict="Requires Analyst Validation"
| convert ctime(First_Seen) ctime(Last_Seen)
| sort - Failed_Logons

This search identifies accounts that generated both failed and successful authentication events

The search does not automatically prove compromise. The analyst must validate:

- Logon type
- Source address
- Account name
- Target endpoint
- Time relationship
- Whether an interactive session was established
- Whether the activity was authorize

---

# Authentication vs. Authorization Finding

A major technical finding from this project was the difference between authentication and authorization.

Hydra reported that the password was valid. However, after the Remote Desktop Group Policy restriction was applied, Hydra also displayed a message indicating that the account was not active or authorized for Remote Desktop.

This demonstrated two separate stages:

1.  Authentication
- Windows evaluated whether the username and password were correct.
- Hydra was able to identify a valid credential.
2.  Authorization
- Windows evaluated whether the account had permission to start an interactive RDP session.
- Group Policy denied the session.

A standard Remote Desktop client confirmed the final result:

The connection was denied because the user account is not authorized for remote login.

Therefore, Hydra reporting a valid password was not treated as proof that a usable Windows desktop session had been established

---

# MITRE ATT&CK Mapping

 | Technique | Name                      | Evidence                                                  |
| --------- | ------------------------- | --------------------------------------------------------- |
| `T1046`   | Network Service Discovery | Reconnaissance and network-connection telemetry           |
| `T1110`   | Brute Force               | Repeated Windows Event ID `4625`                          |
| `T1078`   | Valid Accounts            | Valid credentials identified and Event ID `4624` reviewed |

---

# MITRE ATT&CK Validation SPL

| makeresults
| eval Technique="T1046", Name="Network Service Discovery", Status="Validated", Telemetry="Sysmon Event ID 3"
| append [
    | makeresults
    | eval Technique="T1110", Name="Brute Force", Status="Validated", Telemetry="Windows Event ID 4625"
]
| append [
    | makeresults
    | eval Technique="T1078", Name="Valid Accounts", Status="Validated", Telemetry="Windows Event ID 4624"
]
| table Technique Name Status Telemetry

---

# Triage Process

## The investigation focused on the following questions:

- What activity triggered the investigation?
- Which endpoint was targeted?
- Which account received repeated authentication attempts?
- Which system generated the attack activity?
- How many failed attempts occurred?
- Did a successful authentication event occur afterward?
- Was the same source IP associated with the failures and success?
- Was the activity authorized?
- Was an interactive RDP desktop actually established?
- Which MITRE ATT&CK techniques matched the behavior?
- What immediate containment actions were required?

---

# Investigation Findings

| Field                            | Finding                  |
| -------------------------------- | ------------------------ |
| Source IP                        | `10.30.30.6`             |
| Source system                    | Kali Linux               |
| Target host                      | `Target-PC`              |
| Target IP                        | `10.20.20.15`            |
| Target account                   | `rsmith`                 |
| Attack method                    | RDP brute force          |
| RDP port                         | TCP `3389`               |
| Failed authentication telemetry  | Event ID `4625`          |
| Successful-authentication review | Event ID `4624`          |
| Reconnaissance telemetry         | Sysmon network events    |
| Final interactive RDP result     | Denied after remediation |
| Incident status                  | Contained and validated  |

---

Containment Actions
Credential Containment

The affected account password was reset through Active Directory Users and Computers.

This action invalidated the credential discovered during the attack simulation.

Identity Restriction

The affected test account was restricted from remote logon access.

The following policy location was used:

Computer Configuration
└── Policies
    └── Windows Settings
        └── Security Settings
            └── Local Policies
                └── User Rights Assignment


---

# Allow Log On Through Remote Desktop Services

The policy was restricted to:
- Administrators
  
---

# Deny Log On Through Remote Desktop Services

### The affected test account was added:

MYVRHOMELAB\rsmith

---

# Group Policy Deployment

### The policy was forced onto the endpoint using:

gpupdate /force

The applied policy was verified using:

gpresult /r /scope computer

The results confirmed that the Remote Desktop policy was applied to Target-PC.

---

# Remediation and Hardening
### Account Lockout Policy

The following Active Directory account lockout policy was configured:

| Setting                       | Value                    |
| ----------------------------- | ------------------------ |
| Account lockout threshold     | 5 invalid logon attempts |
| Account lockout duration      | 15 minutes               |
| Reset account lockout counter | 15 minutes               |

This reduced the number of password guesses an attacker could make against a domain account.

# Password Reset

The password for the affected account was reset in Active Directory.

The reset invalidated the password discovered during the Hydra simulation.

# RDP Hardening

The following RDP controls were implemented:

- Restricted Remote Desktop logon rights
- Limited allowed RDP access to administrators
- Explicitly denied the affected user remote logon rights
- Applied the policy to the target workstation
- Verified policy application using gpresult
- Confirmed that manual Remote Desktop access was denied
- Prepared firewall-based containment for TCP port 3389

---

Windows Defender Firewall Rule

An inbound firewall rule was prepared with the following settings:
Protocol: TCP
Local Port: 3389
Action: Block

---

This provides a network-level control when Remote Desktop is not required.

# MikroTik Network Containment

The following MikroTik rule can be used to block the Kali system from reaching RDP on Target-PC:

/ip firewall filter
add chain=forward \
    src-address=10.30.30.6 \
    dst-address=10.20.20.15 \
    protocol=tcp \
    dst-port=3389 \
    action=drop \
    comment="Containment - Block Kali RDP to Target-PC"
The rule should be placed above any broader rule that permits the same traffic.

---

# Validation Results

| Validation Test                              | Result |
| -------------------------------------------- | ------ |
| Windows Security logs ingested into Splunk   | Passed |
| Sysmon telemetry ingested into Splunk        | Passed |
| Reconnaissance visible in Splunk             | Passed |
| Failed RDP logons visible as Event ID `4625` | Passed |
| Source IP identified                         | Passed |
| Target account identified                    | Passed |
| Target endpoint identified                   | Passed |
| MITRE ATT&CK mapping completed               | Passed |
| Password reset completed                     | Passed |
| Account lockout policy configured            | Passed |
| RDP restriction GPO applied                  | Passed |
| Unauthorized interactive RDP login denied    | Passed |
| Splunk monitoring remained active            | Passed |
| Incident response documentation completed    | Passed |


---

# Incident Response Summary
### Incident Type

Active Directory RDP brute-force simulation

### Severity

High

### Affected Asset

Target-PC.myvrhomelab.local

### Affected Account

MYVRHOMELAB\rsmith

### Source

Kali Linux at 10.30.30.6

### Initial Access Method

RDP authentication attempts over TCP 3389

# Detection Sources
- Splunk Enterprise
- Windows Security logs
- Sysmon
- Splunk Universal Forwarder
- Hydra test output
# Containment
- Reset affected account password
- Restricted RDP logon rights
- Denied the affected account remote logon authorization
- Applied Group Policy to the endpoint
- Prepared Windows Firewall RDP blocking
- Continued Splunk monitoring
# Remediation
- Configured account lockout policy
- Restricted RDP access
- Verified Group Policy application
- Validated unauthorized RDP access denial
- Documented the incident

# Recovery Status

Contained and validated.

No unauthorized interactive RDP access was possible after the remediation controls were applied.

---
