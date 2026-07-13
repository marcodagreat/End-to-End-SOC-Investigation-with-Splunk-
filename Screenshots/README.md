# Project Screenshots

This folder contains detection, investigation, containment, remediation, and validation evidence for the project.
---

# Investigation Evidence

The following screenshots document the complete SOC workflow:

**Detection → Triage → Containment → Remediation → Validation**

---

## 1. Failed RDP Logon Events

<img width="1280" height="720" alt="Failed_logons" src="https://github.com/user-attachments/assets/8d61e12c-646a-4a23-800a-03dc52b787d7" />


**Caption:**  
Splunk identified repeated Windows Security Event ID `4625` events on `Target-PC`, confirming a high volume of failed authentication attempts against the targeted domain account.

**Why this matters:**  
This provided the primary detection evidence for the simulated RDP brute-force activity.

---

## 2. MITRE ATT&CK Validation

<img width="1280" height="720" alt="Mitre att ck_validation" src="https://github.com/user-attachments/assets/293856f3-658b-4a80-a93a-8b07c22da687" />


**Caption:**  
The observed activity was mapped to MITRE ATT&CK techniques `T1046 – Network Service Discovery`, `T1110 – Brute Force`, and `T1078 – Valid Accounts`.

**Why this matters:**  
MITRE ATT&CK mapping translated the raw event telemetry into recognizable adversary behavior.

---

## 3. Reconnaissance Events

<img width="1280" height="720" alt="Recon_events" src="https://github.com/user-attachments/assets/8afca273-983f-469d-bfd6-3495755d254c" />


**Caption:**  
Splunk displayed network-related events reviewed during the reconnaissance phase of the investigation.

**Why this matters:**  
These events were used to examine activity occurring before the authentication attack.

> **Validation note:** Confirm that this panel uses the correct Sysmon Operational sourcetype before labeling it as Sysmon Event ID `3`.

---

## 4. Reconnaissance and Failed-Logon Timeline

<img width="1280" height="720" alt="Recontimeline_failed logins over_time" src="https://github.com/user-attachments/assets/f0c52518-8b40-4a88-a0d3-1da22678ebf7" />


**Caption:**  
The Splunk timelines showed reconnaissance-related activity followed by a significant increase in failed authentication attempts.

**Why this matters:**  
The time-based correlation supported the conclusion that the activity occurred as part of a coordinated attack sequence.

---

## 5. Security Event Timeline

<img width="1280" height="720" alt="Timeframe" src="https://github.com/user-attachments/assets/682d252b-bb9f-4576-98d3-2c25f9856f5c" />


**Caption:**  
The centralized security timeline displayed spikes in Event ID `4625` and related network events during the attack window.

**Why this matters:**  
This allowed the investigation to focus on the exact timeframe associated with the simulated brute-force activity.

---

## 6. Top Source IP and Destination Port

<img width="1280" height="720" alt="top source ip and top dest port" src="https://github.com/user-attachments/assets/28da0c39-8fef-4f5a-9d15-7fc538e88e66" />


**Caption:**  
Splunk identified `10.30.30.6` as the primary source of suspicious network activity and summarized the most frequently targeted destination ports.

**Why this matters:**  
The source-IP and destination-port analysis helped identify the attacking Kali Linux system and the services being targeted.

---

# Containment Evidence

## 7. Password Reset

<img width="1280" height="720" alt="Containment_reset_password" src="https://github.com/user-attachments/assets/33e70ed0-4ceb-4ca8-a0f7-13cfd3fe2527" />


**Caption:**  
The affected account password was reset in Active Directory to invalidate the credential discovered during the simulated attack.

**Why this matters:**  
Resetting the credential was an immediate identity-containment action intended to prevent reuse of the compromised password.

> Confirm that the screenshot shows the intended affected account before publishing it.

---

# Remediation Evidence

## 8. Account Lockout Threshold

<img width="1280" height="720" alt="Remediation_account_lockout_policy" src="https://github.com/user-attachments/assets/4615a8e0-42d1-4872-be0d-938fcfbfa71c" />

**Caption:**  
The Active Directory account lockout threshold was configured to lock an account after five invalid logon attempts.

**Why this matters:**  
This control limits the number of password guesses an attacker can make before the account is temporarily locked.

---

## 9. Account Lockout Policy

<img width="1280" height="720" alt="Remediation_account lockout_threshold" src="https://github.com/user-attachments/assets/ca1f2bdd-2f44-4395-90e0-2ab98da24cbe" />


**Caption:**  
The account lockout policy was configured with a five-attempt threshold and a defined reset period.

**Why this matters:**  
The policy reduced exposure to repeated password-guessing attempts across the domain.

---

## 10. Account Lockout Duration

<img width="1280" height="720" alt="Remediation_lockout_duration" src="https://github.com/user-attachments/assets/717cb49c-885f-4f4c-ad88-95bbc97b9640" />


**Caption:**  
The account lockout duration was configured to temporarily prevent further authentication attempts after the threshold was reached.

**Why this matters:**  
The temporary lockout provided an additional barrier against automated brute-force activity.

> Your screenshots appear to show both 15-minute and 30-minute values. Use only the screenshot that matches your final deployed configuration.

---

## 11. Group Policy Update

<img width="1280" height="720" alt="Remediation_force_group_policy update" src="https://github.com/user-attachments/assets/6284e3c2-0ed2-4be6-b71e-de60d9801794" />


**Caption:**  
The updated security policy was applied successfully using `gpupdate /force`.

**Why this matters:**  
This confirmed that the target system received the latest Active Directory Group Policy configuration.

---

## 12. RDP Policy Configuration

<img width="1280" height="720" alt="Remediation_RDP_policy_config" src="https://github.com/user-attachments/assets/ea517b42-d542-44b9-834f-46ef48e66a97" />


**Caption:**  
The `Allow log on through Remote Desktop Services` policy was restricted to authorized administrators.

**Why this matters:**  
This removed standard-user authorization to establish interactive Remote Desktop sessions.

---

# Validation Evidence

## 13. RDP Access Denied

<img width="1280" height="720" alt="Remediation_RDP verification" src="https://github.com/user-attachments/assets/4ec01151-2ef9-4071-9ac0-af9a088de66d" />


**Caption:**  
A manual Remote Desktop test confirmed that the affected account was not authorized for remote login after the Group Policy remediation was applied.

**Why this matters:**  
This provided direct proof that the authorization control successfully prevented an interactive RDP session.

---

## 14. Windows Firewall RDP Rule

<img width="1280" height="720" alt="VirtualBox_ADDserver _11_07_2026_13_12_37" src="https://github.com/user-attachments/assets/e3690903-b6a4-4beb-a33b-989e02b1c412" />


**Caption:**  
A Windows Defender Firewall rule was prepared for inbound TCP port `3389` to provide an additional network-level RDP containment control.

**Why this matters:**  
The firewall rule demonstrated defense in depth by restricting access at the network layer in addition to the identity and authorization controls.
