



---

# 🚨 Incident Response: Brute Force Attempt Detection

![image](https://github.com/user-attachments/assets/078932c1-3e7e-48cf-a0c1-1cd787336ce6)

Scenario Context:
You are a security analyst for a large financial services organization that relies heavily on Microsoft Azure services. Recently, the IT helpdesk received complaints from several employees that their accounts were temporarily locked out due to multiple failed login attempts. These incidents seem to be occurring during off-hours and have affected several employees, particularly those with privileged access.
The IT team suspects this could be an attempt to compromise privileged accounts through a brute-force attack or a credential stuffing campaign. To investigate, the security team has been tasked with identifying whether these failed login attempts represent malicious activity targeting specific accounts or if they are simply due to users forgetting their credentials.
To formulate the Incident Response (IR) process for the Suspicious Account with Excessive Failed Login Attempts scenario in accordance with NIST 800-61 guidelines, we will follow the phases outlined in the NIST Incident Response Life Cycle: Preparation, Detection & Analysis, Containment, Eradication & Recovery, and Post-Incident Activity​(nist.sp.800-61r2).


## 🔍 **Objective**
Create a **Sentinel Scheduled Query Rule** in Log Analytics to detect when the same remote IP address fails to log in to the same local host (Azure VM) 10 times or more within the last 5 hours.

---

## Platforms and Languages Leveraged
- Microsoft Sentinel
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Windows 10 Virtual Machines (Microsoft Azure)
---
1. Preparation
Incident Response Policies and Procedures:
Establish security policies that address handling failed login attempts, lockouts, and brute-force attacks. The policies should cover procedures for reporting suspicious behavior, account lockdowns, and account recovery.
Predefined Actions for account lockout, notifications, and monitoring should be in place, particularly for privileged accounts.
Training: Ensure the security team is trained in handling credential-based attacks such as brute-force attempts and credential stuffing.
Access Control and Logging:
Enable logging of all login attempts across Azure AD and other key services, focusing on failed login attempts.
Ensure integration with tools like Microsoft Defender for Identity and Azure Sentinel to automatically detect and alert on suspicious login behaviors.
Communication Plans:
Maintain an escalation plan for IT support and privileged account holders, ensuring rapid communication during suspected brute-force attacks.
---

### High-Level Discovery Plan

- **Check `DeviceLogonEvents`** for any query to check if any of these IP addresses successfully logged in
- **Check `DeviceFileEvents`** for any file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections.
---
## 🛠️ **Analysis**
### Observations:


Detection and Analysis
Detection of Incident:
Multiple failed login attempts trigger an alert, likely detected via Azure Active Directory sign-in logs and alerts configured for monitoring failed login thresholds.
Analyze Failed Login Patterns: Use the provided KQL query to identify user accounts with excessive failed login attempts and analyze patterns:
kql

Three different virtual machines were potentially impacted by brute force attempts from two distinct public IP addresses:  

![Screenshot 2025-01-06 181511](https://github.com/user-attachments/assets/3134d542-b44d-4036-b2ce-1827bc7dda88)


| **Remote IP Address**  | **Failed Attempts** | **Target Machine**    |
|-------------------------|---------------------|-----------------------|
| `194.180.48.18`         | 21                  | `windows-target-1`    |
| `194.180.48.11`         | 20                  | `windows-target-1`    |
| `113.56.218.168`        | 40                  | `windowsvm-mde-c`     |

![Screenshot 2025-01-06 171817](https://github.com/user-attachments/assets/7778763e-ebac-47a5-b9c2-2ef87e66c509)

This query retrieves data on failed login attempts across users, identifying accounts where the number of failed attempts exceeds a defined threshold (e.g., 3 attempts).
Incident Documentation:
Document the failed login attempts, focusing on patterns such as the number of failed attempts, the origin IP addresses, and times of occurrence. Retain all logs and findings for further review.
Prioritization:
High Priority: If multiple failed attempts target privileged accounts or come from various locations/IP addresses, indicating a possible brute-force attack.
Lower Priority: Isolated failed attempts might suggest user error, particularly if no suspicious patterns or malicious IPs are involved.

### Additional Verification:
I ran the following query to check if any of these IP addresses successfully logged in:  

```kql
DeviceLogonEvents
| where RemoteIP in ("194.180.48.18", "113.56.218.168")
| where ActionType != "LogonFailed"
```

![Screenshot 2025-01-06 194510](https://github.com/user-attachments/assets/bb7e5332-447c-4328-82a3-a34f5aadcd23)

**Result**: No successful logins were detected from these IP addresses. ✅

---

![Screenshot 2025-01-06 190209](https://github.com/user-attachments/assets/2bd0cec0-9b56-4042-a9cf-d751ddd3d0d1)


## 🛡️ **Containment Actions**
1. 🔒 **Device Isolation**:  
   - Isolated both affected devices using **Microsoft Defender for Endpoint (MDE)** 

2. 🛡️ **Anti-Malware Scans**:  
   - Performed anti-malware scans on both devices.  

3. 🔐 **Network Security Group (NSG) Update**:  
   - Locked down RDP access to prevent further brute force attempts from the public internet.  
   - Allowed RDP access **only** from my home IP address.
  
     Containment, Eradication, and Recovery
Containment:
Immediate Lockdown: Lock the affected accounts temporarily if the failed login attempts exceed the threshold and come from suspicious IPs or times (e.g., during off-hours).
Geo-blocking: Implement conditional access policies to block login attempts from regions or IPs where the attacks are suspected to originate.
MFA Enforcement: For privileged accounts, enable or enforce multi-factor authentication (MFA) to prevent unauthorized access.

Eradication:
Investigate if any of the accounts have been compromised. If so, reset passwords for the affected accounts.
If the attack involves specific locations or IP addresses, consider blacklisting these to prevent future login attempts.

Recovery:
Password Reset Campaign: Force password resets on all accounts that were targets of the attacks.
Monitor for Further Attacks: Set up monitoring rules in Azure Sentinel or another SIEM to detect any recurring failed login attempts.

![Screenshot 2025-01-06 193306](https://github.com/user-attachments/assets/8e45d194-40df-4058-8f2d-ee56a1cfc10b)
---

## 🚫 **Outcome**
- **Brute force attempts were not successful.** No threats related to this incident were detected.  
- **Proposed Policy Update**: Require NSG lockdown for all VMs, limiting RDP access to authorized IPs only.

  Post-Incident Activity
Lessons Learned:
Conduct a lessons learned session with the security team, IT staff, and affected users. This will help evaluate the incident response and identify areas for improvement.
Questions to consider:
Was the detection mechanism sufficient to identify the issue quickly?
Were privileged accounts sufficiently protected by security controls such as MFA and conditional access policies?
System Improvements:
Review Security Controls: If gaps were identified (e.g., failed login attempts not leading to automatic lockdowns), adjust security controls. Improve detection rules and thresholds for failed logins.
User Awareness: Educate employees on safe password practices, avoiding password reuse, and how to handle potential phishing attempts.
Documentation:
Document the findings, actions taken, and recommendations for future incidents. This report should include the incident timeline, analysis results, and response actions.

   

In this scenario, following NIST 800-61 guidelines ensures a structured approach to detecting and responding to suspicious account activity. By systematically detecting failed login attempts and responding appropriately, your organization can reduce the risk of unauthorized access, especially to privileged accounts, which are common targets for brute-force and credential stuffing attacks​(nist.sp.800-61r2)​(nist.sp.800-61r2).

---

🎉 **Status**: Incident resolved, no further action required. 

--- 

