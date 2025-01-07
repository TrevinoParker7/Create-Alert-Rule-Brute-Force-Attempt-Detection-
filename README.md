



---

# 🚨 Incident Response: Brute Force Attempt Detection

## 🔍 **Objective**
Create a **Sentinel Scheduled Query Rule** in Log Analytics to detect when the same remote IP address fails to log in to the same local host (Azure VM) 10 times or more within the last 5 hours.

---

## Platforms and Languages Leveraged
- Microsoft Sentinel
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Windows 10 Virtual Machines (Microsoft Azure)
---
### High-Level Discovery Plan

- **Check `DeviceLogonEvents`** for any query to check if any of these IP addresses successfully logged in
- **Check `DeviceFileEvents`** for any file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections.
---
## 🛠️ **Analysis**
### Observations:
Three different virtual machines were potentially impacted by brute force attempts from two distinct public IP addresses:  

![Screenshot 2025-01-06 181511](https://github.com/user-attachments/assets/3134d542-b44d-4036-b2ce-1827bc7dda88)


| **Remote IP Address**  | **Failed Attempts** | **Target Machine**    |
|-------------------------|---------------------|-----------------------|
| `194.180.48.18`         | 21                  | `windows-target-1`    |
| `194.180.48.11`         | 20                  | `windows-target-1`    |
| `113.56.218.168`        | 40                  | `windowsvm-mde-c`     |

![Screenshot 2025-01-06 171817](https://github.com/user-attachments/assets/7778763e-ebac-47a5-b9c2-2ef87e66c509)


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
   - Isolated both affected devices using **Microsoft Defender for Endpoint (MDE)**.  

2. 🛡️ **Anti-Malware Scans**:  
   - Performed anti-malware scans on both devices.  

3. 🔐 **Network Security Group (NSG) Update**:  
   - Locked down RDP access to prevent further brute force attempts from the public internet.  
   - Allowed RDP access **only** from my home IP address.  

---

## 🚫 **Outcome**
- **Brute force attempts were not successful.** No threats related to this incident were detected.  
- **Proposed Policy Update**: Require NSG lockdown for all VMs, limiting RDP access to authorized IPs only.

   ![Screenshot 2025-01-06 193306](https://github.com/user-attachments/assets/8e45d194-40df-4058-8f2d-ee56a1cfc10b)


---

🎉 **Status**: Incident resolved, no further action required. 

--- 

