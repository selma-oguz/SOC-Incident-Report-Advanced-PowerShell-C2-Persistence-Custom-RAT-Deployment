<img width="1870" height="927" alt="incident graph" src="https://github.com/user-attachments/assets/a8885dd6-e091-442c-bcc1-e961a1806ede" />

<img width="1867" height="912" alt="Process Tree" src="https://github.com/user-attachments/assets/a95c6bfc-6e12-4d7d-825d-616d18e28bc8" />




# SOC Incident Report: Advanced PowerShell C2, Persistence & Custom RAT Deployment

**Ticket ID:** INC-EDR-004 (Alert ID: da7f0df489-6cfd-493f-a8ae-d38d911857ab_1)
**Date:** September 21, 2026
**Analyst:** Selma Oguz
**Environment:** Microsoft Defender for Endpoint (XDR)

## SECTION 1: Executive Summary & Incident Scope
---

On April 20, 2026, Microsoft Defender triggered high-severity alerts on endpoint `mde-moon`, indicating a "Hands-on keyboard attack" and suspicious PowerShell execution. Analysis confirmed that an attacker established a remote connection to the device and executed a highly obfuscated PowerShell dropper via `cmd.exe`. 

The dropper bypassed standard web protocols by opening a raw TCP socket to a C2 server (`172.29.41.73`), downloaded a malicious payload (`secret.ps1`), and masqueraded it as a Windows Update file (`KB5068308.ps1`). The attacker successfully established persistence via Windows Scheduled Tasks before executing the payload. Code analysis of the payload revealed a custom-built Remote Access Trojan (RAT) equipped with automated reconnaissance, privilege escalation checks, timestomping capabilities, and anti-forensics (log clearing) mechanisms. 

The machine was rapidly isolated from the network, and comprehensive enterprise sweeps confirmed no lateral movement to other devices. 

* **Declaration:** True Positive – Issue (Compromised Endpoint)
* **Affected Endpoint:** `mde-moon`
* **Host IP:** Private: `172.27.116.170` | Public: `37.154.107.135`
* **Operating System:** Windows 10 64-bit (Release 22H2 Build 19045.6456)
* **Compromised User:** `Ahmet` (Workgroup)

## SECTION 2: Kill Chain & Execution Timeline
---

* **Initial Access & Execution:** The attacker connected remotely and spawned `cmd.exe`, followed by the execution of a Base64-encoded PowerShell command using evasion flags (`-NoP -ep Bypass -W Hidden -enc`).
* **Command & Control (C2):** The decoded PowerShell script utilized `Net.Sockets.TcpClient` to bypass standard HTTP monitoring, sending a raw GET request to `http://172.29.41.73/secret.ps1`.
* **Masquerading & Persistence (T1036 & T1053):** The downloaded script was saved to `C:\Users\Ahmet\Desktop\KB5068308.ps1` to mimic a legitimate Windows Knowledge Base (KB) update. Immediately after, a Scheduled Task named `KB4584641` was created to run the script whenever the system is idle for 5 minutes (`/sc onidle /i 5`).
* **Post-Exploitation:** The attacker manually executed the script, initiating the custom RAT's automated reconnaissance protocols.

## SECTION 3: Artifact & Code Analysis
---

### Artifact 1: The Initial Dropper (Base64)
* **Process ID:** `7640`
* **Command:** `powershell.exe -NoP -ep Bypass -W Hidden -enc [Base64_String]`
* **Deobfuscated Action:** Opens a raw TCP stream to `172.29.41.73`, downloads the payload, drops it as `KB5068308.ps1`, creates a scheduled task, and executes the payload.

### Artifact 2: The Custom RAT (Secondary Payload)
* **Name:** `KB5068308.ps1` (Original: `secret.ps1`)
* **Path:** `C:\Users\Ahmet\Desktop\KB5068308.ps1`
* **SHA1:** `1684614b2c4454c2746727a2ed8302331ec9856d`
* **Network Indicator:** `172.29.41.73:4444`

**Reverse Engineering the Payload (Capabilities):**
Deep analysis of the PowerShell script content revealed a sophisticated, switch-case structured RAT with the following modules:
1. **Interactive Reverse Shell (Case 1):** Establishes a direct command execution pipeline back to the attacker.
2. **Privilege Discovery (Case 2):** Executes `whoami /priv` to verify if the compromised account has `SeDebugPrivilege` (often a precursor to LSASS credential dumping).
3. **Timestomping (Case 4 - T1070.006):** Modifies `LastWriteTime` and `CreationTime` of files to random dates, specifically designed to blind forensic timeline analysis.
4. **Automated Reconnaissance (Case 5 - T1082):** Automatically gathers OS details, active TCP connections, local user groups, running services, and Windows Defender status, exfiltrating the data via Base64 encoding.
5. **Anti-Forensics (Exit Routine - T1070.001):** Uses `Clear-EventLog` to wipe Windows PowerShell, Security, and System logs upon exit to erase operational tracks.

## SECTION 4: Incident Response Actions & Remediation
---

**Immediate Containment (Analyst Actions):**
* **Endpoint Isolation:** The device `mde-moon` was isolated via Microsoft Defender to cut off the active C2 connection (`172.29.41.73:4444`).
* **Account Disruption:** Active sessions for user `Ahmet` were revoked, and a mandatory password reset was initiated (Jira Ticket: **SOC/14**).
* **Network Blocking:** The malicious IP (`172.29.41.73`) and the payload hash were permanently blocked at the perimeter (Jira Tickets: **SOC/12** & **SOC/13**).

**Post-Incident Recommendations:**
* **Reimage Device (SOC/15):** Due to the successful establishment of persistence (Scheduled Tasks), administrative recon, and potential timestomping, the integrity of `mde-moon` is compromised. The device must be completely reimaged.
* **Evasion Detection:** Implement custom hunting queries (KQL) to detect raw `Net.Sockets.TcpClient` usage in PowerShell, as this effectively bypasses standard web proxy and download restrictions.
