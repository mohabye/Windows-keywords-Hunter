# Advanced Windows Forensic Malware Hunter

A comprehensive web-based tool for detecting indicators of compromise (IOCs) in Windows event logs, command history, and forensic artifacts. This tool scans for malware families and exploitation frameworks such as PowerSploit, Cobalt Strike, Metasploit, Empire, Mimikatz, and more. It supports dynamic category-based keyword filtering, CSV/EVTX/XML log parsing, and real-time statistics.

## **Overview**

This is a standalone HTML/JavaScript application designed for threat hunting and forensic analysis on Windows systems. It provides an intuitive interface with multiple tabs for configuration, keyword management, artifact guidance, results export, and detailed documentation.

Key capabilities:

- Scan logs for over 1000+ threat keywords across 15+ categories.
- Support for CSV, EVTX, XML, TXT, and LOG file formats.
- Real-time dashboard with events scanned, threats detected, risk score, and severity levels.
- Custom keyword addition and management.
- Export detections to CSV, JSON, or plain text reports.

## **Features**

### **Threat Hunter Module**

- Upload and parse log files (CSV/EVTX/XML/TXT/LOG).
- Select hunt types (e.g., All Threats, PowerSploit, Cobalt Strike).
- Choose detection strategies (Keyword Matching, Pattern Recognition, Behavioral Analysis).
- Set search depth (Light, Standard, Deep).
- Display detected threats with severity (Critical, High, Medium, Low), category, line number, timestamp, and content snippets.

### **Keyword Manager**

- Add, view, and remove custom keywords/IOCs.
- Categorize keywords (e.g., Persistence, Lateral Movement).
- View statistics: Total keywords and category breakdown.

### **Artifact Analysis**

- Guidance on common Windows forensic artifacts (e.g., Security.evtx, Sysmon logs, PowerShell history, Prefetch, AmCache).
- Reference table for key Event IDs (e.g., 4688 for Process Creation).

### **Results & Export**

- Summary of detections by severity.
- Export options: CSV, JSON, or generate a detailed report.

### **Documentation**

- Built-in reference for threat categories, keywords, Event IDs, usage guide, and best practices.

## **New Features**

- **Dynamic Category Filtering**: Focus scans on specific threat types to reduce false positives.
- **CSV Parser**: Proper field extraction for comma-separated logs.
- **EVTX/XML Support**: Parse Windows Event Viewer exports.
- **1000+ Threat Keywords**: Comprehensive database across categories.
- **Real-time Statistics**: Live updates on scan progress and risk assessment.

## **Threat Categories and Keywords**

The tool includes a built-in database of keywords organized by categories. Examples include:

### **PowerSploit (25+ keywords)**

- Invoke-Mimikatz - In-memory credential dumping.
- Invoke-DllInjection - DLL injection attacks.
- PowerView - Active Directory enumeration.
- PowerUp - Privilege escalation toolkit.

### **Cobalt Strike (22+ keywords)**

- beacon - Beacon payloads.
- execute-assembly - In-memory assembly execution.
- psexec - Lateral movement via PsExec.

### **Metasploit (13+ keywords)**

- meterpreter - Meterpreter sessions.
- hashdump - Password hash dumping.
- multi/handler - Exploit handlers.

### **Empire (7+ keywords)**

- Invoke-Empire - Empire framework commands.
- Invoke-Kerberoast - Kerberoasting attacks.

### **Mimikatz (8+ keywords)**

- sekurlsa::logonpasswords - Extract passwords from memory.
- lsadump::dcsync - Domain Controller sync.
- kerberos::golden - Golden ticket attacks.

### **LOLBAS (15+ keywords)**

- certutil -urlcache - File downloads.
- bitsadmin /transfer - Background transfers.
- regsvr32 /i: - Scriptlet execution.

### **Additional Categories**

- **Persistence**: Registry Run keys, scheduled tasks, WMI subscriptions.
- **Lateral Movement**: PSExec, WMI, WinRM.
- **Privilege Escalation**: Token manipulation, UAC bypass.
- **Credential Access**: Kerberoasting, NTDS dumping.
- **Defense Evasion**: AMSI bypass, log clearing.
- **Discovery**: Network enumeration, AD queries.
- **Execution**: PowerShell, WScript abuse.
- **Exfiltration**: Data compression, network transfers.

## **Windows Event IDs Reference**

| **Event ID** | **Source** | **Description** | **Use Case** |
| --- | --- | --- | --- |
| 4688 | Security | Process Creation | Track command-line execution |
| 4689 | Security | Process Exit | Process termination tracking |
| 4702 | Security | Scheduled Task Created | Persistence detection |
| 1 | Sysmon | Process Created | Detailed process execution |
| 3 | Sysmon | Network Connection | C2 communication detection |
| 8 | Sysmon | CreateRemoteThread | Process injection detection |
| 10 | Sysmon | Process Accessed | LSASS dumping detection |
| 22 | Sysmon | DNS Query | C2 domain detection |

## **Usage Guide**

1. **Open the Tool**: Download and open the HTML file in a modern web browser (e.g., Chrome, Firefox). No installation required.
2. **Upload Log File**: In the "Threat Hunter" tab, select a log file (e.g., Security.evtx exported from Event Viewer).
3. **Configure Hunt**:
    - Choose Hunt Type (e.g., All Threats or specific category).
    - Select Detection Strategy and Search Depth.
4. **Start Hunt**: Click "▶ Start Threat Hunt" to scan the file.
5. **Review Results**: View detected threats in the "Detected Threats" section with details and severity.
6. **Manage Keywords**: In the "Keyword Manager" tab, add/remove keywords.
7. **Export Data**: In the "Results & Export" tab, download CSV/JSON or generate a report.
8. **Reset**: Click "Reset" to clear the current scan.

### **Exporting Logs from Windows**

- Security.evtx: wevtutil epl Security C:\Security.evtx
- Sysmon: wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Sysmon.evtx

## **Best Practices**

- Enable PowerShell script block logging (Event ID 4104).
- Enable command-line logging in Event ID 4688.
- Deploy Sysmon for enhanced visibility.
- Use category-specific hunts for focused investigations.
- Regularly update keywords with new IOCs.
- Run in an isolated environment for large log files.

## **Legal Notice**

This tool is intended for authorized security testing, incident response, and forensic analysis only. Ensure you have proper authorization before analyzing any systems or data. The authors assume no liability for misuse.

Contributions are welcome! Fork the repository, make changes, and submit a pull request. Focus on adding new keywords, improving parsers, or enhancing UI/UX.

##
