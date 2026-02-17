# SOC-Incident-Response-Case-Study (False Positive)
Suspicious Encoded PowerShell — False Positive Investigation





# Overview

This project simulates a real-world SOC investigation involving suspicious encoded PowerShell execution detected by Wazuh.

Rather than assuming compromise, the objective was to:

i] Triage the alert

ii] Pivot across telemetry sources

iii] Analyze PowerShell logging

iv] Validate process activity

v] Assess impact

vi] Determine whether escalation was warranted

#### The investigation concluded as a false positive, demonstrating structured alert validation and detection tuning methodology.



# Lab Environment

i] Windows 11 (Endpoint) with Wazuh agent installed

ii] Wazuh 4.14 (SIEM)

iii] Sysmon (Olaf configuration)

iv] PowerShell Logging enabled and integrated into Wazuh Agent

v] Windows Server 2025 (Domain Controller)

# Alert Intake

### Alert Name: Suspicious Encoded PowerShell Execution
### Source: Wazuh (PowerShell Logging)
Relevant Event IDS Observed:

i] 4103 - Powershell Module Logging

ii] 11 - Sysmon FileCreate

iii] 1 - Sysmon ProcessCreate (local only; filtered in Wazuh depending on config)
### Host: Win11.ad.wasteman.xyz
### User: kaguero
### Severity: High

Detection triggered due to detection of ```-EncodedCommand``` usage in PowerShell.


# Encoded powershell Command on Windows 11 Endpoint:

![49 trigger alert](https://github.com/user-attachments/assets/ca993cb2-b337-4194-8968-201ab47c9204)


Initial risk assessment: Possible malware execution or obfuscation attempt.

# Investigation & Triage
## Step 1: Review PowerShell Telemetry (Event ID 4103)

PowerShell Module Logging (4103) captured command invocation metadata.


![52 powershell logging detcted in wazuh](https://github.com/user-attachments/assets/017e9617-982f-4856-b11a-5f0912ed5502)

Relevant fields reviewed:
```
data.win.eventdata.payload: CommandInvocation(Start-Process): \"Start-Process\"  ParameterBinding(Start-Process): name=\"FilePath\"; value=\"notepad.exe\"


data.win.eventdata.contextinfo: Severity = Informational  Host Name = ConsoleHost  Host Version = 5.1.26100.7705  Host ID = 926064ae-6a4a-4518-8fd3-3279a16dbb01   Host Application = C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAG4AbwB0AGUAcABhAGQALgBlAHgAZQA=    Engine Version = 5.1.26100.7705    Runspace ID = 8ff09a0c-0368-4afb-ae2c-fb5009505bcb    Pipeline ID = 1     Command Name = Start-Process   Command Type = Cmdlet   Script Name =      Command Path =      Sequence Number = 16      User = AD\\kaguero       Connected User =    Shell ID = Microsoft.PowerShell

data.win.eventdata.image: C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
```
The payload was extracted and decoded using CyberChef.


![50 decoded encoded powershell command via cyberchef](https://github.com/user-attachments/assets/9ecbdb7d-7dd7-4b3f-a102-611d9a7a6d17)

Decoded content:
```
Start-Process notepad.exe
```

No obfuscation beyond Base64 encoding.
No dynamic download behavior.
No execution of remote content.



## Step 2: Process Creation Review (Event ID 1)

![![55 process creation eventid 1](https://github.com/user-attachments/assets/9a8746c1-cccd-480a-b5ff-4c6138c494a3)

Filtered for:
```
data.win.system.eventID : "1"
AND data.win.eventdata.image : "*powershell.exe"
```

Findings:

i] Event ID 1 was present locally in Event Viewer.

ii] Depending on Sysmon filtering (Olaf config), not all PowerShell executions were forwarded to Wazuh.

iii] No additional spawned processes.

iv] No suspicious command-line arguments beyond encoding.

v] No suspicious parent process observed.

### Note:
Sysmon configuration significantly impacts visibility. Logging strategy may intentionally suppress benign process creation events to reduce noise.

![51 confirmed ps command in event viewer on endpoint](https://github.com/user-attachments/assets/5df2abc1-728a-4adb-bca6-134d1b767d78)







## Step 3: File Activity Review (Sysmon Event ID 11)

![56a event id 11](https://github.com/user-attachments/assets/33c0cbc4-1371-4097-961d-ada0c9f705fa)


![56b event id 11](https://github.com/user-attachments/assets/87ad4fe2-6758-44c4-9eb3-3a46e3fa0c00)

Findings:

i] No suspicious payloads written to disk.

ii] No executable drop.

iii] No modification of startup locations.




## Step 4: Check for Network Activity

![54 no network connections](https://github.com/user-attachments/assets/856e57ad-4cb0-4cc4-8440-cd1b6834a1b6)

Filtered for:
```
data.win.system.eventID : "3"
```

Findings:

i] No outbound connections tied to the PowerShell execution

ii] No C2-like traffic patterns.

iii] No DNS anomalies




## Step 5: Check for Persistence & Escalation

Investigated for:
![53 no persistence](https://github.com/user-attachments/assets/080739b7-a752-4dda-9416-08bb2ae8abf7)

i] Scheduled task creation

ii] Registry run keys

iii] Startup folder modifications

Findings:

i] No Event ID 4698 (Scheduled Task)

ii] No persistence artifacts

iii] No privilege escalation activity






# Timeline Reconstruction

i] 18:54:48.184 – Encoded PowerShell execution detected.

ii] 18:54:49.141 – PowerShell Module Logging (4103) recorded invocation.

iii] 18:55:45.528 - No further suspicious telemetry.

No subsequent malicious activity observed

No lateral movement, no credential abuse, no persistence.

# Impact Assessment

i] No elevated privileges obtained

ii] No admin group modification

iii] No network propagation

iv] No file encryption or destructive behavior

v] No persistence

vi] No compromise indicators found

Scope: Isolated single command execution.





# Final Classification

### Classification: False Positive
#### Root Cause: Legitimate encoded PowerShell used for benign process launch
#### Escalation Required: No
#### Containment Required: No







# Detection Improvement Recommendations

Rather than alerting on all encoded PowerShell executions, escalate only if encoded PowerShell is accompanied by:

i] Network connection (Sysmon Event ID 3)

ii] File drop in suspicious directory

iii] Scheduled task creation

iv] Privilege escalation

v] Suspicious parent process (e.g., Word, Excel)

This reduces alert fatigue and improves signal to noise ratio..






# Lessons Learned

1. 4103 vs 4104 Visibility Difference

    4103 (Module Logging) logs invocation details.

    4104 (Script Block Logging) provides deeper script content visibility.

    Logging configuration affects investigation depth.

2. Sysmon Filtering Impacts SIEM Visibility

    Event ID 1 may exist locally but not be forwarded depending on include rules.

    Detection depends on logging design, not just event generation.

3. Encoded PowerShell ≠ Malicious

    Context determines risk.

    Follow-on behavior is more important than encoding alone.

4. Correlation > Single Event Alerts

    High-confidence detections require multi-event analysis.

5. False Positives Are Valuable

    Proper triage prevents unnecessary escalation.

    Detection tuning improves SOC efficiency.


# What This Project Demonstrates

i] Practical SOC alert triage

ii] PowerShell telemetry analysis

iii] Log pivoting across data sources

iv] Understanding of logging configuration limitations

v] Mature false-positive handling

vi] Context-based risk assessment

vii] Detection improvement mindset




# MITRE ATT&CK Context

Although benign in this case, encoded PowerShell commonly maps to:

i] T1059.001 – PowerShell

ii] T1027 – Obfuscated Files or Information

Investigation confirmed no adversarial behavior.
