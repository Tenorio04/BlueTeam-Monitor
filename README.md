\# BlueTeam-Monitor



Mini Blue Team SOC lab built with PowerShell to monitor Windows events, detect suspicious activity, generate alerts, and create automated security reports.



\## Features



\- Detect failed login attempts (Event ID 4625)

\- Detect new user creation (Event ID 4720)

\- Detect suspicious processes

\- Generate security alerts

\- Create automatic reports

\- Create log files for investigation



\## Technologies



\- PowerShell

\- Windows Event Logs

\- Blue Team Monitoring

\- Security Automation



\## Run



```powershell

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\\monitor.ps1

```

