# BlueTeam-Monitor + Wazuh SIEM Integration

## Overview

This project simulates a basic Blue Team monitoring workflow using PowerShell and Wazuh SIEM.

The monitor generates security-related events on a Windows endpoint, which are collected by the Wazuh agent and forwarded to a centralized Wazuh Manager running on Ubuntu.

Custom Wazuh rules detect suspicious activity such as multiple failed login attempts and generate alerts for SOC analysis.

---

## Technologies Used

* PowerShell
* Wazuh SIEM
* Windows 11
* Ubuntu Server
* VMware
* Syslog-style event parsing
* Custom Wazuh detection rules

---

## Lab Architecture

Windows Endpoint (PowerShell Monitor)
↓
events.log
↓
Wazuh Agent
↓
Wazuh Manager (Ubuntu)
↓
Custom Rules
↓
SOC Alerts

---

## Features

* Custom PowerShell security event generation
* Wazuh agent integration
* Real-time log forwarding
* Custom detection engineering
* Failed login detection alerts
* SIEM event monitoring

---

## Example Detection

Example generated event:

May 26 23:02:00 BlueTeamMonitor: Se detectaron 20 intentos fallidos

Generated Wazuh alert:

Rule: 100101 (level 12)
BlueTeam-Monitor: Multiple failed login attempts detected

---

## Custom Wazuh Rule

```xml
<rule id="100101" level="12">
  <match>Se detectaron</match>
  <description>BlueTeam-Monitor: Multiple failed login attempts detected</description>
  <group>authentication_failed,blue_team,custom_monitor</group>
</rule>
```

---

## Skills Demonstrated

* SIEM integration
* Security monitoring
* Log analysis
* Detection engineering
* PowerShell scripting
* Linux administration
* Blue Team workflows
* Troubleshooting and debugging

---

## Future Improvements

* Brute force threshold detection
* MITRE ATT&CK mapping
* Active response automation
* Email/Slack alerting
* Dashboard visualizations


Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\\monitor.ps1

```

