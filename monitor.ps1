#Requires -RunAsAdministrator
param(
    [int]$WindowMinutes = 5,
    [int]$Threshold     = 5
)

$LogDir  = Join-Path $PSScriptRoot 'logs'
$LogFile = Join-Path $LogDir 'events.log'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Write-SecEvent {
    param([string]$Type, [hashtable]$Fields)
    # Syslog-style timestamp; invariant culture so the month is "May", not "mayo"
    $ts = (Get-Date).ToString('MMM dd HH:mm:ss', [cultureinfo]::InvariantCulture)
    $kv = ($Fields.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '
    "$ts $env:COMPUTERNAME BlueTeamMonitor: type=$Type $kv" |
        Out-File -Append -Encoding utf8 $LogFile
}

function Get-SecEvents {
    param([int]$Id, [datetime]$Since)
    try {
        Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=$Id; StartTime=$Since } -ErrorAction Stop
    }
    catch {
        if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') { return @() }
        throw   # any other error (permissions, missing log) is surfaced
    }
}

$since  = (Get-Date).AddMinutes(-$WindowMinutes)
$alerts = 0

# 4625: failed logons, grouped by source IP
Get-SecEvents -Id 4625 -Since $since |
    ForEach-Object { [pscustomobject]@{ User = $_.Properties[5].Value; Ip = $_.Properties[19].Value } } |
    Group-Object Ip |
    ForEach-Object {
        $sev = if ($_.Count -ge $Threshold) { 'high' } else { 'low' }
        Write-SecEvent 'failed_logon' @{ src_ip=$_.Name; count=$_.Count; window_min=$WindowMinutes; severity=$sev }
        if ($sev -eq 'high') { $alerts++ }
    }

# 4720: local account creation
Get-SecEvents -Id 4720 -Since $since | ForEach-Object {
    Write-SecEvent 'user_created' @{ new_user=$_.Properties[0].Value; created_by=$_.Properties[4].Value }
    $alerts++
}

Write-Host "Check complete. High-severity alerts: $alerts"
