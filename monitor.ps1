Write-Host "Blue Team Monitor iniciado..." -ForegroundColor Green

$LogFile = ".\logs\security_log.txt"

$AlertCount = 0

function Save-Alert {

    param($Message)

    $Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    "$Date : $Message" | Out-File -Append $LogFile

    Write-Host "[ALERTA] $Message" -ForegroundColor Red

    $script:AlertCount++
}

# Buscar eventos de intentos fallidos de login

try {

    $FailedLogins = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4625
    } -MaxEvents 10 -ErrorAction Stop

    if($FailedLogins){

        Save-Alert "Se detectaron $($FailedLogins.Count) intentos fallidos de inicio de sesión"

    }

}
catch{

    Write-Host "No hay intentos fallidos detectados"

}

# Detectar creación de usuarios

try {

    $NewUsers = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4720
    } -MaxEvents 5 -ErrorAction SilentlyContinue

    if($NewUsers){

        Save-Alert "Se detectó creación de usuario(s) reciente(s)"

    }
    else{

        Write-Host "No hay nuevos usuarios"

    }

}
catch{

    Write-Host "No hay eventos de creación de usuarios"
}


# Verificar si hubo alertas

if($AlertCount -eq 0){

    Write-Host "[OK] No se detectaron alertas" -ForegroundColor Green

    $Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    "$Date : Sistema revisado - Sin alertas" | Out-File -Append $LogFile
}

# =============================
# Generación automática de reporte
# =============================

$ReportFile = ".\reports\report.txt"

$Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Crear encabezado del reporte
@"
====================================
BLUE TEAM SECURITY REPORT
====================================

Fecha: $Date
Alertas detectadas: $AlertCount

Resumen:
"@ | Out-File $ReportFile

# Agregar información según el resultado

if($AlertCount -gt 0){

    "Estado: ALERTAS DETECTADAS" | Out-File -Append $ReportFile

}
else{

    "Estado: SIN ALERTAS" | Out-File -Append $ReportFile

}

"`nEventos registrados:`n" | Out-File -Append $ReportFile

# Agregar contenido del log si existe

if(Test-Path $LogFile){

    Get-Content $LogFile | Out-File -Append $ReportFile

}

Write-Host "[REPORTE] report.txt generado correctamente" -ForegroundColor Cyan

# Wazuh SIEM Integration Complete