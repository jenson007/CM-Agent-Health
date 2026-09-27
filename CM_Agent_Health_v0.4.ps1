<#
.SYNOPSIS
    ConfigMgr (SCCM) Client- & Windows-Update-Diagnose, Remediation und Evaluation.

.DESCRIPTION
    Version 0.4 - getrennte Evaluierung und Remediation.

    Betriebsarten:
      Evaluate  Ausschließlich Diagnose, keine Änderungen
      Light     Diagnose, risikoarme/gezielte Reparaturen und ConfigMgr-Zyklen
      Deep      Wie Light; zusätzlich WU-Cache-Reset bei passendem Symptom

    Mit "-Mode Deep -Force" wird der WU-Cache-Reset unabhängig vom Diagnosebefund
    ausgeführt. -Force ist ausschließlich zusammen mit -Mode Deep zulässig.

    Wesentliche Änderungen gegenüber v0.1:
      - WMI-Prüfung ausgewertet über Exit-Code + Out-String (kein Array-Falsch-Positiv mehr)
      - DISM-Prüfung sprachneutral über Repair-WindowsImage / ImageHealthState
      - SMS_Client.ResetPolicy mit korrektem Parameter "uFlags" (v0.1 nutzte "TargetPolicyType")
      - Zyklus-GUIDs 108/113 korrekt benannt und in sinnvoller Reihenfolge ausgeführt
      - UseWUServer als Drei-Zustand ausgewertet (nicht konfiguriert / =1 / <>1)
      - smsts.log-Auswertung mit Altersfilter und rotierten Logs
      - regsvr32-Legacyblock entfernt (auf Win10/11 nutzlos bis schädlich)
      - SoftwareDistribution/catroot2 werden umbenannt statt gelöscht
      - ConfigMgr-Client selbst (CcmExec, root\ccm, CcmEval) wird geprüft
      - Pending-Reboot-Erkennung, Re-Validierung, Exit-Codes, JSON-Zusammenfassung
      - -Mode Evaluate / -WhatIf für gefahrlosen Breitenausrollen

    Änderungen in v0.4:
      - UseWUServer wird korrekt aus dem Unterschlüssel WindowsUpdate\AU gelesen
      - WUServer/WUStatusServer werden aus der Registry ausgewertet und ausgegeben
      - SoftwareDistribution wird auf übermäßige Eintragszahlen geprüft
      - Evaluate, Light und Deep trennen Diagnose und Behandlung
      - Deep kann mit -Force bewusst ohne Befund ausgeführt werden
      - JSON enthält Symptomdetails, WU-Konfiguration und Remediation-Ergebnisse

.PARAMETER Mode
    Evaluate: nur prüfen. Light: risikoarme und symptombezogene Behandlung.
    Deep: wie Light und zusätzlich WU-Cache-Reset bei passendem Symptom.

.PARAMETER Force
    Erzwingt den WU-Cache-Reset ohne passenden Befund. Nur mit -Mode Deep.

.PARAMETER DeepScan
    Nutzt in Phase 1 DISM /ScanHealth statt /CheckHealth (deutlich gründlicher,
    aber mehrere Minuten Laufzeit).

.PARAMETER EnforceWSUS
    Erzwingt UseWUServer = 1, sofern WUServer und WUStatusServer vollständig
    konfiguriert sind. Ohne diesen Schalter werden WUfB-/Intune-Konfigurationen
    nicht verändert.

.PARAMETER TSLogMaxAgeDays
    Maximales Alter eines smsts.log, das noch ausgewertet wird. Verhindert, dass
    ein Monate altes OSD-Log eine Tiefenreparatur auslöst. Standard: 14.

.PARAMETER SoftwareDistributionEntryThreshold
    Maximale Anzahl von Dateien und Verzeichnissen unter SoftwareDistribution.
    Wird der Grenzwert überschritten, wird das Symptom
    WU_SOFTWAREDISTRIBUTION_EXCESSIVE gemeldet. Standard: 100000.

.PARAMETER LogPath
    Pfad der CMTrace-Logdatei.

.PARAMETER LogMaxSizeMB
    Größe, ab der die Logdatei nach .lo_ rotiert wird. Standard: 5.

.PARAMETER Quiet
    Unterdrückt die Konsolenausgabe (Logdatei und JSON-Ausgabe bleiben erhalten).

.EXAMPLE
    .\CM_Agent_Health_v0.4.ps1 -Mode Evaluate
    Nur Diagnose, kein Eingriff.

.EXAMPLE
    .\CM_Agent_Health_v0.4.ps1 -Mode Light -WhatIf
    Zeigt, welche Reparaturen ausgeführt würden, ohne sie durchzuführen.

.EXAMPLE
    .\CM_Agent_Health_v0.4.ps1 -Mode Deep
    Tiefenreparatur nur bei einem passenden Symptom.

.EXAMPLE
    .\CM_Agent_Health_v0.4.ps1 -Mode Deep -Force
    Erzwingt den WU-Cache-Reset unabhängig vom Diagnoseergebnis.

.NOTES
    Version : 0.4
    Laufzeit: Mit -Mode Deep und DISM /RestoreHealth + SFC sind 30-60 Minuten
              realistisch. Der Standard-Timeout von "Skripte ausführen" in ConfigMgr
              liegt bei 60 Minuten - ggf. als Paket/Task mit eigenem Timeout ausrollen.

    Exit-Codes:
       0     Keine Symptome (mehr) vorhanden
       1     Es sind Symptome offen geblieben
       3010  Bereinigt, aber Neustart erforderlich
       2     Abbruch durch unerwarteten Fehler

    WICHTIG: Diese Datei als UTF-8 MIT BOM speichern, sonst zerlegt Windows
             PowerShell 5.1 die Umlaute.
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Evaluate', 'Light', 'Deep')][string]$Mode = 'Evaluate',
    [switch]$Force,
    [switch]$DeepScan,
    [switch]$EnforceWSUS,
    [ValidateRange(1, 365)][int]$TSLogMaxAgeDays = 14,
    [ValidateRange(1000, 5000000)][int]$SoftwareDistributionEntryThreshold = 100000,
    [string]$LogPath = "$env:SystemRoot\CCM\Logs\CM_AgentHealth.log",
    [ValidateRange(1, 100)][int]$LogMaxSizeMB = 5,
    [switch]$Quiet
)

if ($Force -and $Mode -ne 'Deep') {
    throw '-Force ist ausschließlich zusammen mit -Mode Deep zulässig.'
}

# Fehler sollen sichtbar sein - jeder Block fängt gezielt ab.
$ErrorActionPreference = 'Stop'

$script:LogPath         = $LogPath
$script:Quiet           = $Quiet.IsPresent
$script:DetectedIssues  = [System.Collections.Generic.HashSet[string]]::new()
$script:IssueDetails    = [ordered]@{}
$script:InitialIssueDetails = [ordered]@{}
$script:RemediationResults = [System.Collections.Generic.List[object]]::new()
$script:RebootPending   = $false
$script:ScriptName      = 'CM_Agent_Health_v0.4.ps1'
$script:SoftwareDistributionEntryCount = 0
$script:WUConfiguration = [ordered]@{}

# ==========================================================================
# HILFSFUNKTIONEN
# ==========================================================================

function Initialize-Log {
    try {
        $dir = Split-Path -Path $script:LogPath -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
        if (Test-Path -LiteralPath $script:LogPath) {
            $sizeMB = (Get-Item -LiteralPath $script:LogPath).Length / 1MB
            if ($sizeMB -ge $LogMaxSizeMB) {
                $backup = [System.IO.Path]::ChangeExtension($script:LogPath, 'lo_')
                Move-Item -LiteralPath $script:LogPath -Destination $backup -Force
            }
        }
    }
    catch {
        # Fällt auf TEMP zurück, damit wenigstens irgendwo protokolliert wird.
        $script:LogPath = Join-Path $env:TEMP 'CM_AgentHealth.log'
        Write-Warning "Log-Pfad nicht verfügbar, weiche aus auf $($script:LogPath)"
    }
}

function Write-CMLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet(1, 2, 3)][int]$Type = 1,
        [string]$Component = 'CMAgentHealth'
    )

    $time = Get-Date -Format 'HH:mm:ss.fff'
    $date = Get-Date -Format 'MM-dd-yyyy'
    $line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="{5}" file="{6}">' -f `
                $Message, $time, $date, $Component, $Type, $PID, $script:ScriptName

    # Mehrere parallele Instanzen (z.B. CcmEval + manuelle Ausführung) können
    # kollidieren - deshalb kurze Wiederholung statt stillem Verschlucken.
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8 -ErrorAction Stop
            break
        }
        catch {
            if ($attempt -eq 3) { Write-Warning "Logging fehlgeschlagen: $($_.Exception.Message)" }
            else { Start-Sleep -Milliseconds 150 }
        }
    }

    if (-not $script:Quiet) {
        switch ($Type) {
            1 { Write-Host "[INFO] $Message"  -ForegroundColor Green }
            2 { Write-Host "[WARN] $Message"  -ForegroundColor Yellow }
            3 { Write-Host "[ERROR] $Message" -ForegroundColor Red }
        }
    }
}

function Invoke-NativeCommand {
    <# Native Programme geben Meldungen oft auf stderr aus. Zusammen mit
       $ErrorActionPreference = 'Stop' würde "2>&1" den Aufruf abbrechen lassen,
       obwohl gar kein Fehler vorliegt - deshalb lokal auf 'Continue' schalten. #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $FilePath @Arguments 2>&1 | Out-String
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output   = $output.Trim()
        }
    }
    finally {
        $ErrorActionPreference = $previous
    }
}

function Add-Issue {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Message
    )
    [void]$script:DetectedIssues.Add($Id)
    $script:IssueDetails[$Id] = $Message
    Write-CMLog "[-] Symptom ($Id): $Message" 3
}

function Test-Issue {
    param([Parameter(Mandatory)][string]$Id)
    return $script:DetectedIssues.Contains($Id)
}

function Add-RemediationResult {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][bool]$Succeeded,
        [Parameter(Mandatory)][string]$Message
    )
    [void]$script:RemediationResults.Add([pscustomobject]@{
        Action    = $Action
        Succeeded = $Succeeded
        Message   = $Message
    })
}

function Get-DirectoryEntryCount {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$StopAfter
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return 0 }

    $count = 0
    foreach ($entry in [System.IO.Directory]::EnumerateFileSystemEntries(
        $Path, '*', [System.IO.SearchOption]::AllDirectories)) {
        $count++
        if ($count -ge $StopAfter) { break }
    }
    return $count
}

function Set-ServiceStartup {
    <# Setzt den Starttyp und verifiziert das Ergebnis.
       "DelayedAuto" gibt es unter PowerShell 5.1 nicht via Set-Service -> sc.exe. #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Manual', 'Automatic', 'DelayedAuto')][string]$StartupType
    )
    try {
        if ($StartupType -eq 'DelayedAuto') {
            & sc.exe config $Name start= delayed-auto | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "sc.exe config lieferte Exit-Code $LASTEXITCODE" }
        }
        else {
            Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop
        }

        $current = (Get-Service -Name $Name -ErrorAction Stop).StartType
        if ($current -eq 'Disabled') {
            Write-CMLog "   [-] $Name ist trotz Korrektur weiterhin 'Disabled' - vermutlich per GPO/Intune erzwungen." 3
            return $false
        }
        Write-CMLog "   [+] $Name Starttyp jetzt: $current" 1
        return $true
    }
    catch {
        Write-CMLog "   [-] Starttyp für $Name konnte nicht gesetzt werden: $($_.Exception.Message)" 3
        return $false
    }
}

function Stop-ServiceSafe {
    param([Parameter(Mandatory)][string]$Name, [int]$TimeoutSeconds = 30)
    try {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $svc) { return $true }
        if ($svc.Status -eq 'Stopped') { return $true }
        Stop-Service -Name $Name -Force -ErrorAction Stop
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($TimeoutSeconds))
        Write-CMLog "   [+] Dienst $Name gestoppt." 1
        return $true
    }
    catch {
        Write-CMLog "   [-] Dienst $Name konnte nicht gestoppt werden: $($_.Exception.Message)" 3
        return $false
    }
}

function Start-ServiceSafe {
    param([Parameter(Mandatory)][string]$Name)
    try {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $svc) { return $true }
        if ($svc.StartType -eq 'Disabled') {
            Write-CMLog "   [!] Dienst $Name ist deaktiviert und wird nicht gestartet." 2
            return $false
        }
        if ($svc.Status -ne 'Running') { Start-Service -Name $Name -ErrorAction Stop }
        Write-CMLog "   [+] Dienst $Name gestartet." 1
        return $true
    }
    catch {
        Write-CMLog "   [-] Dienst $Name konnte nicht gestartet werden: $($_.Exception.Message)" 3
        return $false
    }
}

function Rename-ResetFolder {
    <# MS-Standard: umbenennen statt löschen - rollback-fähig und scheitert nicht
       an einzelnen gesperrten Dateien. #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-CMLog "   [i] $Path existiert nicht - übersprungen." 1
        return $true
    }
    $leaf   = Split-Path -Path $Path -Leaf
    $target = "$Path.old"
    try {
        if (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
        }
        Rename-Item -LiteralPath $Path -NewName "$leaf.old" -Force -ErrorAction Stop
        Write-CMLog "   [+] $Path umbenannt nach $target" 1
        return $true
    }
    catch {
        Write-CMLog "   [-] $Path konnte nicht umbenannt werden: $($_.Exception.Message)" 3
        return $false
    }
}

function Test-PendingReboot {
    $reasons = @()
    try {
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
            $reasons += 'CBS RebootPending'
        }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\WindowsUpdate\Auto Update\RebootRequired') {
            $reasons += 'WindowsUpdate RebootRequired'
        }
        $pfro = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                    -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if ($pfro) { $reasons += 'PendingFileRenameOperations' }

        $ccmReboot = Get-CimInstance -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_ClientUtilities' -ErrorAction SilentlyContinue
        if ($ccmReboot) {
            $state = Invoke-CimMethod -InputObject $ccmReboot -MethodName 'DetermineIfRebootPending' -ErrorAction SilentlyContinue
            if ($state -and ($state.RebootPending -or $state.IsHardRebootPending)) { $reasons += 'ConfigMgr Client' }
        }
    }
    catch {
        Write-CMLog "[!] Pending-Reboot-Prüfung unvollständig: $($_.Exception.Message)" 2
    }
    return , $reasons
}

# ==========================================================================
# PHASE 1: VALIDATION / DIAGNOSTIK (REIN LESEND)
# ==========================================================================

function Invoke-Diagnostics {
    param([switch]$IsRecheck)

    $script:DetectedIssues.Clear()
    $script:IssueDetails = [ordered]@{}

    $label = if ($IsRecheck) { 'PHASE 2b: RE-VALIDIERUNG' } else { 'PHASE 1: VALIDATION (Diagnostik)' }
    Write-CMLog "--- $label ---" 1

    # ---- 1.0 ConfigMgr-Client -------------------------------------------
    Write-CMLog '[1.0] Prüfe ConfigMgr-Client (CcmExec / root\ccm)...'
    try {
        $ccmSvc = Get-Service -Name 'CcmExec' -ErrorAction SilentlyContinue
        if (-not $ccmSvc) {
            Add-Issue 'CCM_CLIENT_MISSING' 'SMS Agent Host (CcmExec) ist nicht installiert.'
        }
        elseif ($ccmSvc.Status -ne 'Running') {
            Add-Issue 'CCM_SERVICE_STOPPED' "CcmExec läuft nicht (Status: $($ccmSvc.Status), Starttyp: $($ccmSvc.StartType))."
        }
        else {
            $client = Get-CimInstance -Namespace 'root\ccm' -ClassName 'SMS_Client' -ErrorAction Stop
            Write-CMLog "[+ OK] ConfigMgr-Client aktiv (Client-Version $($client.ClientVersion))." 1
        }
    }
    catch {
        Add-Issue 'CCM_WMI_UNAVAILABLE' "Namespace root\ccm nicht erreichbar: $($_.Exception.Message)"
    }

    # ---- 1.0b CcmEval-Status (nur informativ) ---------------------------
    try {
        $lastEvalRaw = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\CCM\CcmEval' `
                          -Name 'LastEvalTime' -ErrorAction SilentlyContinue).LastEvalTime
        if ($lastEvalRaw) {
            [datetime]$parsed = [datetime]::MinValue
            if ([datetime]::TryParse($lastEvalRaw, [ref]$parsed)) {
                $ageDays = [int]((Get-Date) - $parsed).TotalDays
                if ($ageDays -gt 7) { Write-CMLog "[!] CcmEval lief zuletzt vor $ageDays Tagen ($parsed)." 2 }
                else { Write-CMLog "[+ OK] CcmEval zuletzt ausgeführt: $parsed." 1 }
            }
            else { Write-CMLog "[i] CcmEval LastEvalTime nicht interpretierbar: $lastEvalRaw" 2 }
        }
        else { Write-CMLog '[i] Kein CcmEval-Ergebnis in der Registry vorhanden.' 2 }
    }
    catch {
        Write-CMLog "[!] CcmEval-Status nicht lesbar: $($_.Exception.Message)" 2
    }

    # ---- 1.1 WMI-Repository ---------------------------------------------
    Write-CMLog '[1.1] Prüfe WMI-Repository Zustand...'
    try {
        # Out-String, weil native Ausgabe ein Array ist: bei Arrays liefert -notmatch
        # die nicht passenden ELEMENTE zurück und ist damit praktisch immer "wahr".
        $wmi = Invoke-NativeCommand -FilePath 'winmgmt.exe' -Arguments @('/verifyrepository')
        if ($wmi.ExitCode -ne 0 -or $wmi.Output -notmatch 'consistent|konsistent') {
            Add-Issue 'WMI_CORRUPT' "WMI-Repository inkonsistent (Exit $($wmi.ExitCode)): $($wmi.Output)"
        }
        else {
            Write-CMLog '[+ OK] WMI-Repository ist konsistent.' 1
        }
    }
    catch {
        Add-Issue 'WMI_CORRUPT' "WMI-Prüfung nicht ausführbar: $($_.Exception.Message)"
    }

    # ---- 1.2 Component Store --------------------------------------------
    $mode = if ($DeepScan) { 'ScanHealth' } else { 'CheckHealth' }
    Write-CMLog "[1.2] Prüfe Windows Component Store (DISM $mode)..."
    try {
        # Sprachneutral: ImageHealthState statt Textvergleich auf lokalisierte
        # DISM-Ausgabe ("reparierbar" vs. "reparabel" vs. "repairable").
        $img = if ($DeepScan) {
            Repair-WindowsImage -Online -ScanHealth -ErrorAction Stop
        } else {
            Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop
        }
        switch ($img.ImageHealthState) {
            'Healthy'       { Write-CMLog '[+ OK] Component Store ist gesund.' 1 }
            'Repairable'    { Add-Issue 'DISM_CORRUPT' 'Component Store (WinSxS) ist beschädigt, aber reparierbar.' }
            'NonRepairable' { Add-Issue 'DISM_NONREPAIRABLE' 'Component Store ist NICHT online reparierbar - In-Place-Upgrade/Neuinstallation nötig.' }
            default         { Add-Issue 'DISM_CORRUPT' "Unerwarteter ImageHealthState: $($img.ImageHealthState)" }
        }
    }
    catch {
        Add-Issue 'DISM_CORRUPT' "Component-Store-Prüfung fehlgeschlagen: $($_.Exception.Message)"
    }

    # ---- 1.3 Windows Update Agent (COM) ---------------------------------
    Write-CMLog '[1.3] Prüfe WUA COM-Schnittstelle...'
    $wuSession = $null
    try {
        $wuSession  = New-Object -ComObject 'Microsoft.Update.Session'
        $wuSearcher = $wuSession.CreateUpdateSearcher()
        # Echter Funktionstest - die reine Instanziierung schlägt fast nie fehl.
        $historyCount = $wuSearcher.GetTotalHistoryCount()
        Write-CMLog "[+ OK] WUA COM funktionsfähig (Update-Historie: $historyCount Einträge)." 1
    }
    catch {
        Add-Issue 'WUA_COM_ERROR' "WUA COM-Schnittstelle reagiert nicht: $($_.Exception.Message)"
    }
    finally {
        if ($wuSession) {
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($wuSession) } catch { }
        }
    }

    # ---- 1.4 Starttypen der Update-Dienste -------------------------------
    Write-CMLog '[1.4] Prüfe Starttypen der Windows Update Dienste...'
    $disabled = @()
    $missing  = @()
    foreach ($svcName in $script:WuServiceDefaults.Keys) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if (-not $svc)                         { $missing  += $svcName }
            elseif ($svc.StartType -eq 'Disabled') { $disabled += $svcName }
        }
        catch { $missing += $svcName }
    }
    if ($missing.Count -gt 0) { Write-CMLog "[!] Nicht vorhandene Dienste (OS-abhängig normal): $($missing -join ', ')" 2 }
    if ($disabled.Count -gt 0) {
        $script:DisabledServices = $disabled
        Add-Issue 'WU_SERVICES_DISABLED' "Deaktivierte Update-Dienste: $($disabled -join ', ')"
    }
    else {
        $script:DisabledServices = @()
        Write-CMLog '[+ OK] Kein relevanter Update-Dienst ist deaktiviert.' 1
    }

    # ---- 1.5 UseWUServer (Drei-Zustand) ----------------------------------
    Write-CMLog '[1.5] Prüfe WSUS-Konfiguration aus der Registry...'
    try {
        $wuPolicy       = Get-ItemProperty -Path $script:WUPolicyKey -ErrorAction SilentlyContinue
        $wuAuPolicy     = Get-ItemProperty -Path $script:WUAUPolicyKey -ErrorAction SilentlyContinue
        $useWUServer    = if ($null -ne $wuAuPolicy.UseWUServer) { [int]$wuAuPolicy.UseWUServer } else { $null }
        $wuServer       = "$($wuPolicy.WUServer)".Trim()
        $wuStatusServer = "$($wuPolicy.WUStatusServer)".Trim()

        $script:WUConfiguration = [ordered]@{
            UseWUServer    = $useWUServer
            WUServer       = $wuServer
            WUStatusServer = $wuStatusServer
            Source         = if ($useWUServer -eq 1) { 'WSUS/SUP' } else { 'Microsoft Update/WUfB or not configured' }
        }

        Write-CMLog "[i] WU-Registry: UseWUServer='$useWUServer'; WUServer='$wuServer'; WUStatusServer='$wuStatusServer'." 1

        if ($EnforceWSUS) {
            if (-not $wuServer -or -not $wuStatusServer) {
                Add-Issue 'WU_WSUS_CONFIG_INCOMPLETE' 'WSUS wird erzwungen, aber WUServer oder WUStatusServer fehlt. UseWUServer wird nicht automatisch aktiviert.'
            }
            elseif ($useWUServer -ne 1) {
                Add-Issue 'WU_USEWUSERVER_DISABLED' "WSUS ist vollständig konfiguriert, UseWUServer steht aber auf $useWUServer statt 1."
            }
            else {
                Write-CMLog '[+ OK] WSUS-Endpunkte sind vollständig und UseWUServer ist auf 1 gesetzt.' 1
            }
        }
        elseif ($useWUServer -eq 1) {
            if (-not $wuServer -or -not $wuStatusServer) {
                Add-Issue 'WU_WSUS_CONFIG_INCOMPLETE' 'UseWUServer ist aktiv, aber WUServer oder WUStatusServer fehlt.'
            }
            else {
                Write-CMLog '[+ OK] UseWUServer ist auf 1 gesetzt und beide WSUS-Endpunkte sind vorhanden.' 1
            }
        }
        else {
            Write-CMLog "[i] UseWUServer ist '$useWUServer'. Ohne -EnforceWSUS wird eine mögliche WUfB-/Intune-Konfiguration nicht verändert." 1
        }
    }
    catch {
        Add-Issue 'WU_REGISTRY_UNREADABLE' "WU-Konfiguration nicht aus der Registry lesbar: $($_.Exception.Message)"
    }

    # ---- 1.6 SUSClientId --------------------------------------------------
    Write-CMLog '[1.6] Prüfe WSUS-Client-Identität (SUSClientId)...'
    try {
        $susId = (Get-ItemProperty -Path $script:WUIdentityKey -Name 'SUSClientId' -ErrorAction SilentlyContinue).SUSClientId
        if (-not $susId) { Add-Issue 'WU_SUSCLIENTID_MISSING' 'SUSClientId fehlt in der Registry.' }
        else { Write-CMLog "[+ OK] SUSClientId vorhanden ($susId)." 1 }
    }
    catch {
        Write-CMLog "[!] SUSClientId nicht lesbar: $($_.Exception.Message)" 2
    }

    # ---- 1.7 Provisioning Mode -------------------------------------------
    Write-CMLog '[1.7] Prüfe ConfigMgr Provisioning Mode...'
    try {
        $provRaw = (Get-ItemProperty -Path $script:CcmExecKey -Name 'ProvisioningMode' -ErrorAction SilentlyContinue).ProvisioningMode
        $prov    = if ($null -ne $provRaw) { "$provRaw".Trim() } else { $null }
        if ($prov -and $prov -eq 'true') {
            Add-Issue 'CLIENT_PROVISIONING_MODE' 'Client steckt im Provisioning Mode fest.'
        }
        else {
            Write-CMLog '[+ OK] Client ist nicht im Provisioning Mode.' 1
        }
    }
    catch {
        Write-CMLog "[!] Provisioning Mode nicht lesbar: $($_.Exception.Message)" 2
    }

    # ---- 1.8 SoftwareDistribution-Größe -----------------------------------
    Write-CMLog "[1.8] Prüfe SoftwareDistribution (Grenzwert: $SoftwareDistributionEntryThreshold Einträge)..."
    try {
        $softwareDistributionPath = Join-Path $env:SystemRoot 'SoftwareDistribution'
        $stopAfter = $SoftwareDistributionEntryThreshold + 1
        $script:SoftwareDistributionEntryCount = Get-DirectoryEntryCount `
            -Path $softwareDistributionPath -StopAfter $stopAfter

        if ($script:SoftwareDistributionEntryCount -gt $SoftwareDistributionEntryThreshold) {
            Add-Issue 'WU_SOFTWAREDISTRIBUTION_EXCESSIVE' `
                "SoftwareDistribution enthält mehr als $SoftwareDistributionEntryThreshold Einträge; Zählung wurde bei $($script:SoftwareDistributionEntryCount) abgebrochen."
        }
        else {
            Write-CMLog "[+ OK] SoftwareDistribution enthält $($script:SoftwareDistributionEntryCount) Einträge." 1
        }
    }
    catch {
        Add-Issue 'WU_SOFTWAREDISTRIBUTION_UNREADABLE' "SoftwareDistribution konnte nicht ausgewertet werden: $($_.Exception.Message)"
    }

    # ---- 1.9 Task-Sequence-Log auswerten ---------------------------------
    Write-CMLog "[1.9] Analysiere smsts.log (max. $TSLogMaxAgeDays Tage alt)..."
    if ($IsRecheck -and $script:TSRepairSucceeded) {
        Write-CMLog '[+ OK] WU-Komponenten wurden in diesem Lauf erfolgreich zurückgesetzt; historische smsts.log-Fehler werden bei der Re-Validierung nicht erneut gewertet.' 1
    }
    else {
        try {
        $cutoff  = (Get-Date).AddDays(-$TSLogMaxAgeDays)
        $tsRoots = @(
            "$env:SystemRoot\CCM\Logs\SMSTSLog",
            "$env:SystemRoot\CCM\Logs",
            "$env:SystemDrive\_SMSTaskSequence\Logs",
            "$env:SystemDrive\SMSTSLog"
        )

        # Auch rotierte Logs (smsts-<timestamp>.log) berücksichtigen.
        $tsLogs = foreach ($root in $tsRoots) {
            if (Test-Path -LiteralPath $root) {
                Get-ChildItem -LiteralPath $root -Filter 'smsts*.log' -File -ErrorAction SilentlyContinue
            }
        }
        $tsLogs = $tsLogs | Where-Object { $_.LastWriteTime -ge $cutoff } |
                            Sort-Object LastWriteTime -Descending |
                            Select-Object -First 3

        if (-not $tsLogs) {
            Write-CMLog "[+ OK] Kein aktuelles smsts.log vorhanden - keine Post-OSD-Auswertung nötig." 1
        }
        else {
            $hexCodes = @('0x800F081F', '0x80070490', '0x800F0900', '0x800F0922',
                          '0x80240020', '0x80248007', '0x8024002E', '0x80244022', '0x8007000E')
            $stepPattern = 'Failed to (create|refresh|search updates using) WUA'
            $foundHex    = New-Object System.Collections.Generic.HashSet[string]
            $stepHits    = @()

            foreach ($log in $tsLogs) {
                $lines = Get-Content -LiteralPath $log.FullName -Tail 2000 -ErrorAction SilentlyContinue
                if (-not $lines) { continue }

                $stepHits += $lines | Select-String -Pattern $stepPattern
                foreach ($code in $hexCodes) {
                    if ($lines | Select-String -SimpleMatch -Pattern $code -Quiet) { [void]$foundHex.Add($code) }
                }
            }

            if ($stepHits.Count -gt 0 -or $foundHex.Count -gt 0) {
                $detail = "Quelle: $($tsLogs[0].FullName) ($($tsLogs[0].LastWriteTime))"
                if ($foundHex.Count -gt 0) { $detail += "; Hex-Codes: $(($foundHex) -join ', ')" }
                if ($stepHits.Count -gt 0) { $detail += "; WUAgent-Fehlerzeilen: $($stepHits.Count)" }
                Add-Issue 'WU_TS_COMPONENT_CORRUPT' "Post-OSD Windows-Update-Komponentenfehler im TS-Log. $detail"
            }
            else {
                Write-CMLog "[+ OK] Keine WU-Komponentenfehler in $($tsLogs.Count) ausgewerteten TS-Log(s)." 1
            }
        }
        }
        catch {
            Write-CMLog "[!] smsts.log-Auswertung fehlgeschlagen: $($_.Exception.Message)" 2
        }
    }

    # ---- 1.10 Pending Reboot ---------------------------------------------
    Write-CMLog '[1.10] Prüfe ausstehenden Neustart...'
    $rebootReasons = Test-PendingReboot
    if ($rebootReasons.Count -gt 0) {
        $script:RebootPending = $true
        Write-CMLog "[!] Neustart ausstehend: $($rebootReasons -join ', ')" 2
    }
    else {
        Write-CMLog '[+ OK] Kein zusätzlicher Neustartindikator gefunden.' 1
    }

    Write-CMLog "=== Diagnose abgeschlossen. Erkannte Symptome: $($script:DetectedIssues.Count) ===" 1
}

# ==========================================================================
# PHASE 2: REMEDIATION
# ==========================================================================

function Invoke-Remediation {
    Write-CMLog "--- PHASE 2: REMEDIATION (Modus: $Mode$(if ($Force) { ', Force' })) ---" 1

    if ($script:DetectedIssues.Count -eq 0) {
        Write-CMLog '[i] Keine Symptome erkannt. Die für den gewählten Modus vorgesehenen Basismaßnahmen werden trotzdem ausgeführt.' 1
    }

    # ---- 2.0 ConfigMgr-Dienst ---------------------------------------------
    if (Test-Issue 'CCM_SERVICE_STOPPED') {
        if ($PSCmdlet.ShouldProcess('CcmExec', 'Dienst starten')) {
            Write-CMLog '[REMEDIATION] Starte SMS Agent Host (CcmExec)...'
            if ((Get-Service -Name 'CcmExec').StartType -eq 'Disabled') {
                [void](Set-ServiceStartup -Name 'CcmExec' -StartupType 'Automatic')
            }
            [void](Start-ServiceSafe -Name 'CcmExec')
        }
    }
    if ((Test-Issue 'CCM_WMI_UNAVAILABLE') -or (Test-Issue 'CCM_CLIENT_MISSING')) {
        Write-CMLog '[!] ConfigMgr-Client fehlt oder root\ccm ist defekt. Automatische Reparatur wird hier bewusst NICHT ausgeführt - bitte ccmrepair.exe bzw. Client-Neuinstallation einplanen.' 2
    }

    # ---- 2.1 WMI-Repository -----------------------------------------------
    if ($Mode -eq 'Deep' -and (Test-Issue 'WMI_CORRUPT')) {
        if ($PSCmdlet.ShouldProcess('WMI-Repository', 'winmgmt /salvagerepository')) {
            Write-CMLog '[REMEDIATION] Führe WMI Salvage-Repository aus...'
            $ccmWasRunning = (Get-Service -Name 'CcmExec' -ErrorAction SilentlyContinue).Status -eq 'Running'
            if ($ccmWasRunning) { [void](Stop-ServiceSafe -Name 'CcmExec' -TimeoutSeconds 60) }
            try {
                $salvage = Invoke-NativeCommand -FilePath 'winmgmt.exe' -Arguments @('/salvagerepository')
                Write-CMLog "   [i] Salvage-Ausgabe (Exit $($salvage.ExitCode)): $($salvage.Output)" 1

                $verify = Invoke-NativeCommand -FilePath 'winmgmt.exe' -Arguments @('/verifyrepository')
                if ($verify.ExitCode -eq 0 -and $verify.Output -match 'consistent|konsistent') {
                    Write-CMLog '   [+ OK] WMI-Repository nach Salvage konsistent.' 1
                }
                else {
                    Write-CMLog "   [-] WMI weiterhin inkonsistent: $($verify.Output) - Neuaufbau/Client-Neuinstallation prüfen." 3
                }
            }
            catch {
                Write-CMLog "   [-] Salvage fehlgeschlagen: $($_.Exception.Message)" 3
            }
            finally {
                if ($ccmWasRunning) { [void](Start-ServiceSafe -Name 'CcmExec') }
            }
        }
    }

    # ---- 2.2 Component Store ----------------------------------------------
    if ($Mode -eq 'Deep' -and (Test-Issue 'DISM_CORRUPT')) {
        if ($PSCmdlet.ShouldProcess('Component Store', 'DISM RestoreHealth + SFC')) {
            Write-CMLog '[REMEDIATION] Führe DISM RestoreHealth aus (kann 15-45 Minuten dauern)...'
            try {
                $repair = Repair-WindowsImage -Online -RestoreHealth -NoRestart -ErrorAction Stop
                Write-CMLog "   [+ OK] DISM RestoreHealth abgeschlossen (RestartNeeded: $($repair.RestartNeeded))." 1
                if ($repair.RestartNeeded) { $script:RebootPending = $true }
            }
            catch {
                Write-CMLog "   [-] DISM RestoreHealth fehlgeschlagen: $($_.Exception.Message)" 3
            }

            Write-CMLog '[REMEDIATION] Führe SFC /scannow aus...'
            try {
                # sfc.exe gibt UCS-2 aus und lässt sich schlecht parsen -> Exit-Code auswerten.
                $sfc = Invoke-NativeCommand -FilePath 'sfc.exe' -Arguments @('/scannow')
                if ($sfc.ExitCode -eq 0) { Write-CMLog '   [+ OK] SFC abgeschlossen (Exit 0).' 1 }
                else { Write-CMLog "   [!] SFC beendet mit Exit-Code $($sfc.ExitCode) - CBS.log prüfen." 2 }
            }
            catch {
                Write-CMLog "   [-] SFC fehlgeschlagen: $($_.Exception.Message)" 3
            }
        }
    }
    if (Test-Issue 'DISM_NONREPAIRABLE') {
        Write-CMLog '[!] Component Store ist online nicht reparierbar - In-Place-Upgrade oder Neuinstallation erforderlich. Keine automatische Reparatur.' 2
    }

    # ---- 2.3 Nur die tatsächlich deaktivierten Dienste reaktivieren -------
    if (Test-Issue 'WU_SERVICES_DISABLED') {
        if ($PSCmdlet.ShouldProcess("Dienste: $($script:DisabledServices -join ', ')", 'Starttyp zurücksetzen')) {
            Write-CMLog '[REMEDIATION] Reaktiviere deaktivierte Update-Dienste...'
            foreach ($svcName in $script:DisabledServices) {
                $target = $script:WuServiceDefaults[$svcName]
                if (Set-ServiceStartup -Name $svcName -StartupType $target) {
                    [void](Start-ServiceSafe -Name $svcName)
                }
            }
            if (Test-Path $script:WUPolicyKey) {
                Write-CMLog '   [!] WindowsUpdate-Policy-Key vorhanden: Prüfen, ob GPO/Intune die Dienste erneut deaktiviert.' 2
            }
        }
    }

    # Light-Basisbehandlung läuft in Light und Deep unabhängig vom Befund.
    if ($PSCmdlet.ShouldProcess('CcmExec, wuauserv, bits', 'Erforderliche Dienste starten')) {
        $lightServicesOk = $true
        foreach ($svcName in @('CcmExec', 'wuauserv', 'bits')) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc -and $svc.StartType -ne 'Disabled') {
                if (-not (Start-ServiceSafe -Name $svcName)) { $lightServicesOk = $false }
            }
        }
        Add-RemediationResult -Action 'StartCoreServices' -Succeeded $lightServicesOk `
            -Message $(if ($lightServicesOk) { 'Erforderliche Client- und Update-Dienste laufen.' } else { 'Mindestens ein erforderlicher Dienst konnte nicht gestartet werden.' })
    }

    # ---- 2.4 UseWUServer ---------------------------------------------------
    if (Test-Issue 'WU_USEWUSERVER_DISABLED') {
        if ($PSCmdlet.ShouldProcess($script:WUAUPolicyKey, 'UseWUServer = 1')) {
            Write-CMLog '[REMEDIATION] Setze UseWUServer auf 1...'
            try {
                if (-not (Test-Path $script:WUAUPolicyKey)) { New-Item -Path $script:WUAUPolicyKey -Force | Out-Null }
                Set-ItemProperty -Path $script:WUAUPolicyKey -Name 'UseWUServer' -Value 1 -Type DWord -Force -ErrorAction Stop
                Write-CMLog '   [+ OK] UseWUServer = 1 gesetzt (wird ggf. durch GPO überschrieben).' 1
                Add-RemediationResult -Action 'SetUseWUServer' -Succeeded $true -Message 'UseWUServer wurde im AU-Unterschlüssel auf 1 gesetzt.'
            }
            catch {
                Write-CMLog "   [-] UseWUServer konnte nicht gesetzt werden: $($_.Exception.Message)" 3
                Add-RemediationResult -Action 'SetUseWUServer' -Succeeded $false -Message $_.Exception.Message
            }
        }
    }
    if (Test-Issue 'WU_WSUS_CONFIG_INCOMPLETE') {
        Write-CMLog '[!] WSUS-Konfiguration ist unvollständig. WUServer und WUStatusServer müssen per GPO/MDM korrigiert werden; keine automatische Änderung.' 2
    }

    # ---- 2.5 Provisioning Mode beenden ------------------------------------
    if (Test-Issue 'CLIENT_PROVISIONING_MODE') {
        if ($PSCmdlet.ShouldProcess('ConfigMgr Client', 'Provisioning Mode deaktivieren')) {
            Write-CMLog '[REMEDIATION] Deaktiviere Provisioning Mode...'
            try {
                Invoke-CimMethod -Namespace 'root\ccm' -ClassName 'SMS_Client' `
                    -MethodName 'SetClientProvisioningMode' -Arguments @{ bEnable = $false } -ErrorAction Stop | Out-Null
                Set-ItemProperty -Path $script:CcmExecKey -Name 'ProvisioningMode' -Value 'false' -Force -ErrorAction Stop
                Write-CMLog '   [+ OK] Provisioning Mode beendet.' 1
            }
            catch {
                Write-CMLog "   [-] Provisioning Mode konnte nicht zurückgesetzt werden: $($_.Exception.Message)" 3
            }
        }
    }

    # ---- 2.6 WSUS-Client-Identität zurücksetzen ---------------------------
    if ($Mode -eq 'Deep' -and ((Test-Issue 'WU_SUSCLIENTID_MISSING') -or (Test-Issue 'WUA_COM_ERROR'))) {
        if ($PSCmdlet.ShouldProcess('WSUS Client-Identität', 'SUSClientId Reset')) {
            Write-CMLog '[REMEDIATION] Erneuere WSUS-Client-Identität...'
            $wuService    = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
            $wuWasRunning = $wuService -and $wuService.Status -eq 'Running'
            $resetOk      = $true

            if (-not $wuService) {
                Write-CMLog '   [-] WSUS-Client-Identität wird nicht verändert, weil wuauserv nicht vorhanden ist.' 3
                $resetOk = $false
            }
            elseif ($wuWasRunning -and -not (Stop-ServiceSafe -Name 'wuauserv')) {
                Write-CMLog '   [-] WSUS-Client-Identität wird nicht verändert, weil wuauserv nicht gestoppt werden konnte.' 3
                $resetOk = $false
            }

            if ($resetOk -and (Test-Path -LiteralPath $script:WUIdentityKey)) {
                foreach ($valueName in @('AccountDomainSid', 'PingID', 'SUSClientId', 'SUSClientIdValidation')) {
                    try {
                        $key = Get-Item -LiteralPath $script:WUIdentityKey -ErrorAction Stop
                        if ($key.GetValueNames() -contains $valueName) {
                            Remove-ItemProperty -LiteralPath $script:WUIdentityKey -Name $valueName -Force -ErrorAction Stop
                        }
                    }
                    catch {
                        Write-CMLog "   [-] $valueName konnte nicht entfernt werden: $($_.Exception.Message)" 3
                        $resetOk = $false
                    }
                }
            }

            if ($resetOk -and -not (Start-ServiceSafe -Name 'wuauserv')) {
                $resetOk = $false
            }

            if ($resetOk) {
                $uso = Join-Path $env:SystemRoot 'System32\UsoClient.exe'
                if (Test-Path -LiteralPath $uso) {
                    try {
                        foreach ($action in @('RefreshSettings', 'StartScan')) {
                            $refresh = Invoke-NativeCommand -FilePath $uso -Arguments @($action)
                            if ($refresh.ExitCode -ne 0) {
                                Write-CMLog "   [!] UsoClient $action lieferte Exit-Code $($refresh.ExitCode): $($refresh.Output)" 2
                            }
                        }
                    }
                    catch {
                        Write-CMLog "   [!] UsoClient-Aktualisierung fehlgeschlagen: $($_.Exception.Message)" 2
                    }
                }

                $newSusId = $null
                for ($attempt = 1; $attempt -le 6 -and -not $newSusId; $attempt++) {
                    Start-Sleep -Seconds 5
                    $newSusId = (Get-ItemProperty -Path $script:WUIdentityKey -Name 'SUSClientId' -ErrorAction SilentlyContinue).SUSClientId
                }
                if ($newSusId) {
                    Write-CMLog "   [+ OK] Client-Identität wurde neu erzeugt ($newSusId)." 1
                }
                else {
                    Write-CMLog '   [-] Nach 30 Sekunden wurde keine neue SUSClientId erzeugt.' 3
                    $resetOk = $false
                }
            }

            if (-not $wuWasRunning -and $wuService) {
                if (-not (Stop-ServiceSafe -Name 'wuauserv')) {
                    Write-CMLog '   [!] Der ursprüngliche Dienstzustand von wuauserv konnte nicht wiederhergestellt werden.' 2
                    $resetOk = $false
                }
            }

            if (-not $resetOk) {
                Write-CMLog '   [-] WSUS-Client-Identität konnte nicht vollständig zurückgesetzt werden.' 3
            }
            Add-RemediationResult -Action 'ResetWSUSClientIdentity' -Succeeded $resetOk `
                -Message $(if ($resetOk) { 'WSUS-Client-Identität wurde erneuert.' } else { 'WSUS-Client-Identität konnte nicht vollständig erneuert werden.' })
        }
    }

    # ---- 2.7 Tiefenreparatur der WU-Komponenten ---------------------------
    $deepSymptoms = @('WU_TS_COMPONENT_CORRUPT', 'WU_SOFTWAREDISTRIBUTION_EXCESSIVE', 'WUA_COM_ERROR')
    $hasDeepSymptom = @($deepSymptoms | Where-Object { Test-Issue $_ }).Count -gt 0
    $runDeepReset = $Mode -eq 'Deep' -and ($Force -or $hasDeepSymptom)

    if ($runDeepReset) {
        if ($PSCmdlet.ShouldProcess('Windows Update Komponenten', 'SoftwareDistribution/catroot2 zurücksetzen')) {
            Write-CMLog '[REMEDIATION] Setze Windows-Update-Komponenten zurück...'

            # trustedinstaller bewusst NICHT anfassen - der läuft bedarfsgesteuert.
            $stopOrder  = @('wuauserv', 'UsoSvc', 'bits', 'dosvc', 'cryptsvc')
            $startOrder = $stopOrder[($stopOrder.Count - 1)..0]   # in umgekehrter Reihenfolge starten
            $serviceWasRunning = @{}
            $allStopped        = $true
            $restoreOk         = $true
            $ok1               = $false
            $ok2               = $false

            foreach ($svcName in $stopOrder) {
                $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if ($svc) { $serviceWasRunning[$svcName] = ($svc.Status -eq 'Running') }
            }

            try {
                foreach ($svcName in $stopOrder) {
                    if ($serviceWasRunning[$svcName] -and -not (Stop-ServiceSafe -Name $svcName)) {
                        $allStopped = $false
                    }
                }

                if (-not $allStopped) {
                    Write-CMLog '   [-] Mindestens ein Update-Dienst konnte nicht gestoppt werden. Ordner werden nicht verändert.' 3
                }
                else {
                    Start-Sleep -Seconds 3
                    $ok1 = Rename-ResetFolder -Path "$env:SystemRoot\SoftwareDistribution"
                    $ok2 = Rename-ResetFolder -Path "$env:SystemRoot\System32\catroot2"
                }
            }
            finally {
                foreach ($svcName in $startOrder) {
                    if ($serviceWasRunning[$svcName] -and -not (Start-ServiceSafe -Name $svcName)) {
                        $restoreOk = $false
                    }
                }
            }

            # Hinweis: Der regsvr32-Block aus v0.1 wurde ersatzlos entfernt. Die dort
            # registrierten DLLs (mshtml, shdocvw, browseui, ole32, shell32 ...) stammen
            # aus der WSUS-3.0-Ära und bringen unter Windows 10/11 keinen Nutzen.

            if ($ok1 -and $ok2 -and $restoreOk) {
                $script:TSRepairSucceeded = $true
                $script:RebootPending = $true
                Write-CMLog '   [+ OK] WU-Komponenten zurückgesetzt. Update-Historie wurde dabei verworfen.' 1
                Add-RemediationResult -Action 'ResetWindowsUpdateCache' -Succeeded $true `
                    -Message "WU-Cache zurückgesetzt (Force=$($Force.IsPresent))."
            }
            else {
                Write-CMLog '   [!] Reset nicht oder nur teilweise erfolgreich - nach Neustart wiederholen.' 2
                Add-RemediationResult -Action 'ResetWindowsUpdateCache' -Succeeded $false `
                    -Message 'WU-Cache konnte nicht vollständig zurückgesetzt werden.'
            }
        }
    }
    elseif ($Mode -eq 'Deep') {
        Write-CMLog '[i] Kein passendes Deep-Symptom erkannt. WU-Cache-Reset wird ohne -Force nicht ausgeführt.' 1
    }
    elseif ($hasDeepSymptom) {
        Write-CMLog '[!] Ein Deep-Symptom wurde erkannt. Für die Tiefenbehandlung erneut mit -Mode Deep ausführen.' 2
    }

    # ---- 2.8 Machine Policy Reset (nur bei Policy-nahen Symptomen) --------
    $policyIssues = @('CLIENT_PROVISIONING_MODE', 'CCM_SERVICE_STOPPED', 'CCM_WMI_UNAVAILABLE', 'WMI_CORRUPT')
    $needsPolicyReset = $policyIssues | Where-Object { Test-Issue $_ }

    if ($needsPolicyReset) {
        if ($PSCmdlet.ShouldProcess('ConfigMgr Machine Policy', 'ResetPolicy(uFlags=1)')) {
            Write-CMLog '[REMEDIATION] Setze ConfigMgr Machine Policy zurück (Purge + Full Refresh)...'
            $done = $false
            try {
                # v0.1 nutzte "TargetPolicyType" - die Methodensignatur lautet ResetPolicy(uint32 uFlags).
                Invoke-CimMethod -Namespace 'root\ccm' -ClassName 'SMS_Client' `
                    -MethodName 'ResetPolicy' -Arguments @{ uFlags = [uint32]1 } -ErrorAction Stop | Out-Null
                Write-CMLog '   [+ OK] SMS_Client.ResetPolicy(1) ausgeführt.' 1
                $done = $true
            }
            catch {
                Write-CMLog "   [!] CIM-Aufruf fehlgeschlagen ($($_.Exception.Message)) - Fallback auf WMI..." 2
            }
            if (-not $done) {
                try {
                    ([wmiclass]'ROOT\ccm:SMS_Client').ResetPolicy(1) | Out-Null
                    Write-CMLog '   [+ OK] ResetPolicy(1) über WMI ausgeführt.' 1
                    $done = $true
                }
                catch {
                    Write-CMLog "   [-] ResetPolicy endgültig fehlgeschlagen: $($_.Exception.Message)" 3
                }
            }
            if ($done) { $script:PolicyWasReset = $true }
        }
    }
    else {
        Write-CMLog '[i] Kein Policy-nahes Symptom - Machine-Policy-Reset wird bewusst nicht ausgeführt.' 1
    }
}

# ==========================================================================
# PHASE 3: EVALUATION
# ==========================================================================

function Invoke-Evaluation {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-CMLog '--- PHASE 3: EVALUATION (ConfigMgr-Zyklen) ---' 1

    $ccm = Get-Service -Name 'CcmExec' -ErrorAction SilentlyContinue
    if (-not $ccm -or $ccm.Status -ne 'Running') {
        Write-CMLog '[-] CcmExec läuft nicht - Zyklen können nicht getriggert werden. Phase 3 übersprungen.' 3
        return
    }

    # Nach einem Policy-Purge braucht der Client Zeit, die Policy neu zu laden.
    $initialWait = if ($script:PolicyWasReset) { 60 } else { 5 }

    # Reihenfolge ist fachlich entscheidend:
    #   021 Policy holen -> 022 Policy auswerten -> 113 Scan by Update Source
    #   -> 108 Software Updates Assignments (Deployment) Evaluation -> 001 Inventory
    # In v0.1 waren 108 und 113 vertauscht benannt UND in falscher Reihenfolge.
    $schedules = @(
        [pscustomobject]@{ Id = '{00000000-0000-0000-0000-000000000021}'; Name = 'Machine Policy Retrieval Cycle';                   WaitAfter = $initialWait }
        [pscustomobject]@{ Id = '{00000000-0000-0000-0000-000000000022}'; Name = 'Machine Policy Evaluation Cycle';                  WaitAfter = 30 }
        [pscustomobject]@{ Id = '{00000000-0000-0000-0000-000000000113}'; Name = 'Software Update Scan Cycle (Scan by Update Source)'; WaitAfter = 60 }
        [pscustomobject]@{ Id = '{00000000-0000-0000-0000-000000000108}'; Name = 'Software Updates Deployment Evaluation Cycle';     WaitAfter = 10 }
        [pscustomobject]@{ Id = '{00000000-0000-0000-0000-000000000001}'; Name = 'Hardware Inventory Cycle';                         WaitAfter = 0 }
    )

    foreach ($sched in $schedules) {
        if (-not $PSCmdlet.ShouldProcess("ConfigMgr-Zeitplan $($sched.Id)", $sched.Name)) {
            continue
        }
        Write-CMLog "[EVALUATION] Triggere $($sched.Name) $($sched.Id)..."
        $triggered = $false
        try {
            $result = Invoke-CimMethod -Namespace 'root\ccm' -ClassName 'SMS_Client' `
                -MethodName 'TriggerSchedule' -Arguments @{ sScheduleID = $sched.Id } -ErrorAction Stop
            $returnValue = if ($null -ne $result.ReturnValue) { [int]$result.ReturnValue } else { 0 }
            $triggered = $returnValue -eq 0
            if (-not $triggered) {
                Add-Issue 'CCM_SCHEDULE_TRIGGER_FAILED' "$($sched.Name) lieferte ReturnValue $returnValue."
            }
        }
        catch {
            Write-CMLog "   [!] CIM-Trigger fehlgeschlagen ($($_.Exception.Message)) - Fallback auf WMI..." 2
            try {
                $result = Invoke-WmiMethod -Namespace 'root\ccm' -Class 'SMS_Client' -Name 'TriggerSchedule' `
                    -ArgumentList $sched.Id -ErrorAction Stop
                $returnValue = if ($null -ne $result.ReturnValue) { [int]$result.ReturnValue } else { 0 }
                $triggered = $returnValue -eq 0
                if (-not $triggered) {
                    Add-Issue 'CCM_SCHEDULE_TRIGGER_FAILED' "$($sched.Name) lieferte ReturnValue $returnValue."
                }
            }
            catch {
                Write-CMLog "   [-] Trigger endgültig fehlgeschlagen: $($_.Exception.Message)" 3
                Add-Issue 'CCM_SCHEDULE_TRIGGER_FAILED' "$($sched.Name) konnte nicht getriggert werden: $($_.Exception.Message)"
            }
        }

        if ($triggered) {
            Write-CMLog '   [+ OK] Trigger abgesetzt.' 1
            Add-RemediationResult -Action "TriggerSchedule:$($sched.Id)" -Succeeded $true `
                -Message "$($sched.Name) wurde vom Client angenommen."
            if ($sched.WaitAfter -gt 0) {
                Write-CMLog "   [i] Warte $($sched.WaitAfter)s, damit der Client den Zyklus verarbeiten kann..." 1
                Start-Sleep -Seconds $sched.WaitAfter
            }
        }
        else {
            Add-RemediationResult -Action "TriggerSchedule:$($sched.Id)" -Succeeded $false `
                -Message "$($sched.Name) wurde vom Client nicht angenommen."
        }
    }
}

# ==========================================================================
# HAUPTPROGRAMM
# ==========================================================================

$script:WUPolicyKey      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$script:WUAUPolicyKey    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$script:WUIdentityKey    = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate'
$script:CcmExecKey       = 'HKLM:\SOFTWARE\Microsoft\CCM\CcmExec'
$script:DisabledServices = @()
$script:PolicyWasReset   = $false
$script:TSRepairSucceeded = $false

# Starttypen gemäß Windows-10/11-Standard. Bitte gegen den eigenen
# Sicherheits-Baseline-Stand prüfen und ggf. anpassen.
$script:WuServiceDefaults = [ordered]@{
    'wuauserv' = 'Manual'        # Windows Update
    'UsoSvc'   = 'Automatic'     # Update Orchestrator
    'bits'     = 'Manual'        # Background Intelligent Transfer
    'dosvc'    = 'DelayedAuto'   # Delivery Optimization
}

$exitCode = 2
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

try {
    Initialize-Log
    Write-CMLog '===========================================================' 1
    Write-CMLog "=== Start CM Agent Health v0.4 auf $env:COMPUTERNAME ===" 1
    Write-CMLog "=== Modus: $Mode$(if ($Force) { ' [Force]' })$(if ($WhatIfPreference) { ' [WhatIf]' }) ===" 1
    Write-CMLog "=== PowerShell $($PSVersionTable.PSVersion) | OS $([System.Environment]::OSVersion.Version)" 1

    Invoke-Diagnostics
    $initialIssues = @($script:DetectedIssues)
    foreach ($issueId in $script:IssueDetails.Keys) {
        $script:InitialIssueDetails[$issueId] = $script:IssueDetails[$issueId]
    }

    if ($Mode -eq 'Evaluate') {
        Write-CMLog '[i] Modus Evaluate: Remediation und ConfigMgr-Zyklen werden übersprungen.' 1
    }
    else {
        Invoke-Remediation

        if (-not $WhatIfPreference) {
            Start-Sleep -Seconds 5
            Invoke-Diagnostics -IsRecheck

            $fixed     = $initialIssues | Where-Object { -not (Test-Issue $_) }
            $remaining = @($script:DetectedIssues)

            if ($fixed)     { Write-CMLog "[+] Behoben: $($fixed -join ', ')" 1 }
            if ($remaining) { Write-CMLog "[-] Weiterhin offen: $($remaining -join ', ')" 3 }
        }

        Invoke-Evaluation
    }

    # ---- Zusammenfassung ---------------------------------------------------
    $stopwatch.Stop()
    $failedRemediations = @($script:RemediationResults | Where-Object { -not $_.Succeeded })
    $isCompliant = $script:DetectedIssues.Count -eq 0 -and $failedRemediations.Count -eq 0
    $summary = [ordered]@{
        ComputerName    = $env:COMPUTERNAME
        ScriptVersion   = '0.4'
        Timestamp       = (Get-Date).ToString('o')
        Mode            = $Mode
        Force           = $Force.IsPresent
        DurationMinutes = [math]::Round($stopwatch.Elapsed.TotalMinutes, 1)
        InitialIssues   = @($initialIssues)
        InitialIssueDetails = $script:InitialIssueDetails
        RemainingIssues = @($script:DetectedIssues)
        RemainingIssueDetails = $script:IssueDetails
        WUConfiguration = $script:WUConfiguration
        SoftwareDistributionEntries = $script:SoftwareDistributionEntryCount
        SoftwareDistributionThreshold = $SoftwareDistributionEntryThreshold
        SoftwareDistributionCountCapped = ($script:SoftwareDistributionEntryCount -gt $SoftwareDistributionEntryThreshold)
        RemediationResults = @($script:RemediationResults)
        RebootPending   = $script:RebootPending
        Compliant       = $isCompliant
    }

    Write-CMLog "=== Ergebnis: $(if ($summary.Compliant) { 'COMPLIANT' } else { 'NON-COMPLIANT' }) | Dauer: $($summary.DurationMinutes) min | Neustart nötig: $($script:RebootPending) ===" $(if ($summary.Compliant) { 1 } else { 2 })
    Write-CMLog '=== CM Agent Health v0.4 beendet ===' 1

    # Maschinenlesbare Ausgabe für "Skripte ausführen" / Configuration Items.
    Write-Output ($summary | ConvertTo-Json -Compress -Depth 4)

    if (-not $summary.Compliant)             { $exitCode = 1 }
    elseif ($script:RebootPending)           { $exitCode = 3010 }
    else                                     { $exitCode = 0 }
}
catch {
    try { Write-CMLog "[FATAL] Unerwarteter Abbruch: $($_.Exception.Message)" 3 } catch { }
    Write-Error $_
    $exitCode = 2
}

exit $exitCode
