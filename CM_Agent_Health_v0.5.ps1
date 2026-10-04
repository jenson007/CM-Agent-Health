<#
.SYNOPSIS
    ConfigMgr (SCCM) Client- & Windows-Update-Diagnose, Remediation und Evaluation.

.DESCRIPTION
    Version 0.5 - ergänzt Aktualitätsprüfungen und abgesicherte Tiefenreparatur.

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

    Änderungen in v0.5:
      - Alter des letzten installierten Windows-Updates wird geprüft
      - Alter der Microsoft-Defender-Signaturen wird geprüft
      - beide Altersgrenzen sind parametrierbar (Standard: 30 bzw. 5 Tage)
      - Light stößt bei veralteten Ständen gezielte Aktualisierungen an
      - Phase 1 enthält eine rein lesende SFC-Prüfung
      - Deep deaktiviert Update-Dienste temporär und restauriert den Ausgangszustand

.PARAMETER Mode
    Evaluate: nur prüfen. Light: risikoarme und symptombezogene Behandlung.
    Deep: wie Light und zusätzlich WU-Cache-Reset bei passendem Symptom.

.PARAMETER Force
    Erzwingt den WU-Cache-Reset ohne passenden Befund. Nur mit -Mode Deep.

.PARAMETER DeepScan
    Nutzt in Phase 1 DISM /ScanHealth statt /CheckHealth (deutlich gründlicher,
    aber mehrere Minuten Laufzeit).

.PARAMETER WindowsUpdateMaxAgeDays
    Maximales Alter des letzten installierten Windows-Betriebssystemupdates.
    Standard: 30 Tage.

.PARAMETER DefenderSignatureMaxAgeDays
    Maximales Alter der Microsoft-Defender-Signaturen. Standard: 5 Tage.

.PARAMETER SkipSfcValidation
    Überspringt die standardmäßig ausgeführte, rein lesende Prüfung
    "sfc.exe /verifyonly".

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
    .\CM_Agent_Health_v0.5.ps1 -Mode Evaluate
    Nur Diagnose, kein Eingriff.

.EXAMPLE
    .\CM_Agent_Health_v0.5.ps1 -Mode Light -WhatIf
    Zeigt, welche Reparaturen ausgeführt würden, ohne sie durchzuführen.

.EXAMPLE
    .\CM_Agent_Health_v0.5.ps1 -Mode Deep
    Tiefenreparatur nur bei einem passenden Symptom.

.EXAMPLE
    .\CM_Agent_Health_v0.5.ps1 -Mode Deep -Force
    Erzwingt den WU-Cache-Reset unabhängig vom Diagnoseergebnis.

.NOTES
    Version : 0.5
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
#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Evaluate', 'Light', 'Deep')][string]$Mode = 'Evaluate',
    [switch]$Force,
    [switch]$DeepScan,
    [ValidateRange(1, 365)][int]$WindowsUpdateMaxAgeDays = 30,
    [ValidateRange(1, 90)][int]$DefenderSignatureMaxAgeDays = 5,
    [switch]$SkipSfcValidation,
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
$script:ScriptName      = 'CM_Agent_Health_v0.5.ps1'
$script:SoftwareDistributionEntryCount = 0
$script:WUConfiguration = [ordered]@{}
$script:WindowsUpdateAge = $null
$script:DefenderSignatureAge = $null
$script:SfcValidation = [ordered]@{}
$script:ServiceStateJournalPath = Join-Path $env:ProgramData 'CM_AgentHealth\ServiceState.json'

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

function Get-LastWindowsUpdateInstall {
    $candidates = [System.Collections.Generic.List[object]]::new()

    try {
        foreach ($hotfix in @(Get-HotFix -ErrorAction Stop)) {
            if (-not $hotfix.InstalledOn) { continue }
            [void]$candidates.Add([pscustomobject]@{
                InstalledOn = [datetime]$hotfix.InstalledOn
                Title       = "$($hotfix.Description) $($hotfix.HotFixID)".Trim()
                Source      = 'Get-HotFix'
            })
        }
    }
    catch {
        Write-CMLog "[!] Get-HotFix konnte nicht ausgewertet werden: $($_.Exception.Message)" 2
    }

    $session = $null
    $searcher = $null
    try {
        $session = New-Object -ComObject 'Microsoft.Update.Session'
        $searcher = $session.CreateUpdateSearcher()
        $historyCount = $searcher.GetTotalHistoryCount()
        $pageSize = 200
        $titlePattern = '(?i)(cumulative update|kumulatives update|security update for microsoft windows|sicherheitsupdate für microsoft windows|update for microsoft windows|update für microsoft windows|servicing stack update|wartungsstapelupdate)'
        $excludePattern = '(?i)(defender|office|visual studio|sql server|driver|treiber|malicious software removal|tool zum entfernen)'

        for ($offset = 0; $offset -lt $historyCount; $offset += $pageSize) {
            $count = [math]::Min($pageSize, $historyCount - $offset)
            $page = $searcher.QueryHistory($offset, $count)
            $matchFound = $false
            foreach ($entry in @($page)) {
                # Operation 1 = Installation, ResultCode 2 = erfolgreich.
                if ($entry.Operation -eq 1 -and $entry.ResultCode -eq 2 -and
                    $entry.Title -match $titlePattern -and $entry.Title -notmatch $excludePattern) {
                    [void]$candidates.Add([pscustomobject]@{
                        InstalledOn = [datetime]$entry.Date
                        Title       = [string]$entry.Title
                        Source      = 'Windows Update Agent'
                    })
                    $matchFound = $true
                    break
                }
            }
            # QueryHistory liefert die neuesten Einträge zuerst.
            if ($matchFound) { break }
        }
    }
    catch {
        Write-CMLog "[!] WUA-Installationshistorie konnte nicht ausgewertet werden: $($_.Exception.Message)" 2
    }
    finally {
        if ($searcher) {
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($searcher) } catch { }
        }
        if ($session) {
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($session) } catch { }
        }
    }

    $latest = $candidates | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if (-not $latest) { return $null }

    return [pscustomobject]@{
        InstalledOn = $latest.InstalledOn.ToString('o')
        AgeDays      = [int][math]::Floor(((Get-Date) - $latest.InstalledOn).TotalDays)
        Title        = $latest.Title
        Source       = $latest.Source
    }
}

function Get-DefenderSignatureStatus {
    $cmd = Get-Command -Name 'Get-MpComputerStatus' -ErrorAction SilentlyContinue
    if (-not $cmd) {
        return [pscustomobject]@{ Applicable = $false; State = 'NotInstalled'; UpdatedOn = $null; AgeDays = $null; ProductStatus = $null }
    }

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $runningMode = "$($status.AMRunningMode)"
        $applicable = $runningMode -match '(?i)normal|passive|edr' -or $status.AntivirusEnabled -or $status.AMServiceEnabled
        if (-not $applicable) {
            return [pscustomobject]@{ Applicable = $false; State = 'Inactive'; UpdatedOn = $null; AgeDays = $null; ProductStatus = $runningMode }
        }

        $updatedOn = $status.AntivirusSignatureLastUpdated
        if (-not $updatedOn) {
            return [pscustomobject]@{ Applicable = $true; State = 'Unknown'; UpdatedOn = $null; AgeDays = $null; ProductStatus = $runningMode }
        }

        return [pscustomobject]@{
            Applicable  = $true
            State       = 'Available'
            UpdatedOn   = ([datetime]$updatedOn).ToString('o')
            AgeDays     = [int][math]::Floor(((Get-Date) - [datetime]$updatedOn).TotalDays)
            ProductStatus = $runningMode
        }
    }
    catch {
        return [pscustomobject]@{ Applicable = $true; State = 'Error'; UpdatedOn = $null; AgeDays = $null; ProductStatus = $_.Exception.Message }
    }
}

function Invoke-SfcValidation {
    try {
        $result = Invoke-NativeCommand -FilePath 'sfc.exe' -Arguments @('/verifyonly')
        $state = if ($result.Output -match '(?i)did not find any integrity violations|keine integritätsverletzungen gefunden') {
            'Healthy'
        }
        elseif ($result.Output -match '(?i)found corrupt files|beschädigte dateien gefunden|integrity violations|integritätsverletzungen') {
            'Corrupt'
        }
        else {
            'Indeterminate'
        }
        return [pscustomobject]@{
            State    = $state
            ExitCode = $result.ExitCode
            Output   = $result.Output
        }
    }
    catch {
        return [pscustomobject]@{ State = 'Error'; ExitCode = $null; Output = $_.Exception.Message }
    }
}

function Get-ServiceStateSnapshot {
    param([Parameter(Mandatory)][string[]]$Names)

    $snapshot = foreach ($name in $Names) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        if ([string]$svc.Status -notin @('Running', 'Stopped')) {
            throw "Dienst $name befindet sich im Übergangszustand '$($svc.Status)'; sichere Aufnahme nicht möglich."
        }
        $delayed = $false
        try {
            $delayed = [bool](Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$name" `
                -Name DelayedAutoStart -ErrorAction SilentlyContinue).DelayedAutoStart
        }
        catch { }
        [pscustomobject]@{
            Name             = $name
            State            = [string]$svc.Status
            StartMode        = switch ([string]$svc.StartType) {
                'Automatic' { 'Auto' }
                'Manual'    { 'Manual' }
                'Disabled'  { 'Disabled' }
                default     { throw "Unbekannter Starttyp '$($svc.StartType)' für $name." }
            }
            DelayedAutoStart = $delayed
        }
    }
    return @($snapshot)
}

function Set-ServiceStartupExact {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Auto', 'Manual', 'Disabled')][string]$StartMode,
        [bool]$DelayedAutoStart = $false
    )

    try {
        switch ($StartMode) {
            'Auto' {
                $scStart = if ($DelayedAutoStart) { 'delayed-auto' } else { 'auto' }
                & sc.exe config $Name start= $scStart | Out-Null
            }
            'Manual'   { & sc.exe config $Name start= demand | Out-Null }
            'Disabled' { & sc.exe config $Name start= disabled | Out-Null }
        }
        if ($LASTEXITCODE -ne 0) { throw "sc.exe config lieferte Exit-Code $LASTEXITCODE" }

        $current = Get-Service -Name $Name -ErrorAction Stop
        $expectedStartType = if ($StartMode -eq 'Auto') { 'Automatic' } else { $StartMode }
        if ([string]$current.StartType -ne $expectedStartType) {
            throw "Starttyp ist '$($current.StartType)' statt '$expectedStartType'."
        }
        if ($StartMode -eq 'Auto') {
            $currentDelayed = [bool](Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" `
                -Name DelayedAutoStart -ErrorAction SilentlyContinue).DelayedAutoStart
            if ($currentDelayed -ne $DelayedAutoStart) {
                throw "DelayedAutoStart ist '$currentDelayed' statt '$DelayedAutoStart'."
            }
        }
        return $true
    }
    catch {
        Write-CMLog "   [-] Starttyp von $Name konnte nicht auf $StartMode gesetzt werden: $($_.Exception.Message)" 3
        return $false
    }
}

function Save-ServiceStateJournal {
    param([Parameter(Mandatory)][object[]]$Snapshot)
    $directory = Split-Path -Path $script:ServiceStateJournalPath -Parent
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    $temporaryPath = "$($script:ServiceStateJournalPath).tmp"
    ConvertTo-Json -InputObject @($Snapshot) -Depth 3 |
        Set-Content -LiteralPath $temporaryPath -Encoding UTF8 -Force
    Move-Item -LiteralPath $temporaryPath -Destination $script:ServiceStateJournalPath -Force
}

function Restore-ServiceStateSnapshot {
    param([Parameter(Mandatory)][object[]]$Snapshot)

    $allowedServices = @('wuauserv', 'UsoSvc', 'bits', 'dosvc', 'cryptsvc')
    $seenServices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($state in $Snapshot) {
        if ($state.Name -notin $allowedServices -or
            $state.StartMode -notin @('Auto', 'Manual', 'Disabled') -or
            $state.State -notin @('Running', 'Stopped') -or
            $state.DelayedAutoStart -isnot [bool] -or
            -not $seenServices.Add([string]$state.Name)) {
            Write-CMLog '   [-] Dienstzustandsjournal enthält ungültige oder doppelte Einträge; Wiederherstellung abgebrochen.' 3
            return $false
        }
    }

    $succeeded = $true
    foreach ($state in $Snapshot) {
        if (-not (Set-ServiceStartupExact -Name $state.Name -StartMode $state.StartMode `
            -DelayedAutoStart ([bool]$state.DelayedAutoStart))) {
            $succeeded = $false
        }
    }

    $restoreOrder = @($Snapshot)
    [array]::Reverse($restoreOrder)
    foreach ($state in $restoreOrder) {
        if ($state.State -eq 'Running') {
            if (-not (Start-ServiceSafe -Name $state.Name)) { $succeeded = $false }
        }
        else {
            if (-not (Stop-ServiceSafe -Name $state.Name)) { $succeeded = $false }
        }
    }

    foreach ($state in $Snapshot) {
        $current = Get-Service -Name $state.Name -ErrorAction SilentlyContinue
        $expectedStartType = if ($state.StartMode -eq 'Auto') { 'Automatic' } else { $state.StartMode }
        if (-not $current -or [string]$current.StartType -ne $expectedStartType -or
            [string]$current.Status -ne $state.State) {
            $succeeded = $false
        }
        if ($current -and $state.StartMode -eq 'Auto') {
            $currentDelayed = [bool](Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($state.Name)" `
                -Name DelayedAutoStart -ErrorAction SilentlyContinue).DelayedAutoStart
            if ($currentDelayed -ne [bool]$state.DelayedAutoStart) { $succeeded = $false }
        }
    }

    if ($succeeded) {
        Remove-Item -LiteralPath $script:ServiceStateJournalPath -Force -ErrorAction SilentlyContinue
    }
    return $succeeded
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

    # ---- 1.2b Systemdateien (SFC) ------------------------------------------
    if ($SkipSfcValidation) {
        $script:SfcValidation = [ordered]@{ State = 'Skipped'; ExitCode = $null }
        Write-CMLog '[1.2b] SFC-Prüfung wurde per -SkipSfcValidation übersprungen.' 2
    }
    else {
        Write-CMLog '[1.2b] Prüfe geschützte Systemdateien (SFC /verifyonly)...'
        $sfcCheck = Invoke-SfcValidation
        $script:SfcValidation = [ordered]@{
            State    = $sfcCheck.State
            ExitCode = $sfcCheck.ExitCode
        }
        switch ($sfcCheck.State) {
            'Healthy' { Write-CMLog '[+ OK] SFC meldet keine Integritätsverletzungen.' 1 }
            'Corrupt' { Add-Issue 'SFC_CORRUPT' 'SFC hat Integritätsverletzungen in geschützten Systemdateien festgestellt.' }
            'Error'   { Add-Issue 'SFC_CHECK_FAILED' "SFC-Prüfung konnte nicht ausgeführt werden: $($sfcCheck.Output)" }
            default   { Add-Issue 'SFC_CHECK_INDETERMINATE' "SFC-Ausgabe konnte nicht eindeutig bewertet werden (Exit $($sfcCheck.ExitCode)). CBS.log prüfen." }
        }
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
        if ($wuSearcher) {
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($wuSearcher) } catch { }
        }
        if ($wuSession) {
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($wuSession) } catch { }
        }
    }

    # ---- 1.3b Letztes Windows-Betriebssystemupdate ------------------------
    Write-CMLog "[1.3b] Prüfe letztes installiertes Windows-Update (Grenzwert: $WindowsUpdateMaxAgeDays Tage)..."
    try {
        $script:WindowsUpdateAge = Get-LastWindowsUpdateInstall
        if (-not $script:WindowsUpdateAge) {
            Add-Issue 'WINDOWS_UPDATE_AGE_UNKNOWN' 'Kein erfolgreich installiertes Windows-Betriebssystemupdate konnte ermittelt werden.'
        }
        elseif ([datetime]$script:WindowsUpdateAge.InstalledOn -le (Get-Date).AddDays(-$WindowsUpdateMaxAgeDays)) {
            Add-Issue 'WINDOWS_UPDATES_STALE' `
                "Letztes Windows-Update ist $($script:WindowsUpdateAge.AgeDays) Tage alt ($($script:WindowsUpdateAge.InstalledOn), $($script:WindowsUpdateAge.Title))."
        }
        else {
            Write-CMLog "[+ OK] Letztes Windows-Update vor $($script:WindowsUpdateAge.AgeDays) Tagen: $($script:WindowsUpdateAge.Title)." 1
        }
    }
    catch {
        Add-Issue 'WINDOWS_UPDATE_AGE_UNKNOWN' "Alter des letzten Windows-Updates konnte nicht ermittelt werden: $($_.Exception.Message)"
    }

    # ---- 1.3c Microsoft-Defender-Signaturen -------------------------------
    Write-CMLog "[1.3c] Prüfe Defender-Signaturen (Grenzwert: $DefenderSignatureMaxAgeDays Tage)..."
    $script:DefenderSignatureAge = Get-DefenderSignatureStatus
    if (-not $script:DefenderSignatureAge.Applicable) {
        Write-CMLog "[i] Microsoft Defender ist nicht aktiv/anwendbar (Status: $($script:DefenderSignatureAge.State)); keine Altersbewertung." 1
    }
    elseif ($script:DefenderSignatureAge.State -ne 'Available') {
        Add-Issue 'DEFENDER_SIGNATURE_AGE_UNKNOWN' `
            "Defender-Signaturstand ist nicht ermittelbar (Status: $($script:DefenderSignatureAge.State), Produktstatus: $($script:DefenderSignatureAge.ProductStatus))."
    }
    elseif ([datetime]$script:DefenderSignatureAge.UpdatedOn -lt (Get-Date).AddDays(-$DefenderSignatureMaxAgeDays)) {
        Add-Issue 'DEFENDER_SIGNATURES_STALE' `
            "Defender-Signaturen sind $($script:DefenderSignatureAge.AgeDays) Tage alt (Stand: $($script:DefenderSignatureAge.UpdatedOn))."
    }
    else {
        Write-CMLog "[+ OK] Defender-Signaturen sind $($script:DefenderSignatureAge.AgeDays) Tage alt." 1
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
    if (Test-Path -LiteralPath $script:ServiceStateJournalPath) {
        Add-Issue 'WU_SERVICE_RESTORE_PENDING' "Ein Wiederherstellungsjournal liegt unter '$($script:ServiceStateJournalPath)'. Ein früherer Deep-Lauf konnte Dienstzustände nicht vollständig restaurieren."
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

    if (Test-Issue 'WU_SERVICE_RESTORE_PENDING') {
        if ($PSCmdlet.ShouldProcess($script:ServiceStateJournalPath, 'Update-Dienstzustände aus Wiederherstellungsjournal restaurieren')) {
            Write-CMLog '[REMEDIATION] Restauriere Dienstzustände aus einem früheren, unvollständigen Deep-Lauf...'
            try {
                $pendingSnapshot = @(Get-Content -LiteralPath $script:ServiceStateJournalPath -Raw -ErrorAction Stop | ConvertFrom-Json)
                $restored = Restore-ServiceStateSnapshot -Snapshot $pendingSnapshot
                Add-RemediationResult -Action 'RestorePendingServiceState' -Succeeded $restored `
                    -Message $(if ($restored) { 'Dienstzustände aus Wiederherstellungsjournal restauriert.' } else { 'Dienstzustände konnten nicht vollständig restauriert werden; Journal bleibt erhalten.' })
            }
            catch {
                Write-CMLog "   [-] Wiederherstellungsjournal konnte nicht verarbeitet werden: $($_.Exception.Message)" 3
                Add-RemediationResult -Action 'RestorePendingServiceState' -Succeeded $false -Message $_.Exception.Message
            }
        }
    }

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
    $needsDismRepair = Test-Issue 'DISM_CORRUPT'
    $needsSfcRepair = Test-Issue 'SFC_CORRUPT'
    if ($Mode -eq 'Deep' -and ($needsDismRepair -or $needsSfcRepair)) {
        if ($PSCmdlet.ShouldProcess('Windows-Komponenten und Systemdateien', 'DISM RestoreHealth und/oder SFC /scannow')) {
            $repairOk = $true
            if ($needsDismRepair) {
                Write-CMLog '[REMEDIATION] Führe DISM RestoreHealth aus (kann 15-45 Minuten dauern)...'
                try {
                    $repair = Repair-WindowsImage -Online -RestoreHealth -NoRestart -ErrorAction Stop
                    Write-CMLog "   [+ OK] DISM RestoreHealth abgeschlossen (RestartNeeded: $($repair.RestartNeeded))." 1
                    if ($repair.RestartNeeded) { $script:RebootPending = $true }
                }
                catch {
                    $repairOk = $false
                    Write-CMLog "   [-] DISM RestoreHealth fehlgeschlagen: $($_.Exception.Message)" 3
                }
            }

            Write-CMLog '[REMEDIATION] Führe SFC /scannow aus...'
            try {
                $sfc = Invoke-NativeCommand -FilePath 'sfc.exe' -Arguments @('/scannow')
                if ($sfc.ExitCode -eq 0) {
                    Write-CMLog '   [+ OK] SFC abgeschlossen (Exit 0).' 1
                }
                else {
                    $repairOk = $false
                    Write-CMLog "   [!] SFC beendet mit Exit-Code $($sfc.ExitCode) - CBS.log prüfen." 2
                }
            }
            catch {
                $repairOk = $false
                Write-CMLog "   [-] SFC fehlgeschlagen: $($_.Exception.Message)" 3
            }
            Add-RemediationResult -Action 'RepairSystemFiles' -Succeeded $repairOk `
                -Message $(if ($repairOk) { 'DISM/SFC-Reparatur wurde abgeschlossen.' } else { 'DISM/SFC-Reparatur war nicht vollständig erfolgreich.' })
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

    # ---- 2.4b Defender-Signaturen aktualisieren ----------------------------
    if ((Test-Issue 'DEFENDER_SIGNATURES_STALE') -or (Test-Issue 'DEFENDER_SIGNATURE_AGE_UNKNOWN')) {
        if ($PSCmdlet.ShouldProcess('Microsoft Defender', 'Signaturen aktualisieren')) {
            Write-CMLog '[REMEDIATION] Aktualisiere Microsoft-Defender-Signaturen...'
            try {
                Update-MpSignature -ErrorAction Stop | Out-Null
                Write-CMLog '   [+ OK] Defender-Signaturaktualisierung wurde ausgeführt.' 1
                Add-RemediationResult -Action 'UpdateDefenderSignatures' -Succeeded $true `
                    -Message 'Update-MpSignature wurde erfolgreich ausgeführt.'
            }
            catch {
                Write-CMLog "   [-] Defender-Signaturaktualisierung fehlgeschlagen: $($_.Exception.Message)" 3
                Add-RemediationResult -Action 'UpdateDefenderSignatures' -Succeeded $false -Message $_.Exception.Message
            }
        }
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
    $deepSymptoms = @('WU_TS_COMPONENT_CORRUPT', 'WU_SOFTWAREDISTRIBUTION_EXCESSIVE', 'WUA_COM_ERROR', 'WINDOWS_UPDATES_STALE')
    $hasDeepSymptom = @($deepSymptoms | Where-Object { Test-Issue $_ }).Count -gt 0
    $runDeepReset = $Mode -eq 'Deep' -and ($Force -or $hasDeepSymptom)

    if ($runDeepReset) {
        if ($PSCmdlet.ShouldProcess('Windows Update Komponenten', 'SoftwareDistribution/catroot2 zurücksetzen')) {
            Write-CMLog '[REMEDIATION] Setze Windows-Update-Komponenten zurück...'

            # Temporäres Deaktivieren verhindert, dass Monitoring die Dienste
            # während des Ordnerwechsels erneut startet.
            $stopOrder = @('wuauserv', 'UsoSvc', 'bits', 'dosvc', 'cryptsvc')
            $snapshot = Get-ServiceStateSnapshot -Names $stopOrder
            $allControlled = $snapshot.Count -gt 0
            $journalSaved = $false
            $restoreOk = $false
            $ok1 = $false
            $ok2 = $false

            try {
                if (-not $allControlled) {
                    Write-CMLog '   [-] Kein Dienstzustand konnte aufgenommen werden. Der WU-Cache wird nicht verändert.' 3
                }
                else {
                    Save-ServiceStateJournal -Snapshot $snapshot
                    $journalSaved = $true

                    foreach ($state in $snapshot) {
                        if (-not (Set-ServiceStartupExact -Name $state.Name -StartMode 'Disabled')) {
                            $allControlled = $false
                        }
                        if (-not (Stop-ServiceSafe -Name $state.Name)) {
                            $allControlled = $false
                        }
                    }

                    if (-not $allControlled) {
                        Write-CMLog '   [-] Mindestens ein Update-Dienst konnte nicht deaktiviert und gestoppt werden. Ordner werden nicht verändert.' 3
                    }
                    else {
                        Start-Sleep -Seconds 3
                        $ok1 = Rename-ResetFolder -Path "$env:SystemRoot\SoftwareDistribution"
                        $ok2 = Rename-ResetFolder -Path "$env:SystemRoot\System32\catroot2"
                    }
                }
            }
            catch {
                $allControlled = $false
                Write-CMLog "   [-] WU-Cache-Reset wurde sicher abgebrochen: $($_.Exception.Message)" 3
            }
            finally {
                if ($journalSaved) {
                    $restoreOk = Restore-ServiceStateSnapshot -Snapshot $snapshot
                    if (-not $restoreOk) {
                        Write-CMLog "   [-] Ursprüngliche Dienstzustände konnten nicht vollständig restauriert werden. Journal bleibt erhalten: $($script:ServiceStateJournalPath)" 3
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
    Write-CMLog "=== Start CM Agent Health v0.5 auf $env:COMPUTERNAME ===" 1
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
        ScriptVersion   = '0.5'
        Timestamp       = (Get-Date).ToString('o')
        Mode            = $Mode
        Force           = $Force.IsPresent
        DurationMinutes = [math]::Round($stopwatch.Elapsed.TotalMinutes, 1)
        InitialIssues   = @($initialIssues)
        InitialIssueDetails = $script:InitialIssueDetails
        RemainingIssues = @($script:DetectedIssues)
        RemainingIssueDetails = $script:IssueDetails
        WUConfiguration = $script:WUConfiguration
        WindowsUpdateAge = $script:WindowsUpdateAge
        WindowsUpdateMaxAgeDays = $WindowsUpdateMaxAgeDays
        DefenderSignatureAge = $script:DefenderSignatureAge
        DefenderSignatureMaxAgeDays = $DefenderSignatureMaxAgeDays
        SfcValidation = $script:SfcValidation
        SoftwareDistributionEntries = $script:SoftwareDistributionEntryCount
        SoftwareDistributionThreshold = $SoftwareDistributionEntryThreshold
        SoftwareDistributionCountCapped = ($script:SoftwareDistributionEntryCount -gt $SoftwareDistributionEntryThreshold)
        RemediationResults = @($script:RemediationResults)
        RebootPending   = $script:RebootPending
        Compliant       = $isCompliant
    }

    Write-CMLog "=== Ergebnis: $(if ($summary.Compliant) { 'COMPLIANT' } else { 'NON-COMPLIANT' }) | Dauer: $($summary.DurationMinutes) min | Neustart nötig: $($script:RebootPending) ===" $(if ($summary.Compliant) { 1 } else { 2 })
    Write-CMLog '=== CM Agent Health v0.5 beendet ===' 1

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
