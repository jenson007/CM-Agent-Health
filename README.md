# CM Agent Health

`CM_Agent_Health_v0.6.ps1` diagnostiziert und repariert typische Probleme des
Microsoft Configuration Manager Clients und der Windows-Update-Komponenten auf
Windows 10 und Windows 11.

Das Skript richtet sich ausschließlich an ConfigMgr-Clients, die ihre
Softwareupdates über einen WSUS beziehungsweise einen ConfigMgr Software Update
Point beziehen. Für reine WUfB-/Intune-Geräte ist es nicht vorgesehen.

Das Skript prüft unter anderem den ConfigMgr-Dienst, WMI, den Windows Component
Store, geschützte Systemdateien mit SFC, Windows Update, den letzten installierten
Windows-Update-Stand, Microsoft-Defender-Signaturen, die WSUS-Registry-Konfiguration,
den Provisioning Mode, die Größe von `SoftwareDistribution` und ausstehende
Neustarts. Ergebnisse werden als CMTrace-Log und kompakte JSON-Zusammenfassung
ausgegeben.

Die WSUS-Werte werden aus ihren tatsächlichen Registry-Pfaden gelesen:
`WUServer` und `WUStatusServer` aus `...\WindowsUpdate`, `UseWUServer` aus
`...\WindowsUpdate\AU`.

## Betriebsarten

| Modus | Verhalten |
| --- | --- |
| `Evaluate` | Ausschließlich Diagnose; keine Änderungen und keine ConfigMgr-Zyklen |
| `Light` | Diagnose, risikoarme und symptombezogene Behandlung, Defender-Signaturupdate sowie ConfigMgr-Zyklen |
| `Deep` | Wie Light; zusätzlich WMI/DISM/SFC- und WU-Cache-Reparaturen bei passenden Symptomen |

## Einsatz über "Skripte ausführen" in ConfigMgr

Die ConfigMgr-Funktion "Skripte ausführen" erlaubt höchstens zehn Parameter und
kann `[switch]`-Parameter nicht befüllen. Das Skript hat deshalb genau zehn
Parameter, die alle als `[bool]` deklariert sind. Werte, die nicht von außen
steuerbar sein sollen – Logpfad, Logrotation, Konsolenausgabe, `EnforceWSUS` und
das Überspringen der SFC-Prüfung – sind fest im Skriptkopf hinterlegt.

Das Log wird unter `%SystemDrive%\ProgramData\SWP\Logs\CM_AgentHealth.log`
geschrieben und ist in CMTrace inklusive Zeit, Zeitzone und Thread lesbar.

## Forcierte Remediationen

| Parameter | Wirkung | Voraussetzung |
| --- | --- | --- |
| `-ForceWUReset $true` | WU-Cache-Reset, Reaktivierung der Update-Dienste, `UseWUServer = 1`, Erneuerung der WSUS-Client-Identität | `-Mode Deep` |
| `-ForceWMIReset $true` | WMI-Salvage, DISM/SFC-Reparatur und ConfigMgr-Policy-Reset | `-Mode Deep` |
| `-ForceDefenderReset $true` | Aktualisierung der Defender-Signaturen | – |
| `-ForceReboot $true` | Rückgabe von `3010`, damit ConfigMgr den Neustart anstößt | – |

Ohne diese Schalter erfolgen die Eingriffe nur bei passenden Symptomen,
beispielsweise veralteten Windows-Updates oder mehr als 100.000 Einträgen in
`SoftwareDistribution`.

Beim Cache-Reset werden die beteiligten Dienste temporär deaktiviert und
gestoppt und anschließend auf ihren exakten Start- und Laufzustand
zurückgesetzt. Dienste, die Windows nicht deaktivieren lässt (etwa `cryptsvc`),
werden lediglich gestoppt und blockieren die Remediation nicht mehr. Ein
persistentes Journal ermöglicht die Wiederherstellung nach einem abgebrochenen
Lauf.

## Aktualitätsgrenzen

Standardmäßig gilt ein Gerät als auffällig, wenn seit mindestens 30 Tagen kein
Windows-Betriebssystemupdate installiert wurde oder die Defender-Signaturen
älter als fünf Tage sind. Office-, Treiber- und Defender-Updates zählen nicht
als Windows-Betriebssystemupdate. Die Grenzen lassen sich mit
`-WindowsUpdateMaxAgeDays` und `-DefenderSignatureMaxAgeDays` ändern.

`Evaluate` meldet die Befunde nur. `Light` und `Deep` aktualisieren bei Bedarf
die Defender-Signaturen und stoßen die ConfigMgr-Updatezyklen an. `Deep` darf
bei einem veralteten Windows-Update-Stand zusätzlich den WU-Cache zurücksetzen.
Ein Scan installiert nicht zwingend Updates; deshalb kann der Altersbefund bis
zur tatsächlichen Installation eines Updates offen bleiben.

## Sichere Verwendung

Das Skript benötigt Windows PowerShell 5.1 und Administratorrechte. Vor dem
produktiven Einsatz sollte es mit den eigenen ConfigMgr-, GPO- und
Co-Management-Vorgaben getestet werden.

```powershell
# Nur Diagnose, ohne Änderungen
.\CM_Agent_Health_v0.6.ps1 -Mode Evaluate

# Geplante Änderungen anzeigen
.\CM_Agent_Health_v0.6.ps1 -Mode Light -WhatIf

# Light-Behandlung unabhängig davon ausführen, ob zuvor ein Fehler erkannt wurde
.\CM_Agent_Health_v0.6.ps1 -Mode Light

# Befundabhängige Tiefenbehandlung
.\CM_Agent_Health_v0.6.ps1 -Mode Deep

# WU-Cache-Reset ausdrücklich ohne passenden Befund erzwingen
.\CM_Agent_Health_v0.6.ps1 -Mode Deep -ForceWUReset $true

# WMI, Component Store und ConfigMgr-Policy erzwungen reparieren
.\CM_Agent_Health_v0.6.ps1 -Mode Deep -ForceWMIReset $true

# Defender-Signaturen aktualisieren und anschließend Neustart anfordern
.\CM_Agent_Health_v0.6.ps1 -Mode Light -ForceDefenderReset $true -ForceReboot $true

# Eigenen Grenzwert für SoftwareDistribution verwenden
.\CM_Agent_Health_v0.6.ps1 -Mode Evaluate -SoftwareDistributionEntryThreshold 250000

# Eigene Aktualitätsgrenzen verwenden
.\CM_Agent_Health_v0.6.ps1 -Mode Evaluate -WindowsUpdateMaxAgeDays 45 `
    -DefenderSignatureMaxAgeDays 7
```

Die Tiefenreparatur kann `SoftwareDistribution` und `catroot2` zurücksetzen und
einen Neustart erforderlich machen. `-ForceWUReset` stellt dabei auch
`UseWUServer = 1` wieder her und sollte deshalb nur auf Geräten verwendet
werden, die tatsächlich über WSUS beziehungsweise einen ConfigMgr Software
Update Point verwaltet werden.

## Ergebnisdaten

Der Prozess-Exitcode bleibt für Automatisierung stabil. Die JSON-Ausgabe enthält
zusätzlich `InitialIssues`, `InitialIssueDetails`, `RemainingIssues`,
`RemainingIssueDetails`, `WUConfiguration`, `WindowsUpdateAge`,
`DefenderSignatureAge`, `SfcValidation`, die gesetzten Force-Schalter, die Zahl
der geprüften SoftwareDistribution-Einträge und die Ergebnisse der ausgeführten
Remediation-Schritte.

## Rückgabecodes

| Code | Bedeutung |
| ---: | --- |
| `0` | Keine Symptome mehr vorhanden |
| `1` | Symptome sind offen geblieben oder eine Remediation ist fehlgeschlagen |
| `2` | Unerwarteter Abbruch |
| `3010` | Neustart erforderlich; ConfigMgr stößt den Neustart an |

Ein anstehender Neustart hat Vorrang vor `1`, damit ConfigMgr den Client zuerst
neu startet und das Ergebnis anschließend erneut bewertet werden kann.

## Lizenz

Veröffentlicht unter der [MIT License](LICENSE).
