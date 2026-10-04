# CM Agent Health

`CM_Agent_Health_v0.5.ps1` diagnostiziert und repariert typische Probleme des
Microsoft Configuration Manager Clients und der Windows-Update-Komponenten auf
Windows 10 und Windows 11.

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

`-Mode Deep -Force` setzt `SoftwareDistribution` und `catroot2` unabhängig vom
Diagnoseergebnis zurück. Ohne `-Force` erfolgt dieser Eingriff nur bei passenden
Symptomen, beispielsweise veralteten Windows-Updates oder mehr als 100.000
Einträgen in `SoftwareDistribution`. Beim Cache-Reset werden die beteiligten
Dienste temporär deaktiviert und anschließend auf ihren exakten Start- und
Laufzustand zurückgesetzt. Ein persistentes Journal ermöglicht die
Wiederherstellung nach einem abgebrochenen Lauf.

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
.\CM_Agent_Health_v0.5.ps1 -Mode Evaluate

# Geplante Änderungen anzeigen
.\CM_Agent_Health_v0.5.ps1 -Mode Light -WhatIf

# Light-Behandlung unabhängig davon ausführen, ob zuvor ein Fehler erkannt wurde
.\CM_Agent_Health_v0.5.ps1 -Mode Light

# Befundabhängige Tiefenbehandlung
.\CM_Agent_Health_v0.5.ps1 -Mode Deep

# WU-Cache-Reset ausdrücklich ohne passenden Befund erzwingen
.\CM_Agent_Health_v0.5.ps1 -Mode Deep -Force

# WSUS-Konfiguration validieren und UseWUServer bei vollständigen Endpunkten setzen
.\CM_Agent_Health_v0.5.ps1 -Mode Light -EnforceWSUS

# Eigenen Grenzwert für SoftwareDistribution verwenden
.\CM_Agent_Health_v0.5.ps1 -Mode Evaluate -SoftwareDistributionEntryThreshold 250000

# Eigene Aktualitätsgrenzen verwenden und SFC ausnahmsweise überspringen
.\CM_Agent_Health_v0.5.ps1 -Mode Evaluate -WindowsUpdateMaxAgeDays 45 `
    -DefenderSignatureMaxAgeDays 7 -SkipSfcValidation
```

Die Tiefenreparatur kann `SoftwareDistribution` und `catroot2` zurücksetzen und
einen Neustart erforderlich machen. `-EnforceWSUS` sollte ausschließlich auf
Geräten verwendet werden, die tatsächlich über WSUS beziehungsweise einen
ConfigMgr Software Update Point verwaltet werden.

## Ergebnisdaten

Der Prozess-Exitcode bleibt für Automatisierung stabil. Die JSON-Ausgabe enthält
zusätzlich `InitialIssues`, `InitialIssueDetails`, `RemainingIssues`,
`RemainingIssueDetails`, `WUConfiguration`, `WindowsUpdateAge`,
`DefenderSignatureAge`, `SfcValidation`, die Zahl der geprüften
SoftwareDistribution-Einträge und die Ergebnisse der ausgeführten
Remediation-Schritte.

## Rückgabecodes

| Code | Bedeutung |
| ---: | --- |
| `0` | Keine Symptome mehr vorhanden |
| `1` | Symptome sind offen geblieben oder eine Remediation ist fehlgeschlagen |
| `2` | Unerwarteter Abbruch |
| `3010` | Bereinigt, Neustart erforderlich |

## Lizenz

Veröffentlicht unter der [MIT License](LICENSE).
