# CM Agent Health

`CM_Agent_Health_v0.5.ps1` diagnostiziert und repariert typische Probleme des
Microsoft Configuration Manager Clients und der Windows-Update-Komponenten auf
Windows 10 und Windows 11.

Das Skript prüft unter anderem den ConfigMgr-Dienst, WMI, den Windows Component
Store, Windows Update, die WSUS-Registry-Konfiguration, den Provisioning Mode,
die Größe von `SoftwareDistribution` und ausstehende Neustarts. Ergebnisse
werden als CMTrace-Log und kompakte JSON-Zusammenfassung ausgegeben.

Die WSUS-Werte werden aus ihren tatsächlichen Registry-Pfaden gelesen:
`WUServer` und `WUStatusServer` aus `...\WindowsUpdate`, `UseWUServer` aus
`...\WindowsUpdate\AU`.

## Betriebsarten

| Modus | Verhalten |
| --- | --- |
| `Evaluate` | Ausschließlich Diagnose; keine Änderungen und keine ConfigMgr-Zyklen |
| `Light` | Diagnose, risikoarme und symptombezogene Behandlung sowie ConfigMgr-Zyklen |
| `Deep` | Wie Light; zusätzlich WMI/DISM- und WU-Cache-Reparaturen bei passenden Symptomen |

`-Mode Deep -Force` setzt `SoftwareDistribution` und `catroot2` unabhängig vom
Diagnoseergebnis zurück. Ohne `-Force` erfolgt dieser Eingriff nur bei passenden
Symptomen, beispielsweise mehr als 100.000 Einträgen in `SoftwareDistribution`.

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
```

Die Tiefenreparatur kann `SoftwareDistribution` und `catroot2` zurücksetzen und
einen Neustart erforderlich machen. `-EnforceWSUS` sollte ausschließlich auf
Geräten verwendet werden, die tatsächlich über WSUS beziehungsweise einen
ConfigMgr Software Update Point verwaltet werden.

## Ergebnisdaten

Der Prozess-Exitcode bleibt für Automatisierung stabil. Die JSON-Ausgabe enthält
zusätzlich `InitialIssues`, `InitialIssueDetails`, `RemainingIssues`,
`RemainingIssueDetails`, `WUConfiguration`, die Zahl der geprüften
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
