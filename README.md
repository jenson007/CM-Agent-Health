# CM Agent Health

`CM_Agent_Health_v0.3.ps1` diagnostiziert und repariert typische Probleme des
Microsoft Configuration Manager Clients und der Windows-Update-Komponenten auf
Windows 10 und Windows 11.

Das Skript prüft unter anderem den ConfigMgr-Dienst, WMI, den Windows Component
Store, Windows Update, WSUS-Einstellungen, den Provisioning Mode und ausstehende
Neustarts. Erkannte Probleme werden gezielt behandelt; anschließend validiert
das Skript den Zustand erneut und kann die relevanten ConfigMgr-Zyklen auslösen.
Ergebnisse werden als CMTrace-Log und kompakte JSON-Zusammenfassung ausgegeben.

## Sichere Verwendung

Das Skript benötigt Windows PowerShell 5.1 und Administratorrechte. Vor dem
produktiven Einsatz sollte es mit den eigenen ConfigMgr-, GPO- und
Co-Management-Vorgaben getestet werden.

```powershell
# Nur Diagnose, ohne Änderungen
.\CM_Agent_Health_v0.3.ps1 -DiagnoseOnly

# Geplante Änderungen anzeigen
.\CM_Agent_Health_v0.3.ps1 -WhatIf

# Tiefenreparatur der Windows-Update-Komponenten erlauben
.\CM_Agent_Health_v0.3.ps1 -AllowDeepRepair

# WSUS nur bei vollständig konfigurierten Endpunkten erzwingen
.\CM_Agent_Health_v0.3.ps1 -EnforceWSUS
```

Die Tiefenreparatur kann `SoftwareDistribution` und `catroot2` zurücksetzen und
einen Neustart erforderlich machen. `-EnforceWSUS` sollte ausschließlich auf
Geräten verwendet werden, die tatsächlich über WSUS beziehungsweise einen
ConfigMgr Software Update Point verwaltet werden.

## Rückgabecodes

| Code | Bedeutung |
| ---: | --- |
| `0` | Keine Symptome mehr vorhanden |
| `1` | Symptome sind offen geblieben |
| `2` | Unerwarteter Abbruch |
| `3010` | Bereinigt, Neustart erforderlich |

## Lizenz

Veröffentlicht unter der [MIT License](LICENSE).
