# HoneyBadger Vanguard — PowerShell Wrapper Contribution

> **Upstream:** [rasta-mouse/ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)  
> **Wrapper Repo:** [MoSLoF/ThreatCheck](https://github.com/MoSLoF/ThreatCheck)  
> **Author:** HoneyBadger Vanguard LLC · [ihbv.io](https://ihbv.io)  
> **MITRE ATT&CK:** T1562.001 · T1027

---

## What This Adds

This contribution wraps `ThreatCheck.exe` in a production-grade PowerShell module that integrates cleanly into purple team workflows and SIEM pipelines.

| Feature | Description |
|---------|-------------|
| **Pipeline support** | Accepts `FileInfo` objects from `Get-ChildItem` via `ValueFromPipeline` |
| **Structured output** | Returns typed `[PSCustomObject]` per scan (filterable, exportable) |
| **Glob expansion** | Wildcard paths resolved internally before scanning |
| **Wazuh SIEM logging** | NDJSON events with MITRE ATT&CK mapping, ready for Wazuh decoder |
| **HTML threat report** | Self-contained dark-theme report with stats, badges, hex dump display |
| **AMSI engine support** | `-Engine AMSI -Type Script` for PowerShell script scanning |
| **URL scanning** | `-Url` parameter for remote file analysis |
| **Verbose/Debug modes** | `-Verbose` and `-Debug` switches pass through to underlying exe |

---

## Files

```
PowerShell/
├── Invoke-ThreatCheck.psm1   # Module implementation (~880 lines)
├── Invoke-ThreatCheck.psd1   # Module manifest
├── ThreatCheck.exe           # Compiled binary (see Build section)
├── CommandLine.dll           # CommandLineParser dependency
└── System.Management.Automation.dll
```

---

## Build ThreatCheck.exe

The module auto-discovers `ThreatCheck.exe` alongside the `.psm1` file.  
You must compile it first:

```powershell
# 1. Restore NuGet packages (required for old-style .csproj)
.\nuget.exe restore ThreatCheck.sln

# 2. Build Release
$msbuild = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe'
& $msbuild ThreatCheck.sln /p:Configuration=Release /p:Platform="Any CPU"

# 3. Copy binaries to PowerShell folder
$releaseDir = '.\ThreatCheck\bin\Release'
$psDir      = '.\PowerShell'
Copy-Item "$releaseDir\ThreatCheck.exe"                      $psDir
Copy-Item "$releaseDir\CommandLine.dll"                      $psDir
Copy-Item "$releaseDir\System.Management.Automation.dll"     $psDir
```

> **NuGet:** Download `nuget.exe` from https://dist.nuget.org/win-x86-commandline/latest/nuget.exe

---

## Requirements

- PowerShell 7.0+
- Windows (Defender engine requires `MpCmdRun.exe`)
- Administrator rights recommended for Defender engine scans
- `C:\Temp` must exist (Defender engine writes temp files there)

### Defender Exclusions

To prevent false-positive blocks on the module itself and your tools directory, add Defender exclusions before use:

```powershell
Add-MpPreference -ExclusionPath 'D:\YourToolsPath\ThreatCheck'
Add-MpPreference -ExclusionPath 'D:\YourToolsPath\ThreatCheck\PowerShell'
```

> **Note:** If you see `WARNING: True appearing in output` it typically means the Defender exclusion is missing and MpCmdRun is being blocked mid-scan. The module filters stray `True`/`False` lines from stdout, but incomplete scans may still produce unexpected output.

---

## Installation

```powershell
# Option 1 — Import directly
Import-Module '.\PowerShell\Invoke-ThreatCheck.psd1'

# Option 2 — Add to PowerShell profile for persistent availability
$profileLine = "Import-Module 'D:\YourPath\ThreatCheck\PowerShell\Invoke-ThreatCheck.psd1'"
Add-Content $PROFILE $profileLine
```

---

## Usage

### Single File — Defender (default)
```powershell
Invoke-ThreatCheck -Path C:\Tools\Rubeus.exe
```

### Single File — AMSI Engine
```powershell
Invoke-ThreatCheck -Path C:\Tools\Invoke-OffensiveTool.ps1 -Engine AMSI -Type Script
```

### Pipeline — Bulk Scan
```powershell
Get-ChildItem C:\Tools\*.exe | Invoke-ThreatCheck
```

### Filter Flagged Only
```powershell
Get-ChildItem C:\Tools\*.exe | Invoke-ThreatCheck | Where-Object { -not $_.Clean }
```

### Wazuh SIEM Integration
```powershell
Get-ChildItem C:\Tools\*.exe |
    Invoke-ThreatCheck -WazuhLogFile C:\Logs\threatcheck.json
```

### HTML Report
```powershell
Get-ChildItem C:\Tools\*.exe |
    Invoke-ThreatCheck -ReportFile C:\Reports\tc-report.html
```

### Full Purple Team Run
```powershell
Get-ChildItem C:\Tools\*.exe |
    Invoke-ThreatCheck `
        -WazuhLogFile C:\Logs\threatcheck.json `
        -ReportFile   C:\Reports\tc-report.html |
    Where-Object { -not $_.Clean } |
    Select-Object Target, FlaggedOffset, Engine
```

### Scan from URL
```powershell
Invoke-ThreatCheck -Url 'https://example.com/payload.bin' -Engine Defender
```

---

## Output Object Schema

Each scan emits one `[PSCustomObject]` with these properties:

| Property | Type | Description |
|----------|------|-------------|
| `Timestamp` | `DateTime` | Scan start time |
| `Target` | `string` | Full path to scanned file |
| `Engine` | `string` | `Defender` or `AMSI` |
| `Type` | `string` | `Bin` or `Script` |
| `Clean` | `bool` | `$true` if no threat detected |
| `FlaggedOffset` | `string` | Hex offset of detection (if flagged) |
| `ErrorMessage` | `string` | Error text (if scan failed) |
| `HexDump` | `string[]` | Hex dump lines around flagged offset |
| `RawOutput` | `string[]` | Raw ThreatCheck.exe stdout lines |
| `ScanDuration` | `TimeSpan` | Wall-clock scan time |

---

## Wazuh Integration

### Event Schema (NDJSON)

```json
{
  "timestamp": "2026-03-06T15:05:00.0000000-06:00",
  "program_name": "Invoke-ThreatCheck",
  "hbv_version": "1.0.0",
  "event_type": "scan_threat_found",
  "target": "C:\\Tools\\payload.exe",
  "engine": "Defender",
  "file_type": "Bin",
  "clean": false,
  "flagged_offset": "0x1A3F00",
  "error_message": null,
  "scan_duration_ms": 148.32,
  "mitre_technique": "T1562.001",
  "mitre_tactic": "Defense Evasion",
  "mitre_technique2": "T1027",
  "mitre_tactic2": "Defense Evasion"
}
```

### Wazuh Decoder (`/var/ossec/etc/decoders/threatcheck.xml`)

```xml
<decoder name="invoke-threatcheck">
  <prematch>\"program_name\":\"Invoke-ThreatCheck\"</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

### Wazuh Rule (`/var/ossec/etc/rules/threatcheck_rules.xml`)

```xml
<group name="threatcheck,malware,">

  <rule id="100500" level="12">
    <decoded_as>invoke-threatcheck</decoded_as>
    <field name="event_type">scan_threat_found</field>
    <description>ThreatCheck: AV signature detected in $(target)</description>
    <mitre>
      <id>T1562.001</id>
      <id>T1027</id>
    </mitre>
    <group>pci_dss_11.4,gdpr_IV_35.7.d,</group>
  </rule>

  <rule id="100501" level="3">
    <decoded_as>invoke-threatcheck</decoded_as>
    <field name="event_type">scan_clean</field>
    <description>ThreatCheck: Clean scan — $(target)</description>
  </rule>

</group>
```

---

## MITRE ATT&CK Coverage

| Technique | Tactic | Description |
|-----------|--------|-------------|
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Defense Evasion | Identifies AV signatures enabling bypass research |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Defense Evasion | Supports obfuscation analysis and detection tuning |

---

## Purple Team Philosophy

> *"Understand Offense to Build Better Defense."*  
> — HoneyBadger Vanguard LLC

`Invoke-ThreatCheck` is designed for **purple team operators** who need to:

1. **Red side** — Identify exact byte offsets triggering AV detection to inform evasion research
2. **Blue side** — Validate detection coverage across tool inventories and generate audit-ready reports for SIEM pipelines

The Wazuh integration closes the loop: flagged offsets become SIEM events, enabling defenders to track which tools in their environment would be caught vs. missed by current AV configurations.

---

## Known Limitations

- Defender engine requires `Administrator` and `C:\Temp` to exist
- AMSI engine requires the target file to exist on disk (no URL support for AMSI)
- ThreatCheck.exe targets .NET Framework 4.8 — requires .NET 4.8 runtime on the host
- Large binaries (>50MB) may hit the 60-second scan timeout

---

## License

MIT — same as upstream [rasta-mouse/ThreatCheck](https://github.com/rasta-mouse/ThreatCheck).  
Wrapper additions © 2026 HoneyBadger Vanguard LLC.
