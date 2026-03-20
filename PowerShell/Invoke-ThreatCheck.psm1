#Requires -Version 7.0
<#
.SYNOPSIS
    PowerShell wrapper module for ThreatCheck.exe with pipeline support,
    structured output, Wazuh SIEM integration, and HTML reporting.

.DESCRIPTION
    Invoke-ThreatCheck wraps rasta-mouse's ThreatCheck.exe to provide:
      - Pipeline-friendly input (ValueFromPipeline / ValueFromPipelineByPropertyName)
      - Structured [PSCustomObject] output per scan result
      - Glob/wildcard expansion for bulk scanning
      - Wazuh NDJSON event logging with MITRE ATT&CK tagging
      - Self-contained HTML threat report

    ThreatCheck.exe must be compiled and accessible. The module will attempt
    to auto-discover ThreatCheck.exe in the following order:
      1. -ThreatCheckPath parameter (explicit)
      2. Same directory as this .psm1 file
      3. Parent directory of this .psm1 file
      4. $env:PATH

    NOTE: Defender scans require ThreatCheck.exe to write to C:\Temp and
    invoke MpCmdRun.exe. Run as Administrator for Defender engine scans.

.NOTES
    Author      : HoneyBadger Vanguard LLC (github.com/MoSLoF)
    Version     : 1.0.0
    Repo        : github.com/MoSLoF/ThreatCheck
    Upstream    : github.com/rasta-mouse/ThreatCheck
    MITRE       : T1562.001 (Impair Defenses: Disable or Modify Tools)
                  T1027     (Obfuscated Files or Information)
    License     : MIT

.EXAMPLE
    # Scan a single binary with Defender
    Invoke-ThreatCheck -Path C:\Tools\Rubeus.exe

.EXAMPLE
    # Scan a PowerShell script with AMSI engine
    Invoke-ThreatCheck -Path C:\Tools\OffensiveTool.ps1 -Engine AMSI -Type Script

.EXAMPLE
    # Pipeline: scan every .ps1 in a folder, AMSI engine
    Get-ChildItem C:\Tools\*.ps1 | Invoke-ThreatCheck -Engine AMSI -Type Script

.EXAMPLE
    # Bulk scan binaries, show only flagged results
    Get-ChildItem C:\Tools\*.exe | Invoke-ThreatCheck | Where-Object { -not $_.Clean }

.EXAMPLE
    # Full run: scan, log to Wazuh, generate HTML report
    Get-ChildItem C:\Tools\*.exe |
        Invoke-ThreatCheck -WazuhLogFile C:\Logs\threatcheck.json -ReportFile C:\Reports\tc.html

.EXAMPLE
    # Scan from URL
    Invoke-ThreatCheck -Url 'https://example.com/payload.bin' -Engine Defender

.LINK
    https://github.com/rasta-mouse/ThreatCheck
    https://github.com/MoSLoF/ThreatCheck
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Module-level accumulator — initialized once at load time, reset per invocation
$script:_tcResultStore = [System.Collections.Generic.List[object]]::new()

#region ── Internal Helpers ────────────────────────────────────────────────────

function Resolve-ThreatCheckExe {
    [OutputType([string])]
    param([string]$ExplicitPath)

    if ($ExplicitPath) {
        if (Test-Path $ExplicitPath -PathType Leaf) { return $ExplicitPath }
        throw "ThreatCheck.exe not found at specified path: $ExplicitPath"
    }

    $moduleDir = Split-Path -Parent $PSCommandPath
    $candidate = Join-Path $moduleDir 'ThreatCheck.exe'
    if (Test-Path $candidate) { return $candidate }

    $parentDir = Split-Path -Parent $moduleDir
    foreach ($rel in @('ThreatCheck\bin\Release\net48\ThreatCheck.exe','ThreatCheck\bin\Debug\net48\ThreatCheck.exe')) {
        $candidate = Join-Path $parentDir $rel
        if (Test-Path $candidate) { return $candidate }
    }

    $fromPath = Get-Command 'ThreatCheck.exe' -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }

    throw "ThreatCheck.exe not found. Use -ThreatCheckPath to specify its location, or place it alongside Invoke-ThreatCheck.psm1."
}

function Invoke-ThreatCheckExe {
    [OutputType([string[]])]
    param(
        [string]$ExePath,
        [string[]]$Arguments
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName               = $ExePath
    $psi.Arguments              = $Arguments -join ' '
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.RedirectStandardInput  = $true
    $psi.CreateNoWindow         = $true

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $null = $proc.Start()

    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $null = $proc.WaitForExit(60000)

    if (-not $proc.HasExited) {
        $proc.Kill()
        throw "ThreatCheck.exe timed out after 60 seconds"
    }

    # Filter blank lines and bare boolean lines ThreatCheck emits to stdout
    $allOutput = [System.Collections.Generic.List[string]]::new()
    foreach ($src in @($stdout, $stderr)) {
        if ($src) {
            foreach ($line in ($src -split "`r?`n")) {
                $trimmed = $line.Trim()
                if ($trimmed -ne '' -and $trimmed -ne 'True' -and $trimmed -ne 'False') {
                    $allOutput.Add($line)
                }
            }
        }
    }

    return $allOutput.ToArray()
}

function Parse-ThreatCheckOutput {
    [OutputType([hashtable])]
    param(
        [string[]]$Lines,
        [string]$Target,
        [string]$Engine,
        [string]$Type
    )

    $result = @{
        Clean         = $true
        FlaggedOffset = $null
        Signature     = $null
        ErrorMessage  = $null
        HexDump       = [System.Collections.Generic.List[string]]::new()
        RawOutput     = $Lines
    }

    foreach ($line in $Lines) {
        if ($line -match '^\[!\].*offset\s+(0x[0-9A-Fa-f]+)') {
            $result.Clean         = $false
            $result.FlaggedOffset = $Matches[1]
        }
        elseif ($line -match '^\[!\]') {
            $result.Clean = $false
        }
        elseif ($line -match '^\[x\]') {
            $result.ErrorMessage = $line -replace '^\[x\]\s*', ''
        }
        elseif ($line -match '^[0-9A-Fa-f]{8}\s') {
            $result.HexDump.Add($line)
        }
    }

    return $result
}

function Write-WazuhEvent {
    param(
        [string]$LogFile,
        [PSCustomObject]$ScanResult
    )

    $event = [ordered]@{
        timestamp        = $ScanResult.Timestamp.ToString('o')
        program_name     = 'Invoke-ThreatCheck'
        hbv_version      = '1.0.0'
        event_type       = if ($ScanResult.Clean) { 'scan_clean' } else { 'scan_threat_found' }
        target           = $ScanResult.Target
        engine           = $ScanResult.Engine
        file_type        = $ScanResult.Type
        clean            = $ScanResult.Clean
        flagged_offset   = $ScanResult.FlaggedOffset
        error_message    = $ScanResult.ErrorMessage
        scan_duration_ms = [math]::Round($ScanResult.ScanDuration.TotalMilliseconds, 2)
        mitre_technique  = 'T1562.001'
        mitre_tactic     = 'Defense Evasion'
        mitre_technique2 = 'T1027'
        mitre_tactic2    = 'Defense Evasion'
    }

    $json = $event | ConvertTo-Json -Compress
    Add-Content -Path $LogFile -Value $json -Encoding UTF8
}

function New-HtmlReport {
    param(
        [PSCustomObject[]]$Results,
        [string]$ReportFile
    )

    $ResultsArr   = @($Results)
    [int]$totalScans   = $ResultsArr.Count
    [int]$flaggedCount = @($ResultsArr | Where-Object { -not $_.Clean }).Count
    [int]$cleanCount   = @($ResultsArr | Where-Object {  $_.Clean -and -not $_.ErrorMessage }).Count
    [int]$errorCount   = @($ResultsArr | Where-Object {  $_.ErrorMessage }).Count
    $generatedAt  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $cards = foreach ($r in $Results) {
        $statusColor = if (-not $r.Clean) { '#E94560' } elseif ($r.ErrorMessage) { '#FF9800' } else { '#00C853' }
        $statusLabel = if (-not $r.Clean) { 'FLAGGED' } elseif ($r.ErrorMessage) { 'ERROR'   } else { 'CLEAN'   }
        $offsetBadge = if ($r.FlaggedOffset) { "<span class='badge danger'>Offset: $($r.FlaggedOffset)</span>" } else { '' }
        $engineBadge = "<span class='badge engine'>$($r.Engine)</span>"
        $typeBadge   = "<span class='badge type'>$($r.Type)</span>"
        $durationMs  = [math]::Round($r.ScanDuration.TotalMilliseconds)

        $hexRows = if (@($r.HexDump).Count -gt 0) {
            $hexContent = ($r.HexDump | ForEach-Object { [System.Web.HttpUtility]::HtmlEncode($_) }) -join "`n"
            "<div class='hexdump'><pre>$hexContent</pre></div>"
        } else { '' }

        @"
        <div class='card' style='border-left: 4px solid $statusColor'>
            <div class='card-header'>
                <span class='status-badge' style='background:$statusColor'>$statusLabel</span>
                $engineBadge $typeBadge $offsetBadge
                <span class='duration'>${durationMs}ms</span>
            </div>
            <div class='card-target'>$([System.Web.HttpUtility]::HtmlEncode($r.Target))</div>
            <div class='card-time'>$($r.Timestamp.ToString('HH:mm:ss.fff'))</div>
            $hexRows
        </div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ThreatCheck Report — HoneyBadger Vanguard</title>
<style>
  :root {
    --bg: #0a0a0f; --surface: #12121a; --card: #1a1a2e;
    --accent: #E94560; --blue: #0D3B66; --green: #00C853;
    --orange: #FF9800; --text: #e0e0e0; --muted: #888;
    --font: 'Segoe UI', 'Consolas', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); padding: 24px; }
  header { border-bottom: 2px solid var(--accent); padding-bottom: 16px; margin-bottom: 24px; }
  header h1 { color: var(--accent); font-size: 1.6rem; letter-spacing: 2px; text-transform: uppercase; }
  header p  { color: var(--muted); font-size: 0.85rem; margin-top: 4px; }
  .stats { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
  .stat { background: var(--card); border: 1px solid #2a2a3e; border-radius: 8px; padding: 16px 24px; flex: 1; min-width: 140px; }
  .stat-value { font-size: 2rem; font-weight: bold; }
  .stat-label { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; margin-top: 4px; }
  .stat.danger .stat-value { color: var(--accent); }
  .stat.clean  .stat-value { color: var(--green); }
  .stat.warn   .stat-value { color: var(--orange); }
  .stat.total  .stat-value { color: #7c83fd; }
  .mitre-strip { background: var(--blue); border-radius: 6px; padding: 10px 16px; margin-bottom: 24px; font-size: 0.82rem; color: #cdd; }
  .mitre-strip span { margin-right: 24px; }
  .cards { display: flex; flex-direction: column; gap: 12px; }
  .card { background: var(--card); border-radius: 8px; padding: 16px; border: 1px solid #2a2a3e; }
  .card-header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
  .status-badge { padding: 3px 10px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; color: #fff; letter-spacing: 1px; }
  .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; }
  .badge.engine { background: #2a2a4e; color: #aac; }
  .badge.type   { background: #2a3a2e; color: #aca; }
  .badge.danger { background: #3a1a1e; color: var(--accent); font-weight: bold; }
  .duration { margin-left: auto; color: var(--muted); font-size: 0.78rem; }
  .card-target { font-family: 'Consolas', monospace; font-size: 0.88rem; color: #ccc; word-break: break-all; }
  .card-time { color: var(--muted); font-size: 0.78rem; margin-top: 4px; }
  .hexdump { margin-top: 12px; }
  .hexdump pre { background: #0d0d15; border: 1px solid #2a2a3e; border-radius: 4px; padding: 10px; font-size: 0.78rem; color: var(--accent); overflow-x: auto; white-space: pre; }
  footer { margin-top: 32px; border-top: 1px solid #2a2a3e; padding-top: 16px; color: var(--muted); font-size: 0.78rem; text-align: center; }
</style>
</head>
<body>
<header>
  <h1>&#x26A0; ThreatCheck Scan Report</h1>
  <p>HoneyBadger Vanguard LLC &nbsp;|&nbsp; ihbv.io &nbsp;|&nbsp; Generated: $generatedAt</p>
</header>
<div class="stats">
  <div class="stat total"><div class="stat-value">$totalScans</div><div class="stat-label">Total Scanned</div></div>
  <div class="stat danger"><div class="stat-value">$flaggedCount</div><div class="stat-label">Flagged</div></div>
  <div class="stat clean"><div class="stat-value">$cleanCount</div><div class="stat-label">Clean</div></div>
  <div class="stat warn"><div class="stat-value">$errorCount</div><div class="stat-label">Errors</div></div>
</div>
<div class="mitre-strip">
  &#x1F6E1; MITRE ATT&amp;CK Coverage:
  <span>T1562.001 &mdash; Impair Defenses: Disable or Modify Tools</span>
  <span>T1027 &mdash; Obfuscated Files or Information</span>
</div>
<div class="cards">
$($cards -join "`n")
</div>
<footer>
  Invoke-ThreatCheck v1.0.0 &nbsp;|&nbsp; Upstream: github.com/rasta-mouse/ThreatCheck &nbsp;|&nbsp;
  Wrapper: github.com/MoSLoF/ThreatCheck &nbsp;|&nbsp; HoneyBadger Vanguard LLC
</footer>
</body>
</html>
"@

    Set-Content -Path $ReportFile -Value $html -Encoding UTF8
}

#endregion

#region ── Public Function ─────────────────────────────────────────────────────

function Invoke-ThreatCheck {
<#
.SYNOPSIS
    Scans a file or URL with ThreatCheck.exe and returns structured results.

.PARAMETER Path
    Path(s) to file(s) on disk. Accepts pipeline input and wildcards.

.PARAMETER Url
    URL to download and scan. Mutually exclusive with -Path.

.PARAMETER Engine
    Scanning engine: Defender (default) or AMSI.

.PARAMETER Type
    File type hint: Bin (default) or Script.

.PARAMETER ThreatCheckPath
    Explicit path to ThreatCheck.exe.

.PARAMETER WazuhLogFile
    Path to append NDJSON events for Wazuh ingestion.

.PARAMETER ReportFile
    Path to write a self-contained HTML threat report.

.PARAMETER Quiet
    Suppress all console output.
#>
    [CmdletBinding(DefaultParameterSetName = 'File')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(ParameterSetName='File', Mandatory=$true,
                   ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [Alias('FullName','FilePath','PSPath')]
        [string[]]$Path,

        [Parameter(ParameterSetName='Url', Mandatory=$true)]
        [string]$Url,

        [Parameter()]
        [ValidateSet('Defender','AMSI', IgnoreCase=$true)]
        [string]$Engine = 'Defender',

        [Parameter()]
        [ValidateSet('Bin','Script', IgnoreCase=$true)]
        [string]$Type = 'Bin',

        [Parameter()] [string]$ThreatCheckPath,
        [Parameter()] [string]$WazuhLogFile,
        [Parameter()] [string]$ReportFile,
        [Parameter()] [switch]$Quiet
    )

    begin {
        try {
            $script:tcExe = Resolve-ThreatCheckExe -ExplicitPath $ThreatCheckPath
        } catch { throw $_ }

        if (-not $Quiet) {
            Write-Host "[*] ThreatCheck.exe : $script:tcExe" -ForegroundColor Cyan
            Write-Host "[*] Engine          : $Engine"       -ForegroundColor Cyan
            Write-Host "[*] Type            : $Type"         -ForegroundColor Cyan
            if ($WazuhLogFile) { Write-Host "[*] Wazuh log       : $WazuhLogFile" -ForegroundColor Cyan }
            if ($ReportFile)   { Write-Host "[*] HTML report     : $ReportFile"   -ForegroundColor Cyan }
        }

        $script:_tcResultStore = [System.Collections.Generic.List[object]]::new()
    }

    process {
        $targets = [System.Collections.Generic.List[string]]::new()

        if ($PSCmdlet.ParameterSetName -eq 'Url') {
            $targets.Add($Url)
        } else {
            foreach ($p in $Path) {
                $resolved = Resolve-Path -Path $p -ErrorAction SilentlyContinue
                if ($resolved) { $targets.Add($resolved.ProviderPath) }
                else            { Write-Warning "Path not found: $p"  }
            }
        }

        foreach ($target in $targets) {
            $isUrl  = $PSCmdlet.ParameterSetName -eq 'Url'
            $tcArgs = @(
                if ($isUrl) { '-u', "`"$target`"" } else { '-f', "`"$target`"" }
                '-e', $Engine
                '-t', $Type
            )

            if (-not $Quiet) { Write-Host "`n[>] Scanning: $target" -ForegroundColor Yellow }

            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            try   { $rawLines = Invoke-ThreatCheckExe -ExePath $script:tcExe -Arguments $tcArgs }
            catch { $rawLines = @("[x] Execution error: $_") }
            $stopwatch.Stop()

            $parsed = Parse-ThreatCheckOutput -Lines $rawLines -Target $target -Engine $Engine -Type $Type

            if (-not $Quiet) {
                foreach ($line in $rawLines) {
                    switch -Regex ($line) {
                        '^\[\+\]'           { Write-Host $line -ForegroundColor Green   }
                        '^\[!\]'            { Write-Host $line -ForegroundColor Red     }
                        '^\[\*\]'           { Write-Host $line -ForegroundColor Yellow  }
                        '^\[x\]'            { Write-Host $line -ForegroundColor Red     }
                        '^[0-9A-Fa-f]{8}\s' { Write-Host $line -ForegroundColor DarkRed }
                        default             { Write-Host $line }
                    }
                }
            }

            $result = [PSCustomObject][ordered]@{
                PSTypeName    = 'HBV.ThreatCheck.ScanResult'
                Timestamp     = [datetime]::Now
                Target        = $target
                Engine        = $Engine
                Type          = $Type
                Clean         = $parsed.Clean
                FlaggedOffset = $parsed.FlaggedOffset
                ErrorMessage  = $parsed.ErrorMessage
                HexDump       = $parsed.HexDump.ToArray()
                RawOutput     = $parsed.RawOutput
                ScanDuration  = $stopwatch.Elapsed
            }

            if ($WazuhLogFile) {
                try   { Write-WazuhEvent -LogFile $WazuhLogFile -ScanResult $result }
                catch { Write-Warning "Wazuh log write failed: $_" }
            }

            if (-not $Quiet) {
                if ($result.Clean -and -not $result.ErrorMessage) {
                    Write-Host "[+] CLEAN   — $([System.IO.Path]::GetFileName($target))" -ForegroundColor Green
                } elseif ($result.ErrorMessage) {
                    Write-Host "[!] ERROR   — $([System.IO.Path]::GetFileName($target)): $($result.ErrorMessage)" -ForegroundColor Yellow
                } else {
                    Write-Host "[!] FLAGGED — $([System.IO.Path]::GetFileName($target)) at offset $($result.FlaggedOffset)" -ForegroundColor Red
                }
            }

            $script:_tcResultStore.Add($result)
            Write-Output $result
        }
    }

    end {
        [int]$resultCount = $script:_tcResultStore.Count

        if ($ReportFile -and $resultCount -gt 0) {
            try {
                Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
                New-HtmlReport -Results $script:_tcResultStore.ToArray() -ReportFile $ReportFile
                if (-not $Quiet) { Write-Host "`n[+] HTML report written: $ReportFile" -ForegroundColor Cyan }
            } catch { Write-Warning "HTML report generation failed: $_" }
        }

        if (-not $Quiet -and $resultCount -gt 0) {
            [int]$flagged = @($script:_tcResultStore | Where-Object { -not $_.Clean }).Count
            [int]$errors  = @($script:_tcResultStore | Where-Object { $_.ErrorMessage }).Count
            Write-Host "`n[=] Scan complete: $resultCount scanned | " -NoNewline -ForegroundColor Cyan
            Write-Host "$flagged flagged" -NoNewline -ForegroundColor $(if ($flagged -gt 0) {'Red'} else {'Green'})
            Write-Host " | $errors errors"              -ForegroundColor $(if ($errors  -gt 0) {'Yellow'} else {'Green'})
        }
    }
}

#endregion

Export-ModuleMember -Function Invoke-ThreatCheck
