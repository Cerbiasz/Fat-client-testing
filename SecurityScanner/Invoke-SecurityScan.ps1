#Requires -Version 5.1
<#
.SYNOPSIS
    .NET Security Scanner v2.2.0 — Production-grade source code security scanner
    for .NET Framework 4.8 thick client applications with Oracle DB and SOAP/WCF.

.DESCRIPTION
    Scans decompiled or source C# code for security vulnerabilities including:
    - SQL Injection (Oracle ODP.NET specific)
    - Weak cryptography (MD5, SHA1, DES, hardcoded keys)
    - Hardcoded credentials
    - Unsafe deserialization (BinaryFormatter, JSON.NET TypeNameHandling)
    - SOAP/WCF security misconfigurations
    - Path traversal, SSRF, open redirect
    - .NET-specific vulnerabilities (reflection, unsafe code, ViewState)

    Generates HTML and JSON reports with severity filtering, risk scoring,
    and false positive reduction.

.PARAMETER SourcePath
    Path to directory containing source files to scan, or a single file.

.PARAMETER OutputPath
    Path for the HTML report output.

.PARAMETER JsonOutput
    Optional path for the JSON report output.

.PARAMETER Severity
    Comma-separated severity filter: Critical,High,Medium,Low,Info.
    Default: all severities.

.PARAMETER ExcludePaths
    Comma-separated regex patterns for paths to exclude (e.g. "obj,bin,\.Designer\.cs$").

.PARAMETER MaxFileSizeMB
    Maximum file size in MB to scan. Default: 5.

.PARAMETER EnableVerbose
    Enable verbose output during scanning.

.PARAMETER ScanTests
    Include test files in scan. Default: $false.

.PARAMETER ConfigPath
    Path to scanner-config.json. Default: scanner-config.json in script directory.

.EXAMPLE
    .\Invoke-SecurityScan.ps1 -SourcePath "C:\Projects\MyApp\src" -OutputPath "C:\Reports\scan.html"

.EXAMPLE
    .\Invoke-SecurityScan.ps1 -SourcePath ".\decompiled" -OutputPath ".\report.html" -JsonOutput ".\report.json" -Severity "Critical,High" -ExcludePaths "obj,bin"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$SourcePath,

    [Parameter(Mandatory, Position = 1)]
    [string]$OutputPath,

    [string]$JsonOutput,

    [string]$Severity = '',

    [string]$ExcludePaths = '',

    [int]$MaxFileSizeMB = 5,

    [switch]$EnableVerbose,

    [switch]$ScanTests,

    [string]$ConfigPath = ''
)

# ============================================================================
# INITIALIZATION
# ============================================================================

$ErrorActionPreference = 'Stop'
if ($EnableVerbose) { $VerbosePreference = 'Continue' }

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesDir = Join-Path $scriptDir 'modules'
$templatesDir = Join-Path $scriptDir 'templates'

# Load System.Web for HTML encoding
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# Import modules
$moduleFiles = @(
    'Core-Engine.psm1',
    'Rules-Injection.psm1',
    'Rules-Cryptography.psm1',
    'Rules-Authentication.psm1',
    'Rules-DataExposure.psm1',
    'Rules-Oracle.psm1',
    'Rules-SOAP.psm1',
    'Rules-Deserialization.psm1',
    'Rules-FileSystem.psm1',
    'Rules-NetworkSecurity.psm1',
    'Rules-DotNetSpecific.psm1'
)

Write-Host "`n[*] .NET Security Scanner v2.2.0" -ForegroundColor Cyan
Write-Host '[*] Target: .NET Framework 4.8 / Oracle DB / SOAP WCF' -ForegroundColor Cyan
Write-Host ''

foreach ($mod in $moduleFiles) {
    $modPath = Join-Path $modulesDir $mod
    if (-not (Test-Path $modPath)) {
        Write-Error "Module not found: $modPath"
        exit 1
    }
    Import-Module $modPath -Force -DisableNameChecking
    Write-Verbose "Loaded module: $mod"
}

# Load config
$config = $null
if ($ConfigPath -and (Test-Path $ConfigPath)) {
    $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    Write-Verbose "Config loaded: $ConfigPath"
} else {
    $defaultConfig = Join-Path $scriptDir 'scanner-config.json'
    if (Test-Path $defaultConfig) {
        $config = Get-Content $defaultConfig -Raw | ConvertFrom-Json
        Write-Verbose "Config loaded: $defaultConfig"
    }
}

# Merge exclude paths from params + config
$excludePatterns = @()
if ($ExcludePaths) {
    $excludePatterns += $ExcludePaths -split ','
}
if ($config -and $config.excluded_paths) {
    $excludePatterns += $config.excluded_paths
}
$excludePatterns = $excludePatterns | Where-Object { $_ -ne '' } | Select-Object -Unique

# Severity filter
$severityFilter = @()
if ($Severity) {
    $severityFilter = ($Severity -split ',') | ForEach-Object { $_.Trim() }
}

# Validate source path
if (-not (Test-Path $SourcePath)) {
    Write-Error "Source path not found: $SourcePath"
    exit 1
}

# ============================================================================
# FILE DISCOVERY
# ============================================================================

Write-Host "[*] Discovering source files..." -ForegroundColor Yellow

$files = Get-SourceFiles `
    -SourcePath $SourcePath `
    -ExcludePaths $excludePatterns `
    -ScanTests:$ScanTests

if ($files.Count -eq 0) {
    Write-Warning "No source files found in: $SourcePath"
    exit 0
}

Write-Host ('[+] Found {0} files to scan' -f $files.Count) -ForegroundColor Green

# ============================================================================
# SCANNING ENGINE
# ============================================================================

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
$totalLines = 0L
$fileIndex = 0

# Define rule functions to invoke per file
$ruleInvokers = @(
    'Invoke-InjectionRules',
    'Invoke-CryptographyRules',
    'Invoke-AuthenticationRules',
    'Invoke-DataExposureRules',
    'Invoke-OracleRules',
    'Invoke-SOAPRules',
    'Invoke-DeserializationRules',
    'Invoke-FileSystemRules',
    'Invoke-NetworkSecurityRules',
    'Invoke-DotNetSpecificRules'
)

$totalRuleCount = 70  # approximate number of individual rules across all modules

foreach ($file in $files) {
    $fileIndex++

    # Progress bar
    $pct = [Math]::Round($fileIndex / $files.Count * 100)
    Write-Progress -Activity "Scanning files" `
        -Status ('{0} / {1} - {2}' -f $fileIndex, $files.Count, $file.Name) `
        -PercentComplete $pct

    # Read file — force array wrapper to prevent PS 5.1 scalar unwrap
    $lines = @(Read-SourceFile -Path $file.FullName -MaxFileSizeMB $MaxFileSizeMB)
    # Skip null, empty, and single-empty-string results
    if ($lines.Count -eq 0) { continue }
    if ($lines.Count -eq 1 -and [string]::IsNullOrWhiteSpace($lines[0])) { continue }
    # Ensure $lines is typed as string[] for Mandatory parameter binding
    [string[]]$lines = $lines

    $totalLines += $lines.Count
    $lineCount = $lines.Count
    Write-Verbose ('Scanning: {0} ({1} lines)' -f $file.FullName, $lineCount)

    # Run each rule module
    foreach ($invoker in $ruleInvokers) {
        try {
            $results = & $invoker -FilePath $file.FullName -Lines $lines
            if ($results -and $results.Count -gt 0) {
                foreach ($r in $results) {
                    $allFindings.Add($r)
                }
            }
        }
        catch {
            $errMsg = 'Rule error in {0} for {1}: {2}' -f $invoker, $file.Name, $_
            Write-Warning $errMsg
        }
    }
}

Write-Progress -Activity "Scanning files" -Completed
$stopwatch.Stop()

# ============================================================================
# POST-PROCESSING
# ============================================================================

# Apply severity overrides from config
if ($config -and $config.severity_overrides) {
    $overrides = $config.severity_overrides
    foreach ($prop in $overrides.PSObject.Properties) {
        $ruleId = $prop.Name
        $newSev = $prop.Value
        for ($i = 0; $i -lt $allFindings.Count; $i++) {
            if ($allFindings[$i].RuleId -eq $ruleId) {
                $allFindings[$i].Severity = $newSev
            }
        }
    }
}

# Exclude disabled rules
if ($config -and $config.excluded_rules) {
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]@(
        $allFindings | Where-Object { $_.RuleId -notin $config.excluded_rules }
    )
}

# Apply severity filter
if ($severityFilter.Count -gt 0) {
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]@(
        $allFindings | Where-Object { $_.Severity -in $severityFilter }
    )
}

# Deduplicate (same rule, same file, same line)
$seen = @{}
$dedupFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($f in $allFindings) {
    $key = '{0}|{1}|{2}' -f $f.RuleId, $f.FilePath, $f.LineNumber
    if (-not $seen.ContainsKey($key)) {
        $seen[$key] = $true
        $dedupFindings.Add($f)
    }
}
$allFindings = $dedupFindings

# ============================================================================
# CONSOLE SUMMARY
# ============================================================================

$duration = $stopwatch.Elapsed.TotalSeconds
$summary = Get-SeveritySummary -Findings $allFindings.ToArray()
$riskScore = if ($allFindings.Count -gt 0) { Get-RiskScore -Findings $allFindings.ToArray() } else { 0 }

Write-Host ''
Write-Host '=============================================' -ForegroundColor Cyan
Write-Host '  SCAN COMPLETE' -ForegroundColor Cyan
Write-Host '=============================================' -ForegroundColor Cyan
Write-Host ('  Files scanned:   {0}' -f $files.Count)
$linesFormatted = $totalLines.ToString('N0')
$durationFormatted = [Math]::Round($duration, 2)
Write-Host ('  Lines scanned:   {0}' -f $linesFormatted)
Write-Host ('  Duration:        {0}s' -f $durationFormatted)
Write-Host ('  Rules applied:   {0}' -f $totalRuleCount)
Write-Host '---------------------------------------------'

$sevColors = @{ Critical = 'Red'; High = 'DarkYellow'; Medium = 'Yellow'; Low = 'Green'; Info = 'Gray' }
foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
    $count = $summary[$sev]
    $color = $sevColors[$sev]
    Write-Host ('  {0} {1}' -f $sev.PadRight(12), $count) -ForegroundColor $color
}

Write-Host '---------------------------------------------'
Write-Host ('  Total findings:  {0}' -f $allFindings.Count)
if ($riskScore -ge 80) { $riskColor = 'Red' } elseif ($riskScore -ge 50) { $riskColor = 'Yellow' } else { $riskColor = 'Green' }
Write-Host ('  Risk score:      {0} / 100' -f $riskScore) -ForegroundColor $riskColor
Write-Host '=============================================' -ForegroundColor Cyan
Write-Host ''

# ============================================================================
# REPORT GENERATION
# ============================================================================

$findingsArray = $allFindings.ToArray()

# HTML Report
$templatePath = Join-Path $templatesDir 'report.html'
if (Test-Path $templatePath) {
    try {
        Export-HtmlReport `
            -OutputPath $OutputPath `
            -TemplatePath $templatePath `
            -Findings $findingsArray `
            -SourcePath $SourcePath `
            -TotalFiles $files.Count `
            -TotalLines $totalLines `
            -DurationSeconds $duration `
            -RulesApplied $totalRuleCount
    } catch {
        Write-Warning ('HTML report error: {0}' -f $_)
        Write-Warning $_.ScriptStackTrace
    }
} else {
    Write-Warning ('HTML template not found: {0}' -f $templatePath)
}

# JSON Report
if ($JsonOutput) {
    try {
        Export-JsonReport `
            -OutputPath $JsonOutput `
            -Findings $findingsArray `
            -SourcePath $SourcePath `
            -TotalFiles $files.Count `
            -TotalLines $totalLines `
            -DurationSeconds $duration `
            -RulesApplied $totalRuleCount
    } catch {
        Write-Warning ('JSON report error: {0}' -f $_)
    }
}

# Return findings as output for pipeline use
$allFindings.ToArray()
