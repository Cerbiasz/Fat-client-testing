#Requires -Version 5.1
<#
.SYNOPSIS
    Core Engine for .NET Security Scanner — parsing, context analysis, reporting.
.DESCRIPTION
    Provides the scanning engine, finding model, false-positive reduction,
    HTML/JSON report generation, and helper functions used by all rule modules.
#>

# ============================================================================
# FINDING MODEL
# ============================================================================

function New-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [Parameter(Mandatory)][ValidateSet('High','Medium','Low')][string]$Confidence,
        [Parameter(Mandatory)][string]$CWE,
        [string]$OWASP = '',
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][int]$LineNumber,
        [int]$ColumnNumber = 0,
        [string]$FunctionName = '',
        [string]$ClassName = '',
        [string]$Namespace = '',
        [Parameter(Mandatory)][string]$VulnerableCode,
        [string[]]$CodeContext = @(),
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Remediation,
        [string[]]$References = @(),
        [string[]]$FalsePositiveIndicators = @()
    )

    [PSCustomObject]@{
        RuleId                 = $RuleId
        Category               = $Category
        Severity               = $Severity
        Confidence             = $Confidence
        CWE                    = $CWE
        OWASP                  = $OWASP
        FilePath               = $FilePath
        LineNumber             = $LineNumber
        ColumnNumber           = $ColumnNumber
        FunctionName           = $FunctionName
        ClassName              = $ClassName
        Namespace              = $Namespace
        VulnerableCode         = $VulnerableCode
        CodeContext             = $CodeContext
        Description            = $Description
        Remediation            = $Remediation
        References             = $References
        FalsePositiveIndicators = $FalsePositiveIndicators
    }
}

# ============================================================================
# FILE READING & CONTEXT
# ============================================================================

function Read-SourceFile {
    <#
    .SYNOPSIS
        Reads a source file and returns lines array. Uses .NET for performance.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxFileSizeMB = 5
    )

    $fileInfo = [System.IO.FileInfo]::new($Path)
    if ($fileInfo.Length -gt ($MaxFileSizeMB * 1MB)) {
        $fileSizeMB = [math]::Round($fileInfo.Length/1MB,1)
        Write-Verbose ('SKIP: {0} exceeds {1}MB limit ({2}MB)' -f $Path, $MaxFileSizeMB, $fileSizeMB)
        return $null
    }

    try {
        # Try UTF-8 with BOM detection first, then fallback encodings
        $content = $null
        foreach ($enc in @([System.Text.Encoding]::UTF8, [System.Text.Encoding]::Default, [System.Text.Encoding]::Unicode)) {
            try {
                $content = [System.IO.File]::ReadAllLines($Path, $enc)
                if ($null -ne $content -and $content.Length -gt 0) { break }
            } catch { }
        }

        # Validate we got real content (not just empty lines from BOM-only files)
        if ($null -eq $content -or $content.Length -eq 0) {
            Write-Verbose ('SKIP: {0} is empty or unreadable' -f $Path)
            return $null
        }

        # Check if file has any non-empty lines (reject BOM-only / whitespace-only files)
        $hasRealContent = $false
        foreach ($ln in $content) {
            if ($ln.Trim() -ne '') { $hasRealContent = $true; break }
        }
        if (-not $hasRealContent) {
            Write-Verbose ('SKIP: {0} has no meaningful content' -f $Path)
            return $null
        }

        # CRITICAL: Use comma operator to prevent PS 5.1 from unwrapping
        # single-element arrays to scalar strings
        return ,$content
    }
    catch {
        Write-Warning ('Cannot read file: {0} - {1}' -f $Path, $_)
        return $null
    }
}

function Get-CodeContext {
    <#
    .SYNOPSIS
        Returns N lines before and after the target line for context display.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][int]$LineNumber,
        [int]$ContextSize = 5
    )

    $startIdx = [Math]::Max(0, $LineNumber - 1 - $ContextSize)
    $endIdx   = [Math]::Min($Lines.Count - 1, $LineNumber - 1 + $ContextSize)

    $context = @()
    for ($i = $startIdx; $i -le $endIdx; $i++) {
        $prefix = if ($i -eq ($LineNumber - 1)) { '>' } else { ' ' }
        $lineText = $Lines[$i]
        # Truncate mega-lines (single-line decompiled files) to keep reports readable
        if ($lineText.Length -gt 600) {
            $lineText = $lineText.Substring(0, 300) + ' [...truncated...] ' + $lineText.Substring($lineText.Length - 300)
        }
        $context += "{0}{1,4}: {2}" -f $prefix, ($i + 1), $lineText
    }
    return $context
}

function Get-SlidingWindowText {
    <#
    .SYNOPSIS
        Joins N lines around the target into a single string for multi-line pattern matching.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][int]$CenterLineIndex,
        [int]$WindowSize = 15
    )

    $startIdx = [Math]::Max(0, $CenterLineIndex - $WindowSize)
    $endIdx   = [Math]::Min($Lines.Count - 1, $CenterLineIndex + $WindowSize)

    ($Lines[$startIdx..$endIdx]) -join "`n"
}

function Get-TruncatedVulnCode {
    <#
    .SYNOPSIS
        Truncates a line for VulnerableCode display (max ~500 chars around match).
        For use in manual New-Finding calls. Invoke-RegexRuleOnFile already does this.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Line,
        [int]$MaxLength = 500
    )
    $trimmed = $Line.Trim()
    if ($trimmed.Length -le $MaxLength) { return $trimmed }
    $half = [Math]::Floor($MaxLength / 2)
    return $trimmed.Substring(0, $half) + ' [...] ' + $trimmed.Substring($trimmed.Length - $half)
}

# ============================================================================
# COMMENT STRIPPING
# ============================================================================

function Remove-Comments {
    <#
    .SYNOPSIS
        Strips C#/SQL comments from code while preserving string literals.
        Known limitation: // inside string literals (e.g. URLs) may cause
        partial stripping. String literals are replaced with placeholders first
        to minimize this, but nested/escaped quotes can still cause issues.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Code
    )

    # Phase 1: Replace string literals with placeholders
    $stringMap = @{}
    $counter = 0
    $placeholder = '__STR_{0}__'

    # Match @"verbatim strings" and "regular strings" (with escaped quotes)
    $stringPattern = '@"[^"]*(?:""[^"]*)*"|"(?:[^"\\]|\\.)*"'
    $codeWithPlaceholders = [regex]::Replace($Code, $stringPattern, {
        param($m)
        $key = $placeholder -f $counter
        $stringMap[$key] = $m.Value
        $counter++
        return $key
    })

    # Phase 2: Remove multi-line comments
    $codeWithPlaceholders = [regex]::Replace($codeWithPlaceholders, '/\*[\s\S]*?\*/', '')

    # Phase 3: Remove single-line comments
    $codeWithPlaceholders = [regex]::Replace($codeWithPlaceholders, '//.*$', '', [System.Text.RegularExpressions.RegexOptions]::Multiline)

    # Phase 4: Restore string literals
    foreach ($key in $stringMap.Keys) {
        $codeWithPlaceholders = $codeWithPlaceholders.Replace($key, $stringMap[$key])
    }

    return $codeWithPlaceholders
}

# ============================================================================
# CLASS / METHOD / NAMESPACE EXTRACTION
# ============================================================================

function Get-ContainingClass {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][int]$LineIndex
    )

    for ($i = $LineIndex; $i -ge 0; $i--) {
        if ($Lines[$i] -match '(?:public|private|internal|protected|static|abstract|sealed|partial)\s+class\s+(\w+)') {
            return $Matches[1]
        }
    }
    return ''
}

function Get-ContainingMethod {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][int]$LineIndex
    )

    for ($i = $LineIndex; $i -ge 0; $i--) {
        if ($Lines[$i] -match '(?:public|private|internal|protected|static|virtual|override|async)\s+\w+[\w<>\[\],\s]*?\s+(\w+)\s*\(') {
            return $Matches[1]
        }
    }
    return ''
}

function Get-ContainingNamespace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][int]$LineIndex
    )

    for ($i = $LineIndex; $i -ge 0; $i--) {
        if ($Lines[$i] -match '^\s*namespace\s+([\w.]+)') {
            return $Matches[1]
        }
    }
    return ''
}

# ============================================================================
# FALSE POSITIVE REDUCTION
# ============================================================================

function Test-IsDeadCode {
    <#
    .SYNOPSIS
        Checks if the line is inside a comment, #if DEBUG, or [Obsolete] block.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][int]$LineIndex
    )

    $line = $Lines[$LineIndex]

    # Single-line comment
    if ($line -match '^\s*//') { return $true }

    # Check for #if DEBUG block
    $inDebugBlock = $false
    for ($i = $LineIndex; $i -ge 0; $i--) {
        if ($Lines[$i] -match '^\s*#if\s+DEBUG') { $inDebugBlock = $true; break }
        if ($Lines[$i] -match '^\s*#endif') { break }
        if ($Lines[$i] -match '^\s*#else') { break }
    }
    if ($inDebugBlock) { return $true }

    # Check for [Obsolete] attribute on method/class
    for ($i = $LineIndex; $i -ge [Math]::Max(0, $LineIndex - 5); $i--) {
        if ($Lines[$i] -match '\[Obsolete') { return $true }
        if ($Lines[$i] -match '^\s*(public|private|internal|protected)') { break }
    }

    return $false
}

function Test-IsTestFile {
    <#
    .SYNOPSIS
        Checks if the file path suggests a test file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath
    )

    $testPatterns = @(
        '[\\/]tests?[\\/]',
        '[\\/]test[\\/]',
        'Test\.cs$',
        'Tests\.cs$',
        'Mock\w*\.cs$',
        'Stub\w*\.cs$',
        'Fake\w*\.cs$',
        '\.Test\.',
        '\.Tests\.',
        'Fixture\.cs$',
        'Spec\.cs$'
    )

    foreach ($pattern in $testPatterns) {
        if ($FilePath -match $pattern) { return $true }
    }
    return $false
}

function Test-WhitelistMatch {
    <#
    .SYNOPSIS
        Checks if any whitelist pattern is present in the context around the finding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][int]$LineIndex,
        [Parameter(Mandatory)][string[]]$WhitelistPatterns,
        [int]$ContextRange = 15
    )

    $startIdx = [Math]::Max(0, $LineIndex - $ContextRange)
    $endIdx   = [Math]::Min($Lines.Count - 1, $LineIndex + $ContextRange)
    $contextBlock = ($Lines[$startIdx..$endIdx]) -join "`n"

    foreach ($pattern in $WhitelistPatterns) {
        if ($contextBlock -match $pattern) {
            return $true
        }
    }
    return $false
}

function Test-ContextContains {
    <#
    .SYNOPSIS
        Checks if a pattern exists within N lines around the target line.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][int]$LineIndex,
        [Parameter(Mandatory)][string]$Pattern,
        [int]$Range = 15
    )

    $startIdx = [Math]::Max(0, $LineIndex - $Range)
    $endIdx   = [Math]::Min($Lines.Count - 1, $LineIndex + $Range)
    $contextBlock = ($Lines[$startIdx..$endIdx]) -join "`n"

    return ($contextBlock -match $Pattern)
}

# ============================================================================
# FILE DISCOVERY
# ============================================================================

function Get-SourceFiles {
    <#
    .SYNOPSIS
        Discovers source files to scan, applying exclusion filters.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [string[]]$ExcludePaths = @(),
        [switch]$ScanTests,
        [string[]]$Extensions = @('*.cs', '*.config', '*.xml', '*.sql', '*.pks', '*.pkb', '*.resx', '*.trg', '*.prc', '*.fnc')
    )

    $files = @()
    foreach ($ext in $Extensions) {
        $files += Get-ChildItem -Path $SourcePath -Filter $ext -Recurse -File -ErrorAction SilentlyContinue
    }

    # Apply exclusion patterns
    $filtered = @()
    foreach ($file in $files) {
        $relativePath = $file.FullName
        $excluded = $false

        foreach ($pattern in $ExcludePaths) {
            if ($relativePath -match $pattern) {
                $excluded = $true
                break
            }
        }

        if (-not $ScanTests -and (Test-IsTestFile -FilePath $relativePath)) {
            $excluded = $true
        }

        if (-not $excluded) {
            $filtered += $file
        }
    }

    return $filtered
}

# ============================================================================
# RISK SCORE CALCULATION
# ============================================================================

function Get-RiskScore {
    <#
    .SYNOPSIS
        Calculates risk score 0-100 based on finding severities.
        MaxRawScore = 50 (saturation point).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$Findings
    )

    $weights = @{
        'Critical' = 10
        'High'     = 5
        'Medium'   = 2
        'Low'      = 1
        'Info'     = 0
    }

    $rawScore = 0
    foreach ($f in $Findings) {
        $rawScore += $weights[$f.Severity]
    }

    $maxRaw = 50
    [Math]::Min(100, [Math]::Round($rawScore / $maxRaw * 100))
}

# ============================================================================
# SEVERITY SUMMARY
# ============================================================================

function Get-SeveritySummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][PSCustomObject[]]$Findings
    )

    $summary = [ordered]@{
        Critical = 0
        High     = 0
        Medium   = 0
        Low      = 0
        Info     = 0
    }

    foreach ($f in $Findings) {
        if ($summary.Contains($f.Severity)) {
            $summary[$f.Severity]++
        }
    }

    return $summary
}

# ============================================================================
# JSON REPORT
# ============================================================================

function Export-JsonReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][AllowEmptyCollection()][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][string]$SourcePath,
        [int]$TotalFiles,
        [long]$TotalLines,
        [double]$DurationSeconds,
        [int]$RulesApplied
    )

    $summary = Get-SeveritySummary -Findings $Findings
    $riskScore = if ($Findings.Count -gt 0) { Get-RiskScore -Findings $Findings } else { 0 }

    $report = [ordered]@{
        scan_metadata = [ordered]@{
            scan_date            = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
            scanner_version      = '2.2.0'
            source_path          = $SourcePath
            total_files_scanned  = $TotalFiles
            total_lines_scanned  = $TotalLines
            scan_duration_seconds = [Math]::Round($DurationSeconds, 2)
            rules_applied        = $RulesApplied
        }
        summary = [ordered]@{
            critical   = $summary['Critical']
            high       = $summary['High']
            medium     = $summary['Medium']
            low        = $summary['Low']
            info       = $summary['Info']
            risk_score = $riskScore
        }
        findings = @(
            foreach ($f in $Findings) {
                [ordered]@{
                    rule_id          = $f.RuleId
                    category         = $f.Category
                    severity         = $f.Severity
                    confidence       = $f.Confidence
                    cwe              = $f.CWE
                    owasp            = $f.OWASP
                    file             = $f.FilePath
                    line             = $f.LineNumber
                    column           = $f.ColumnNumber
                    function         = $f.FunctionName
                    class            = $f.ClassName
                    namespace        = $f.Namespace
                    vulnerable_code  = $f.VulnerableCode
                    code_context     = $f.CodeContext
                    description      = $f.Description
                    remediation      = $f.Remediation
                    references       = $f.References
                }
            }
        )
    }

    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "[+] JSON report saved: $OutputPath" -ForegroundColor Green
}

# ============================================================================
# HTML REPORT
# ============================================================================

function Export-HtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$TemplatePath,
        [Parameter(Mandatory)][AllowEmptyCollection()][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][string]$SourcePath,
        [int]$TotalFiles,
        [long]$TotalLines,
        [double]$DurationSeconds,
        [int]$RulesApplied
    )

    try {

    $summary = Get-SeveritySummary -Findings $Findings
    $riskScore = if ($Findings.Count -gt 0) { Get-RiskScore -Findings $Findings } else { 0 }

    # Read template
    $html = [System.IO.File]::ReadAllText($TemplatePath, [System.Text.Encoding]::UTF8)

    # HTML encode helper — fallback if System.Web not loaded
    $encFn = {
        param([string]$s)
        if ([string]::IsNullOrEmpty($s)) { return '' }
        try { return [System.Web.HttpUtility]::HtmlEncode($s) }
        catch { return $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;') }
    }

    $sevCssMap = @{ 'Critical' = 'sev-c'; 'High' = 'sev-h'; 'Medium' = 'sev-m'; 'Low' = 'sev-l'; 'Info' = 'sev-i' }

    # Build findings HTML rows — use StringBuilder for performance
    $sb = New-Object System.Text.StringBuilder 65536
    $idx = 0

    $sorted = @($Findings | Sort-Object @{Expression={
        switch ($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} 'Low'{3} 'Info'{4} default{5} }
    }})

    foreach ($f in $sorted) {
        $idx++
        $severityClass = $f.Severity.ToLower()
        $sevCss = $sevCssMap[$f.Severity]
        if (-not $sevCss) { $sevCss = 'sev-i' }

        $ctxLines = @()
        if ($f.CodeContext) { $ctxLines = @($f.CodeContext) }
        $escapedContext = ($ctxLines | ForEach-Object { & $encFn $_ }) -join "`n"
        $escapedDesc = & $encFn $f.Description
        $escapedRem = & $encFn $f.Remediation

        $refsArr = @()
        if ($f.References) { $refsArr = @($f.References) }
        $refsHtml = ($refsArr | ForEach-Object {
            if ($_ -match '^https?://') { "<a href='$_' target='_blank'>$_</a>" } else { & $encFn $_ }
        }) -join '<br/>'

        $fFileName = [System.IO.Path]::GetFileName($f.FilePath)
        $escapedPath = & $encFn $f.FilePath

        # Finding summary row
        [void]$sb.Append('<tr class="finding-row" data-severity="')
        [void]$sb.Append($severityClass)
        [void]$sb.Append('" data-category="')
        [void]$sb.Append($f.Category)
        [void]$sb.Append('" data-file="')
        [void]$sb.Append($f.FilePath)
        [void]$sb.Append('" data-confidence="')
        [void]$sb.Append($f.Confidence)
        [void]$sb.Append('" onclick="toggleDetail(''detail-')
        [void]$sb.Append($idx)
        [void]$sb.AppendLine(''')">')
        [void]$sb.Append('<td><span class="sev ').Append($sevCss).Append('">').Append($f.Severity).AppendLine('</span></td>')
        [void]$sb.Append('<td>').Append($f.RuleId).AppendLine('</td>')
        [void]$sb.Append('<td>').Append($f.Category).AppendLine('</td>')
        [void]$sb.Append('<td class="file-cell" title="').Append($escapedPath).Append('">').Append($fFileName).AppendLine('</td>')
        [void]$sb.Append('<td>').Append($f.LineNumber).AppendLine('</td>')
        [void]$sb.Append('<td>').Append($f.Confidence).AppendLine('</td>')
        [void]$sb.Append('<td>').Append($f.CWE).AppendLine('</td>')
        [void]$sb.AppendLine('</tr>')

        # Detail row (hidden by default)
        [void]$sb.Append('<tr class="detail-row" id="detail-').Append($idx).AppendLine('" style="display:none">')
        [void]$sb.AppendLine('<td colspan="7"><div class="detail-box">')
        [void]$sb.Append('<h4>').Append($f.RuleId).Append(' &mdash; ').Append($f.Category)
        [void]$sb.Append(' <span class="sev ').Append($sevCss).Append('">').Append($f.Severity).AppendLine('</span></h4>')
        [void]$sb.AppendLine('<div class="detail-meta">')
        [void]$sb.Append('<span>File: <code>').Append($escapedPath).AppendLine('</code></span>')
        [void]$sb.Append('<span>Line: ').Append($f.LineNumber).Append(' Col: ').Append($f.ColumnNumber).AppendLine('</span>')
        [void]$sb.Append('<span>Class: <code>').Append($f.ClassName).Append('</code> Method: <code>').Append($f.FunctionName).AppendLine('</code></span>')
        [void]$sb.Append('<span>Namespace: <code>').Append($f.Namespace).AppendLine('</code></span>')
        [void]$sb.Append('<span>CWE: ').Append($f.CWE).Append(' OWASP: ').Append($f.OWASP).AppendLine('</span>')
        [void]$sb.AppendLine('</div>')
        [void]$sb.AppendLine('<div class="detail-section"><h4>Vulnerable Code</h4>')
        [void]$sb.Append('<pre class="code-block">').Append($escapedContext).AppendLine('</pre></div>')
        [void]$sb.AppendLine('<div class="detail-section"><h4>Description</h4>')
        [void]$sb.Append('<p>').Append($escapedDesc).AppendLine('</p></div>')
        [void]$sb.AppendLine('<div class="detail-section"><h4>Remediation</h4>')
        [void]$sb.Append('<p>').Append($escapedRem).AppendLine('</p></div>')
        [void]$sb.AppendLine('<div class="detail-section"><h4>References</h4>')
        [void]$sb.Append('<p>').Append($refsHtml).AppendLine('</p></div>')
        [void]$sb.AppendLine('</div></td></tr>')
    }
    $findingsHtml = $sb.ToString()

    # Top 5 critical findings
    $top5Html = ''
    $top5 = @($sorted | Select-Object -First 5)
    foreach ($f in $top5) {
        $sevCss5 = $sevCssMap[$f.Severity]
        if (-not $sevCss5) { $sevCss5 = 'sev-i' }
        $fname = [System.IO.Path]::GetFileName($f.FilePath)
        $top5Html += "<li><span class='sev $sevCss5'>$($f.Severity)</span> <strong>$($f.RuleId)</strong>: $($f.Category) in <code>${fname}:$($f.LineNumber)</code></li>"
    }

    # Files with most findings
    $fileStatsHtml = ''
    if ($Findings.Count -gt 0) {
        $fileStats = @($Findings | Group-Object FilePath | Sort-Object Count -Descending | Select-Object -First 10)
        foreach ($fs in $fileStats) {
            $fsFName = [System.IO.Path]::GetFileName($fs.Name)
            $fsNameEsc = & $encFn $fs.Name
            $fileStatsHtml += "<tr><td class='file-cell' title='$fsNameEsc'>$fsFName</td><td>$($fs.Count)</td></tr>"
        }
    }

    # Category stats
    $catStatsHtml = ''
    if ($Findings.Count -gt 0) {
        $catStats = @($Findings | Group-Object Category | Sort-Object Count -Descending)
        $maxCat = ($catStats | Measure-Object -Property Count -Maximum).Maximum
        if ($maxCat -lt 1) { $maxCat = 1 }
        foreach ($cs in $catStats) {
            $barWidth = [Math]::Round($cs.Count / $maxCat * 100)
            $catStatsHtml += "<div class='bar-row'><span class='bar-label'>$($cs.Name)</span><div class='bar-container'><div class='bar-fill' style='width:${barWidth}%'></div></div><span class='bar-count'>$($cs.Count)</span></div>"
        }
    }

    # Low confidence findings
    $lowConfHtml = ''
    $lowConfFindings = @($Findings | Where-Object { $_.Confidence -eq 'Low' })
    foreach ($lf in $lowConfFindings) {
        $lfFName = [System.IO.Path]::GetFileName($lf.FilePath)
        $lowConfHtml += "<tr><td>$($lf.RuleId)</td><td>$($lf.Category)</td><td>${lfFName}:$($lf.LineNumber)</td><td>Requires manual verification</td></tr>"
    }

    # Risk gauge color
    $riskColor = '#1a7f37'
    if ($riskScore -ge 80) { $riskColor = '#cf222e' }
    elseif ($riskScore -ge 60) { $riskColor = '#bc4c00' }
    elseif ($riskScore -ge 40) { $riskColor = '#9a6700' }
    elseif ($riskScore -ge 20) { $riskColor = '#1a7f37' }

    # Replace placeholders
    $scanDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $html = $html.Replace('{{SCAN_DATE}}', $scanDate)
    $html = $html.Replace('{{SOURCE_PATH}}', (& $encFn $SourcePath))
    $html = $html.Replace('{{TOTAL_FILES}}', $TotalFiles.ToString())
    $html = $html.Replace('{{TOTAL_LINES}}', $TotalLines.ToString('N0'))
    $html = $html.Replace('{{DURATION}}', ([Math]::Round($DurationSeconds, 2)).ToString())
    $html = $html.Replace('{{RULES_APPLIED}}', $RulesApplied.ToString())
    $html = $html.Replace('{{CRITICAL_COUNT}}', $summary['Critical'].ToString())
    $html = $html.Replace('{{HIGH_COUNT}}', $summary['High'].ToString())
    $html = $html.Replace('{{MEDIUM_COUNT}}', $summary['Medium'].ToString())
    $html = $html.Replace('{{LOW_COUNT}}', $summary['Low'].ToString())
    $html = $html.Replace('{{INFO_COUNT}}', $summary['Info'].ToString())
    $html = $html.Replace('{{RISK_SCORE}}', $riskScore.ToString())
    $html = $html.Replace('{{RISK_COLOR}}', $riskColor)
    $html = $html.Replace('{{TOTAL_FINDINGS}}', $Findings.Count.ToString())
    $html = $html.Replace('{{FINDINGS_ROWS}}', $findingsHtml)
    $html = $html.Replace('{{TOP5_FINDINGS}}', $top5Html)
    $html = $html.Replace('{{FILE_STATS_ROWS}}', $fileStatsHtml)
    $html = $html.Replace('{{CATEGORY_STATS}}', $catStatsHtml)
    $html = $html.Replace('{{LOW_CONF_ROWS}}', $lowConfHtml)

    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.Encoding]::UTF8)
    Write-Host "[+] HTML report saved: $OutputPath" -ForegroundColor Green

    } catch {
        Write-Warning "HTML report generation failed: $_"
        Write-Warning $_.ScriptStackTrace
    }
}

# ============================================================================
# RULE RUNNER HELPER
# ============================================================================

function Invoke-RegexRuleOnFile {
    <#
    .SYNOPSIS
        Runs a single regex-based rule against a file's lines.
        Returns findings array. Handles context, whitelist, dead-code checks.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][string]$Pattern,
        [string]$ContextPattern = '',
        [string[]]$WhitelistPatterns = @(),
        [string]$MustNotHavePattern = '',
        [int]$ContextRange = 15,
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][string]$Confidence,
        [Parameter(Mandatory)][string]$CWE,
        [string]$OWASP = '',
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Remediation,
        [string[]]$References = @()
    )

    $findings = @()

    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i]

        if ($line -notmatch $Pattern) { continue }

        # Dead code check
        if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }

        # Context pattern required?
        if ($ContextPattern -and -not (Test-ContextContains -Lines $Lines -LineIndex $i -Pattern $ContextPattern -Range $ContextRange)) {
            continue
        }

        # Must NOT have pattern in context?
        if ($MustNotHavePattern -and (Test-ContextContains -Lines $Lines -LineIndex $i -Pattern $MustNotHavePattern -Range $ContextRange)) {
            continue
        }

        # Whitelist check
        if ($WhitelistPatterns.Count -gt 0 -and (Test-WhitelistMatch -Lines $Lines -LineIndex $i -WhitelistPatterns $WhitelistPatterns -ContextRange $ContextRange)) {
            continue
        }

        # Extract matched text and surrounding context for VulnerableCode
        $matchedText = if ($Matches -and $Matches[0]) { $Matches[0] } else { '' }
        $colIdx = if ($matchedText) { $line.IndexOf($matchedText) } else { 0 }
        if ($colIdx -lt 0) { $colIdx = 0 }

        # For very long lines (minified/single-line), extract context around the match
        $vulnCode = $line.Trim()
        if ($vulnCode.Length -gt 500 -and $matchedText) {
            $contextStart = [Math]::Max(0, $colIdx - 100)
            $contextEnd = [Math]::Min($vulnCode.Length, $colIdx + $matchedText.Length + 100)
            $prefix = if ($contextStart -gt 0) { '...' } else { '' }
            $suffix = if ($contextEnd -lt $vulnCode.Length) { '...' } else { '' }
            $vulnCode = $prefix + $vulnCode.Substring($contextStart, $contextEnd - $contextStart) + $suffix
        }

        $findings += New-Finding `
            -RuleId $RuleId `
            -Category $Category `
            -Severity $Severity `
            -Confidence $Confidence `
            -CWE $CWE `
            -OWASP $OWASP `
            -FilePath $FilePath `
            -LineNumber ($i + 1) `
            -ColumnNumber $colIdx `
            -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
            -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
            -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
            -VulnerableCode $vulnCode `
            -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
            -Description $Description `
            -Remediation $Remediation `
            -References $References
    }

    return $findings
}

function Invoke-MultiLineRuleOnFile {
    <#
    .SYNOPSIS
        Runs a regex rule against sliding windows (multi-line patterns).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][string]$Pattern,
        [string[]]$WhitelistPatterns = @(),
        [string]$MustNotHavePattern = '',
        [int]$WindowSize = 15,
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][string]$Confidence,
        [Parameter(Mandatory)][string]$CWE,
        [string]$OWASP = '',
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Remediation,
        [string[]]$References = @()
    )

    $findings = @()
    $matchedLines = @{}

    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $window = Get-SlidingWindowText -Lines $Lines -CenterLineIndex $i -WindowSize $WindowSize

        if ($window -notmatch $Pattern) { continue }
        if ($matchedLines.ContainsKey($i)) { continue }

        # Dead code
        if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }

        # Whitelist
        if ($WhitelistPatterns.Count -gt 0) {
            $skip = $false
            foreach ($wl in $WhitelistPatterns) {
                if ($window -match $wl) { $skip = $true; break }
            }
            if ($skip) { continue }
        }

        # Must NOT have
        if ($MustNotHavePattern -and ($window -match $MustNotHavePattern)) { continue }

        $matchedLines[$i] = $true

        $findings += New-Finding `
            -RuleId $RuleId `
            -Category $Category `
            -Severity $Severity `
            -Confidence $Confidence `
            -CWE $CWE `
            -OWASP $OWASP `
            -FilePath $FilePath `
            -LineNumber ($i + 1) `
            -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
            -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
            -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
            -VulnerableCode $Lines[$i].Trim() `
            -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
            -Description $Description `
            -Remediation $Remediation `
            -References $References
    }

    return $findings
}

# ============================================================================
# EXPORTS
# ============================================================================

Export-ModuleMember -Function @(
    'New-Finding',
    'Read-SourceFile',
    'Get-CodeContext',
    'Get-SlidingWindowText',
    'Get-TruncatedVulnCode',
    'Remove-Comments',
    'Get-ContainingClass',
    'Get-ContainingMethod',
    'Get-ContainingNamespace',
    'Test-IsDeadCode',
    'Test-IsTestFile',
    'Test-WhitelistMatch',
    'Test-ContextContains',
    'Get-SourceFiles',
    'Get-RiskScore',
    'Get-SeveritySummary',
    'Export-JsonReport',
    'Export-HtmlReport',
    'Invoke-RegexRuleOnFile',
    'Invoke-MultiLineRuleOnFile'
)
