#Requires -Version 5.1
<#
.SYNOPSIS
    File system rules: path traversal, insecure temp files, ZIP slip.
#>

function Invoke-FileSystemRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Lines
    )

    $findings = @()

    # =========================================================================
    # SEC-FILE-001: Path Traversal
    # CWE-22 | OWASP A01:2021
    # =========================================================================
    $pathPatterns = @(
        '(?i)(File\.(Open|Read|Write|Delete|Copy|Move|Exists)|FileStream|StreamReader|StreamWriter)\s*\(.*?(\+|\$"|string\.Format)',
        'Server\.MapPath\s*\(.*(\+|\$"|string\.Format)',
        'Path\.Combine\s*\(.*(?:Request\.|TextBox|param|user|input)'
    )
    $pathWhitelist = @(
        'Path\.GetFullPath.*StartsWith',
        'AppDomain\.CurrentDomain\.BaseDirectory',
        '\.CanonicalPath',
        'Path\.GetFileName\s*\('  # extracting just filename — safe pattern
    )

    foreach ($pp in $pathPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $pp `
            -WhitelistPatterns $pathWhitelist `
            -RuleId 'SEC-FILE-001' `
            -Category 'Path Traversal' `
            -Severity 'High' `
            -Confidence 'Medium' `
            -CWE 'CWE-22' `
            -OWASP 'A01:2021' `
            -Description 'File path constructed with external input via concatenation. May allow access to files outside intended directory (e.g., ../../etc/passwd or ..\web.config).' `
            -Remediation 'Validate paths using Path.GetFullPath() and verify the result starts with the allowed base directory. Use Path.GetFileName() to strip directory components from user input.' `
            -References @('https://cwe.mitre.org/data/definitions/22.html')
    }

    # =========================================================================
    # SEC-FILE-002: Insecure Temporary Files
    # CWE-377
    # =========================================================================
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern 'Path\.GetTempPath\s*\(\s*\)\s*\+\s*(?!Path\.GetRandomFileName)' `
        -RuleId 'SEC-FILE-002' `
        -Category 'Insecure Temp File' `
        -Severity 'Medium' `
        -Confidence 'Medium' `
        -CWE 'CWE-377' `
        -Description 'Temporary file created with predictable name (GetTempPath + static string). Attacker can pre-create the file (symlink race) to hijack operations.' `
        -Remediation 'Use Path.GetTempFileName() or Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()) for unpredictable temp file names.' `
        -References @('https://cwe.mitre.org/data/definitions/377.html')

    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern 'new\s+FileInfo\s*\(\s*@?["'']C:\\Temp\\' `
        -RuleId 'SEC-FILE-002' `
        -Category 'Insecure Temp File' `
        -Severity 'Medium' `
        -Confidence 'High' `
        -CWE 'CWE-377' `
        -Description 'Hardcoded path to C:\Temp — shared directory with predictable location.' `
        -Remediation 'Use Path.GetTempPath() combined with Path.GetRandomFileName() for safe temp file handling.' `
        -References @('https://cwe.mitre.org/data/definitions/377.html')

    # =========================================================================
    # SEC-FILE-003: ZIP Slip
    # CWE-22 | CVE-2018-1002207
    # =========================================================================
    $zipPatterns = @(
        '(?i)(zipentry|ZipArchiveEntry).*FullName.*(?:File\.WriteAll|FileStream|ExtractToFile)',
        'ZipFile\.ExtractToDirectory'
    )
    foreach ($zp in $zipPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $zp `
            -WhitelistPatterns @('Path\.GetFullPath.*StartsWith', 'canonicalized', 'destinationPath.*StartsWith') `
            -RuleId 'SEC-FILE-003' `
            -Category 'ZIP Slip' `
            -Severity 'High' `
            -Confidence 'Medium' `
            -CWE 'CWE-22' `
            -OWASP 'A01:2021' `
            -Description 'ZIP archive extraction without path validation. Malicious archive entries with ../ paths can overwrite arbitrary files (ZIP Slip, CVE-2018-1002207).' `
            -Remediation 'Before extracting each entry, resolve the full path with Path.GetFullPath() and verify it starts with the intended destination directory.' `
            -References @('https://cwe.mitre.org/data/definitions/22.html', 'https://snyk.io/research/zip-slip-vulnerability')
    }

    return $findings
}

Export-ModuleMember -Function 'Invoke-FileSystemRules'
