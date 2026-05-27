#Requires -Version 5.1
<#
.SYNOPSIS
    Data exposure rules: sensitive data logging, data in URLs, stack traces, IDOR.
#>

function Invoke-DataExposureRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Lines
    )

    $findings = @()

    # =========================================================================
    # SEC-DATA-001: Logging sensitive data
    # CWE-532 | OWASP A09:2021
    # =========================================================================
    $logPatterns = @(
        '(?i)(log|logger|trace|debug|console)\.\s*(Write|Error|Warn|Info|Debug|Fatal|WriteLine)\s*\(.*(?:password|passwd|pwd|secret|token|ssn|pesel|credit.?card|cvv|pin)',
        '(?i)(NLog|log4net|Serilog).*(?:password|passwd|token|secret|credit.?card)',
        'Console\.(Write|WriteLine)\s*\(.*(?i)(password|token|secret|key)'
    )
    foreach ($lp in $logPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $lp `
            -RuleId 'SEC-DATA-001' `
            -Category 'Sensitive Data Logging' `
            -Severity 'High' `
            -Confidence 'Medium' `
            -CWE 'CWE-532' `
            -OWASP 'A09:2021' `
            -Description 'Sensitive data (password, token, SSN, credit card) written to logs. Log files are often accessible to operations teams and may be sent to centralized logging systems.' `
            -Remediation 'Never log sensitive data. Mask or redact credentials, tokens, and PII before logging. Use structured logging with explicit field filtering.' `
            -References @('https://cwe.mitre.org/data/definitions/532.html')
    }

    # Multi-line: sensitive var assigned, then logged on next line
    $findings += Invoke-MultiLineRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern '(?i)(password|token|secret)\s*=.*;\s*\n.*(?:log|trace|debug)' `
        -WindowSize 3 `
        -RuleId 'SEC-DATA-001' `
        -Category 'Sensitive Data Logging' `
        -Severity 'High' `
        -Confidence 'Low' `
        -CWE 'CWE-532' `
        -OWASP 'A09:2021' `
        -Description 'Sensitive variable assigned and potentially logged on the following line.' `
        -Remediation 'Verify that the sensitive variable value is not included in the log statement.' `
        -References @('https://cwe.mitre.org/data/definitions/532.html')

    # =========================================================================
    # SEC-DATA-002: Sensitive data in URL / query string
    # CWE-598
    # =========================================================================
    $urlPatterns = @(
        '(?i)(password|token|secret|ssn|creditcard)\s*=.*Request\.QueryString',
        'HttpUtility\.UrlEncode\s*\(.*(?i)(password|token|secret)',
        'new\s+Uri\s*\(.*\+.*(?i)(password|token|apikey)',
        '(?i)Request\.QueryString\[["''](password|token|secret|key)["'']\]'
    )
    foreach ($up in $urlPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $up `
            -RuleId 'SEC-DATA-002' `
            -Category 'Sensitive Data in URL' `
            -Severity 'High' `
            -Confidence 'High' `
            -CWE 'CWE-598' `
            -OWASP 'A04:2021' `
            -Description 'Sensitive data passed via URL query string. URLs are logged in server logs, browser history, and referrer headers.' `
            -Remediation 'Transmit sensitive data via POST body or HTTP headers (e.g., Authorization header). Never include credentials in URLs.' `
            -References @('https://cwe.mitre.org/data/definitions/598.html')
    }

    # =========================================================================
    # SEC-DATA-003: Stack trace exposed to user
    # CWE-209 | OWASP A05:2021
    # =========================================================================
    $stackPatterns = @(
        '(?:MessageBox\.Show|Response\.Write|\.Text\s*=)\s*.*(?:ex\.StackTrace|ex\.ToString\(\)|e\.StackTrace|e\.ToString\(\))',
        '\.InnerException\.ToString\(\)',
        'Exception\.ToString\(\).*(?:Response|MessageBox|Label|textBox)'
    )
    foreach ($sp in $stackPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $sp `
            -RuleId 'SEC-DATA-003' `
            -Category 'Information Disclosure' `
            -Severity 'Medium' `
            -Confidence 'High' `
            -CWE 'CWE-209' `
            -OWASP 'A05:2021' `
            -Description 'Stack trace or exception details displayed to the user. This reveals internal implementation details, file paths, class names, and potentially sensitive configuration.' `
            -Remediation 'Show generic error messages to users. Log full exception details server-side. Use a global exception handler.' `
            -References @('https://cwe.mitre.org/data/definitions/209.html')
    }

    # =========================================================================
    # SEC-DATA-004: Insecure Direct Object Reference (IDOR)
    # CWE-639
    # =========================================================================
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern '(?i)WHERE\s+\w*[Ii][Dd]\s*=\s*.*(?:Request\.|TextBox|param|input|Convert\.ToInt)' `
        -MustNotHavePattern 'IsOwner|CheckAccess|HasPermission|AuthorizeResource' `
        -RuleId 'SEC-DATA-004' `
        -Category 'IDOR' `
        -Severity 'High' `
        -Confidence 'Low' `
        -CWE 'CWE-639' `
        -OWASP 'A01:2021' `
        -Description 'Database query uses ID directly from user input without visible ownership/access verification. May allow unauthorized access to other users data.' `
        -Remediation 'Always verify that the authenticated user owns or has permission to access the requested resource before returning data.' `
        -References @('https://cwe.mitre.org/data/definitions/639.html')

    # =========================================================================
    # SEC-DATA-005: X509CertificateValidationMode.None
    # CWE-295
    # =========================================================================
    $certPatterns = @(
        'X509CertificateValidationMode\s*=\s*X509CertificateValidationMode\.None',
        'CertificateValidationMode\s*=\s*["'']?None',
        'certificateValidationMode\s*=\s*["'']None["'']',
        'X509RevocationMode\s*=\s*X509RevocationMode\.NoCheck'
    )
    foreach ($cvp in $certPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $cvp `
            -RuleId 'SEC-DATA-005' `
            -Category 'Certificate Validation Bypass' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-295' `
            -OWASP 'A07:2021' `
            -Description 'X509 certificate validation disabled (None). Any certificate, including self-signed, expired, or revoked, will be accepted. Enables MITM attacks.' `
            -Remediation 'Set CertificateValidationMode to ChainTrust or PeerOrChainTrust. Enable revocation checking with X509RevocationMode.Online.' `
            -References @('https://cwe.mitre.org/data/definitions/295.html')
    }

    # =========================================================================
    # SEC-DATA-006: X509Certificate2 private key exposure
    # CWE-311
    # =========================================================================
    $pkeyPatterns = @(
        'X509Certificate2.*Export\s*\(\s*X509ContentType\.Pfx',
        'X509Certificate2.*\.PrivateKey\s*\.\s*ToXmlString\s*\(\s*true',
        'RSACryptoServiceProvider.*\.ExportParameters\s*\(\s*true',
        'X509Certificate2.*X509KeyStorageFlags\.Exportable'
    )
    foreach ($pkp in $pkeyPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $pkp `
            -RuleId 'SEC-DATA-006' `
            -Category 'Private Key Exposure' `
            -Severity 'High' `
            -Confidence 'High' `
            -CWE 'CWE-311' `
            -OWASP 'A02:2021' `
            -Description 'X509 private key exported or marked as exportable. Private keys should remain in secure key storage and never be extracted to memory or files.' `
            -Remediation 'Use X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.NonExportable. Store certificates in Windows Certificate Store or HSM.' `
            -References @('https://cwe.mitre.org/data/definitions/311.html')
    }

    # =========================================================================
    # SEC-DATA-007: Unsigned / unvalidated security tokens
    # CWE-345
    # =========================================================================
    $tokenPatterns = @(
        'TokenValidationParameters.*ValidateIssuerSigningKey\s*=\s*false',
        'TokenValidationParameters.*RequireSignedTokens\s*=\s*false',
        'TokenValidationParameters.*ValidateLifetime\s*=\s*false',
        'TokenValidationParameters.*ValidateAudience\s*=\s*false.*ValidateIssuer\s*=\s*false',
        'JwtSecurityTokenHandler.*ValidateToken.*TokenValidationParameters'
    )
    foreach ($tp in $tokenPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $tp `
            -RuleId 'SEC-DATA-007' `
            -Category 'Unsigned Security Token' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-345' `
            -OWASP 'A07:2021' `
            -Description 'JWT/security token validation weakened or disabled. Unsigned or unvalidated tokens allow attackers to forge authentication claims.' `
            -Remediation 'Set ValidateIssuerSigningKey=true, RequireSignedTokens=true, ValidateLifetime=true. Validate both issuer and audience.' `
            -References @('https://cwe.mitre.org/data/definitions/345.html')
    }

    # =========================================================================
    # SEC-DATA-008: SecureString plaintext leak — missing ZeroFree cleanup
    # CWE-316
    # =========================================================================
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match 'Marshal\.SecureString(?:ToGlobalAllocUnicode|ToBSTR|ToCoTaskMemUnicode)\s*\(') {
            if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }
            # Check for proper cleanup (ZeroFree) within 20 lines
            if (Test-ContextContains -Lines $Lines -LineIndex $i -Pattern 'Marshal\.ZeroFree(?:GlobalAllocUnicode|BSTR|CoTaskMemUnicode)|finally' -Range 20) { continue }

            $findings += New-Finding `
                -RuleId 'SEC-DATA-008' `
                -Category 'Credential Memory Leak' `
                -Severity 'High' `
                -Confidence 'Medium' `
                -CWE 'CWE-316' `
                -OWASP 'A02:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode (Get-TruncatedVulnCode -Line $Lines[$i]) `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description 'SecureString converted to plaintext pointer without visible ZeroFree cleanup. Credential remains in unmanaged memory, accessible to memory dumps.' `
                -Remediation 'Always wrap SecureString marshaling in try/finally with Marshal.ZeroFreeGlobalAllocUnicode() in finally block.' `
                -References @('https://cwe.mitre.org/data/definitions/316.html')
        }

        # Also detect SecureString to managed string (worst case — no cleanup possible)
        if ($Lines[$i] -match 'new\s+NetworkCredential\s*\(.*SecureString|Marshal\.PtrToStringUni.*SecureString|SecureString.*ToString\(\)') {
            if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }
            $findings += New-Finding `
                -RuleId 'SEC-DATA-008' `
                -Category 'Credential Memory Leak' `
                -Severity 'Medium' `
                -Confidence 'Low' `
                -CWE 'CWE-316' `
                -OWASP 'A02:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode (Get-TruncatedVulnCode -Line $Lines[$i]) `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description 'SecureString converted to managed string. Managed strings are immutable and cannot be zeroed — credential persists in memory until GC collects it.' `
                -Remediation 'Keep credentials as SecureString throughout their lifecycle. Use Marshal.SecureStringToGlobalAllocUnicode with ZeroFree in a try/finally block.' `
                -References @('https://cwe.mitre.org/data/definitions/316.html')
        }
    }

    # =========================================================================
    # SEC-DATA-009: Stacktrace disclosure — enhanced patterns
    # CWE-209
    # =========================================================================
    $stackEnhanced = @(
        'customErrors\s+mode\s*=\s*["'']Off["'']',
        '<customErrors\s+mode="Off"',
        'IncludeExceptionDetailInFaults\s*=\s*true',
        'serviceDebug\s+includeExceptionDetailInFaults\s*=\s*["'']true["'']'
    )
    foreach ($se in $stackEnhanced) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $se `
            -RuleId 'SEC-DATA-009' `
            -Category 'Information Disclosure' `
            -Severity 'Medium' `
            -Confidence 'High' `
            -CWE 'CWE-209' `
            -OWASP 'A05:2021' `
            -Description 'Detailed error information exposed to clients. Stack traces reveal internal paths, class names, framework versions, and database schemas.' `
            -Remediation 'Set customErrors mode="RemoteOnly" or "On". Set IncludeExceptionDetailInFaults=false in WCF services.' `
            -References @('https://cwe.mitre.org/data/definitions/209.html')
    }

    return $findings
}

Export-ModuleMember -Function 'Invoke-DataExposureRules'
