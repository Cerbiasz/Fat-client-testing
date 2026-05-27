#Requires -Version 5.1
<#
.SYNOPSIS
    Network security rules: insecure HTTP config, open redirect, SSRF.
#>

function Invoke-NetworkSecurityRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Lines
    )

    $findings = @()

    # =========================================================================
    # SEC-NET-001: Insecure HttpWebRequest / TLS configuration
    # CWE-327
    # =========================================================================
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern 'ServicePointManager\.SecurityProtocol\s*=\s*SecurityProtocolType\.(?:Ssl3|Tls\b)(?!\s*\|)' `
        -RuleId 'SEC-NET-001' `
        -Category 'Insecure TLS Configuration' `
        -Severity 'High' `
        -Confidence 'High' `
        -CWE 'CWE-327' `
        -OWASP 'A02:2021' `
        -Description 'SecurityProtocol set to SSL3 or TLS 1.0 only. These protocols are deprecated and have known vulnerabilities (POODLE, BEAST).' `
        -Remediation 'Set ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13.' `
        -References @('https://cwe.mitre.org/data/definitions/327.html')

    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern 'CheckCertificateRevocationList\s*=\s*false' `
        -RuleId 'SEC-NET-001' `
        -Category 'Insecure TLS Configuration' `
        -Severity 'Medium' `
        -Confidence 'High' `
        -CWE 'CWE-299' `
        -OWASP 'A02:2021' `
        -Description 'Certificate revocation list (CRL) checking disabled. Revoked certificates will be accepted as valid.' `
        -Remediation 'Set ServicePointManager.CheckCertificateRevocationList = true to reject revoked certificates.' `
        -References @('https://cwe.mitre.org/data/definitions/299.html')

    # Auto-redirect with credentials
    $findings += Invoke-MultiLineRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern 'AllowAutoRedirect\s*=\s*true.*(?i)(token|auth|cookie|session)' `
        -WindowSize 5 `
        -RuleId 'SEC-NET-001' `
        -Category 'Credential Leak via Redirect' `
        -Severity 'Medium' `
        -Confidence 'Low' `
        -CWE 'CWE-601' `
        -Description 'HttpWebRequest with AllowAutoRedirect=true in context of authentication. Credentials may be forwarded to redirect target.' `
        -Remediation 'Set AllowAutoRedirect = false and handle redirects manually, stripping sensitive headers before following redirects to different domains.' `
        -References @('https://cwe.mitre.org/data/definitions/601.html')

    # =========================================================================
    # SEC-NET-002: Open Redirect
    # CWE-601
    # =========================================================================
    $redirectPatterns = @(
        'Response\.Redirect\s*\(.*(?:Request\.|QueryString|Form\[|Param)',
        '(?i)(redirect|navigate|location)\s*=\s*.*(?:Request\.|user|param|input)'
    )
    foreach ($rp in $redirectPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $rp `
            -WhitelistPatterns @('IsLocalUrl', 'Uri\.IsWellFormedUriString.*UriKind\.Relative', 'allowedHosts') `
            -RuleId 'SEC-NET-002' `
            -Category 'Open Redirect' `
            -Severity 'Medium' `
            -Confidence 'Medium' `
            -CWE 'CWE-601' `
            -OWASP 'A01:2021' `
            -Description 'Redirect destination taken from user input without validation. Attacker can redirect users to phishing or malware sites.' `
            -Remediation 'Validate redirect URLs are relative or belong to an allowlist of trusted domains. Use Uri.IsWellFormedUriString with UriKind.Relative.' `
            -References @('https://cwe.mitre.org/data/definitions/601.html')
    }

    # =========================================================================
    # SEC-NET-003: SSRF (Server-Side Request Forgery)
    # CWE-918
    # =========================================================================
    $ssrfPatterns = @(
        'WebClient\.(DownloadString|DownloadData|OpenRead)\s*\(.*(\+|\$"|user|param|Request\.)',
        'HttpWebRequest\.Create\s*\(.*(\+|\$"|user|param|Request\.)',
        'new\s+HttpClient.*GetAsync\s*\(.*(\+|\$"|user|param|Request\.)'
    )
    foreach ($sp in $ssrfPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $sp `
            -WhitelistPatterns @('Uri\.CheckHostName', 'allowedHosts\.Contains', 'whitelist', 'allowlist') `
            -RuleId 'SEC-NET-003' `
            -Category 'SSRF' `
            -Severity 'High' `
            -Confidence 'Medium' `
            -CWE 'CWE-918' `
            -OWASP 'A10:2021' `
            -Description 'HTTP request URL built from user input. Server-Side Request Forgery can access internal services, cloud metadata endpoints, or Oracle listeners.' `
            -Remediation 'Validate URLs against an allowlist of permitted hosts/schemes. Block internal IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.169.254).' `
            -References @('https://cwe.mitre.org/data/definitions/918.html')
    }

    # =========================================================================
    # SEC-NET-004: HTTP (non-HTTPS) endpoints in config/source
    # CWE-319
    # =========================================================================
    if ($FilePath -match '\.(config|xml|json|cs|vb)$') {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern 'http://(?!localhost|127\.0\.0\.1|::1|\[::1\]|0\.0\.0\.0|schemas\.|www\.w3\.org|xml\.|example\.com)[\w.-]+' `
            -WhitelistPatterns @('//\s*http://', '^\s*//') `
            -RuleId 'SEC-NET-004' `
            -Category 'Cleartext HTTP' `
            -Severity 'Medium' `
            -Confidence 'Medium' `
            -CWE 'CWE-319' `
            -OWASP 'A02:2021' `
            -Description 'Non-HTTPS URL found in configuration or source code. Data transmitted over HTTP is vulnerable to eavesdropping and MITM attacks.' `
            -Remediation 'Use HTTPS for all external endpoints. Replace http:// with https:// for all production URLs.' `
            -References @('https://cwe.mitre.org/data/definitions/319.html')
    }

    # =========================================================================
    # SEC-NET-005: Insecure file permissions (SetReadAllUsers, etc.)
    # CWE-732
    # =========================================================================
    $permPatterns = @(
        '(?i)SetRead\s*All\s*Users|SetAccessControl.*Everyone|FileSystemAccessRule.*Everyone',
        '(?i)FullControl\s*\).*(?:Everyone|Users|Authenticated)',
        'File\.SetAccessControl|Directory\.SetAccessControl'
    )
    foreach ($pp in $permPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $pp `
            -RuleId 'SEC-NET-005' `
            -Category 'Insecure File Permissions' `
            -Severity 'High' `
            -Confidence 'Medium' `
            -CWE 'CWE-732' `
            -OWASP 'A01:2021' `
            -Description 'File or directory permissions set to allow access by all users. Sensitive data (payment info, credentials) may be exposed.' `
            -Remediation 'Apply least-privilege permissions. Use FileSystemAccessRule with specific user/group instead of Everyone.' `
            -References @('https://cwe.mitre.org/data/definitions/732.html')
    }

    return $findings
}

Export-ModuleMember -Function 'Invoke-NetworkSecurityRules'
