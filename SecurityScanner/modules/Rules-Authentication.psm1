#Requires -Version 5.1
<#
.SYNOPSIS
    Authentication & session rules: hardcoded creds, plain text passwords,
    weak hashing, missing auth checks, session fixation.
#>

function Invoke-AuthenticationRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Lines
    )

    $findings = @()

    # =========================================================================
    # SEC-AUTH-001: Hardcoded credentials
    # CWE-798 | OWASP A07:2021
    # =========================================================================
    $credWhitelist = @(
        '(?i)(test|mock|fake|dummy|sample|example|placeholder|your_|<YOUR_|\{your_)',
        'ConfigurationManager\.AppSettings',
        'Environment\.GetEnvironmentVariable',
        '(?i)(vault|secret_manager|KeyVault|SecretClient)'
    )
    $excludeValues = '^\s*$|placeholder|your_password|changeme|xxx|TODO|CHANGETHIS|empty|null|""'

    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i]
        if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }

        # Pattern 1: variable = "value" where variable name suggests credential
        if ($line -match '(?i)(password|passwd|pwd|pass|secret|apikey|api_key|auth_token|access_token|private_key)\s*=\s*["'']([^"'']{3,})["'']') {
            $value = $Matches[2]
            if ($value -match $excludeValues) { continue }
            if (Test-WhitelistMatch -Lines $Lines -LineIndex $i -WhitelistPatterns $credWhitelist -ContextRange 10) { continue }

            $findings += New-Finding `
                -RuleId 'SEC-AUTH-001' `
                -Category 'Hardcoded Credentials' `
                -Severity 'Critical' `
                -Confidence 'High' `
                -CWE 'CWE-798' `
                -OWASP 'A07:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode (Get-TruncatedVulnCode -Line $line) `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description 'Hardcoded credential detected. Passwords, tokens, and API keys embedded in source code are exposed in binaries and version control.' `
                -Remediation 'Store credentials in a secure vault (Azure Key Vault, DPAPI, environment variables). Never embed secrets in source code.' `
                -References @('https://cwe.mitre.org/data/definitions/798.html')
        }

        # Pattern 2: OracleConnection with hardcoded password
        if ($line -match 'new\s+OracleConnection\s*\(\s*["''][^"'']*Password\s*=\s*[^;''"]+') {
            if (Test-WhitelistMatch -Lines $Lines -LineIndex $i -WhitelistPatterns $credWhitelist -ContextRange 10) { continue }
            $findings += New-Finding `
                -RuleId 'SEC-AUTH-001' `
                -Category 'Hardcoded Credentials' `
                -Severity 'Critical' `
                -Confidence 'High' `
                -CWE 'CWE-798' `
                -OWASP 'A07:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode (Get-TruncatedVulnCode -Line $line) `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description 'Oracle connection string with hardcoded password in OracleConnection constructor.' `
                -Remediation 'Store connection strings with credentials in encrypted config sections, Azure Key Vault, or Oracle Wallet.' `
                -References @('https://cwe.mitre.org/data/definitions/798.html')
        }

        # Pattern 3: ConnectionString with Password
        if ($line -match 'ConnectionString\s*=\s*["''][^"'']*(?:Password|PWD)\s*=\s*(?!;|\s)[^;''"]{3,}') {
            if (Test-WhitelistMatch -Lines $Lines -LineIndex $i -WhitelistPatterns $credWhitelist -ContextRange 10) { continue }
            $findings += New-Finding `
                -RuleId 'SEC-AUTH-001' `
                -Category 'Hardcoded Credentials' `
                -Severity 'Critical' `
                -Confidence 'High' `
                -CWE 'CWE-798' `
                -OWASP 'A07:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode (Get-TruncatedVulnCode -Line $line) `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description 'Connection string with hardcoded password.' `
                -Remediation 'Use encrypted config sections or secure vault for connection strings.' `
                -References @('https://cwe.mitre.org/data/definitions/798.html')
        }

        # Pattern 4: Base64 Authorization header
        if ($line -match 'Authorization\s*:\s*Basic\s+[A-Za-z0-9+/=]{10,}') {
            $findings += New-Finding `
                -RuleId 'SEC-AUTH-001' `
                -Category 'Hardcoded Credentials' `
                -Severity 'Critical' `
                -Confidence 'High' `
                -CWE 'CWE-798' `
                -OWASP 'A07:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode (Get-TruncatedVulnCode -Line $line) `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description 'Hardcoded Basic Authentication header with Base64-encoded credentials.' `
                -Remediation 'Use secure credential storage and set Authorization header dynamically at runtime.' `
                -References @('https://cwe.mitre.org/data/definitions/798.html')
        }

        # Pattern 5: Registry with password/credentials
        if ($line -match '(?i)Registry\.\w*(SetValue|GetValue)\s*\([^)]*(?:password|passwd|pwd|credential|secret)') {
            $findings += New-Finding `
                -RuleId 'SEC-AUTH-001' `
                -Category 'Hardcoded Credentials' `
                -Severity 'Critical' `
                -Confidence 'High' `
                -CWE 'CWE-798' `
                -OWASP 'A07:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode (Get-TruncatedVulnCode -Line $line) `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description 'Credentials stored in or retrieved from Windows Registry. Registry values are readable by other processes and may be exported.' `
                -Remediation 'Use DPAPI (ProtectedData), Windows Credential Manager, or a secure vault instead of Registry for credential storage.' `
                -References @('https://cwe.mitre.org/data/definitions/798.html')
        }

        # Pattern 6: Hardcoded admin/user password comparison
        if ($line -match '(?i)(?:admin|user)\w*(?:Password|Pass|Pwd|Secret)\s*=\s*["''][^"'']{3,}["'']') {
            $value2 = $Matches[0]
            if ($value2 -match $excludeValues) { continue }
            if (Test-WhitelistMatch -Lines $Lines -LineIndex $i -WhitelistPatterns $credWhitelist -ContextRange 10) { continue }

            $findings += New-Finding `
                -RuleId 'SEC-AUTH-001' `
                -Category 'Hardcoded Credentials' `
                -Severity 'Critical' `
                -Confidence 'High' `
                -CWE 'CWE-798' `
                -OWASP 'A07:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode (Get-TruncatedVulnCode -Line $line) `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description 'Hardcoded admin/user password detected. Embedded credentials are exposed in binaries and version control.' `
                -Remediation 'Store credentials in a secure vault (Azure Key Vault, DPAPI, environment variables). Never embed secrets in source code.' `
                -References @('https://cwe.mitre.org/data/definitions/798.html')
        }

        # Pattern 7: .Equals("hardcoded") with password context
        if ($line -match '(?i)(?:password|passwd|secret|token)\)?\s*\)\s*\.Equals\s*\(\s*["''][^"'']{3,}["'']') {
            $findings += New-Finding `
                -RuleId 'SEC-AUTH-001' `
                -Category 'Hardcoded Credentials' `
                -Severity 'Critical' `
                -Confidence 'High' `
                -CWE 'CWE-798' `
                -OWASP 'A07:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode (Get-TruncatedVulnCode -Line $line) `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description 'Password/secret compared against hardcoded value using .Equals(). Embedded credentials are exposed in binaries.' `
                -Remediation 'Store credential hashes in secure vault and compare using constant-time hash comparison.' `
                -References @('https://cwe.mitre.org/data/definitions/798.html')
        }

        # Pattern 8: Hardcoded username check (e.g. Username.Equals("betafastadmin"))
        if ($line -match '(?i)(?:user|login|admin)\w*\.Equals\s*\(\s*["''][^"'']{3,}["'']') {
            if (Test-ContextContains -Lines $Lines -LineIndex $i -Pattern '(?i)(password|passwd|secret|token)' -Range 5) {
                $findings += New-Finding `
                    -RuleId 'SEC-AUTH-001' `
                    -Category 'Hardcoded Credentials' `
                    -Severity 'High' `
                    -Confidence 'Medium' `
                    -CWE 'CWE-798' `
                    -OWASP 'A07:2021' `
                    -FilePath $FilePath `
                    -LineNumber ($i + 1) `
                    -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                    -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                    -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                    -VulnerableCode (Get-TruncatedVulnCode -Line $line) `
                    -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                    -Description 'Hardcoded username comparison in authentication context. Combined with hardcoded password creates a backdoor.' `
                    -Remediation 'Authentication should always be performed server-side against a credential store. Remove hardcoded credentials.' `
                    -References @('https://cwe.mitre.org/data/definitions/798.html')
            }
        }

        # Pattern 9: Private key in source
        if ($line -match '-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----') {
            $findings += New-Finding `
                -RuleId 'SEC-AUTH-001' `
                -Category 'Hardcoded Credentials' `
                -Severity 'Critical' `
                -Confidence 'High' `
                -CWE 'CWE-798' `
                -OWASP 'A07:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode (Get-TruncatedVulnCode -Line $line) `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description 'Private key embedded directly in source code.' `
                -Remediation 'Store private keys in a certificate store, HSM, or secure vault. Never embed in source code.' `
                -References @('https://cwe.mitre.org/data/definitions/798.html')
        }
    }

    # =========================================================================
    # SEC-AUTH-002: Plain text password comparison
    # CWE-256, CWE-257
    # =========================================================================
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern '(?i)(password|passwd)\s*==\s*\w+' `
        -WhitelistPatterns @('Rfc2898DeriveBytes', 'PBKDF2', 'bcrypt', 'Argon2', 'PasswordHasher', 'ComputeHash', 'VerifyHash') `
        -RuleId 'SEC-AUTH-002' `
        -Category 'Plaintext Password' `
        -Severity 'High' `
        -Confidence 'Medium' `
        -CWE 'CWE-256' `
        -OWASP 'A07:2021' `
        -Description 'Direct string comparison of passwords. Passwords should be hashed and compared using constant-time comparison.' `
        -Remediation 'Hash passwords with PBKDF2/bcrypt/Argon2 and use constant-time comparison (e.g. CryptographicOperations.FixedTimeEquals).' `
        -References @('https://cwe.mitre.org/data/definitions/256.html')

    # =========================================================================
    # SEC-AUTH-003: Fast hash for passwords (MD5/SHA for password)
    # CWE-916
    # =========================================================================
    $hashPwdPatterns = @(
        'MD5\.(?:Create|ComputeHash).*(?i)(password|passwd|pwd)',
        '(?i)(password|passwd|pwd).*MD5\.(?:Create|ComputeHash)',
        'SHA(?:1|256|512)\.Create.*(?i)(password|passwd|pwd)',
        '(?i)(password|passwd|pwd).*SHA(?:1|256|512)\.Create'
    )
    foreach ($hp in $hashPwdPatterns) {
        $findings += Invoke-MultiLineRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $hp `
            -WhitelistPatterns @('Rfc2898DeriveBytes', 'PBKDF2', 'bcrypt', 'Argon2', 'PasswordHasher') `
            -WindowSize 10 `
            -RuleId 'SEC-AUTH-003' `
            -Category 'Weak Password Hashing' `
            -Severity 'High' `
            -Confidence 'Medium' `
            -CWE 'CWE-916' `
            -OWASP 'A02:2021' `
            -Description 'Fast hash algorithm (MD5/SHA) used for password hashing. These are vulnerable to brute-force and rainbow table attacks.' `
            -Remediation 'Use PBKDF2 (Rfc2898DeriveBytes with 100k+ iterations), bcrypt, or Argon2id for password hashing.' `
            -References @('https://cwe.mitre.org/data/definitions/916.html')
    }

    # =========================================================================
    # SEC-AUTH-004: Missing authorization check on privileged operations
    # CWE-862
    # =========================================================================
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '(?i)(delete|drop|truncate|admin|privilege|grant|revoke).*OracleCommand') {
            if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }
            if (Test-ContextContains -Lines $Lines -LineIndex $i `
                -Pattern 'IsInRole|HasPermission|Authorize|ClaimsPrincipal|IsAdmin|CheckPermission|PrincipalPermission' `
                -Range 20) { continue }

            $findings += New-Finding `
                -RuleId 'SEC-AUTH-004' `
                -Category 'Missing Authorization' `
                -Severity 'High' `
                -Confidence 'Low' `
                -CWE 'CWE-862' `
                -OWASP 'A01:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode $Lines[$i].Trim() `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description 'Privileged database operation without visible authorization check within 20 lines. Verify that access control is enforced.' `
                -Remediation 'Add explicit authorization check (e.g., IsInRole, HasPermission) before privileged operations.' `
                -References @('https://cwe.mitre.org/data/definitions/862.html')
        }
    }

    # =========================================================================
    # SEC-AUTH-005: Session fixation
    # CWE-384
    # =========================================================================
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match 'Session\["(?:UserId|IsAuthenticated|Role|User)"\]\s*=') {
            if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }

            # Check if in a login context
            $methodName = Get-ContainingMethod -Lines $Lines -LineIndex $i
            if ($methodName -notmatch '(?i)(login|signin|authenticate)') { continue }

            # Must have session regeneration
            if (Test-ContextContains -Lines $Lines -LineIndex $i `
                -Pattern 'Session\.Abandon|Session\.Clear|Session\.RegenerateId|FormsAuthentication' `
                -Range 20) { continue }

            $findings += New-Finding `
                -RuleId 'SEC-AUTH-005' `
                -Category 'Session Fixation' `
                -Severity 'Medium' `
                -Confidence 'Medium' `
                -CWE 'CWE-384' `
                -OWASP 'A07:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName $methodName `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode $Lines[$i].Trim() `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description 'Session values set during authentication without session regeneration. May allow session fixation attacks.' `
                -Remediation 'Call Session.Abandon() and create a new session after successful authentication.' `
                -References @('https://cwe.mitre.org/data/definitions/384.html')
        }
    }

    # =========================================================================
    # SEC-AUTH-006: Cookie without Secure flag
    # CWE-614
    # =========================================================================
    $cookieSecurePatterns = @(
        'new\s+HttpCookie\s*\([^)]*\)(?!.*Secure\s*=\s*true)',
        '\.Cookies\.Add\s*\(.*new\s+HttpCookie',
        'httpCookies\s+requireSSL\s*=\s*["'']false["'']',
        'cookie\.Secure\s*=\s*false'
    )
    foreach ($csp in $cookieSecurePatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $csp `
            -WhitelistPatterns @('Secure\s*=\s*true', 'requireSSL\s*=\s*["'']true') `
            -RuleId 'SEC-AUTH-006' `
            -Category 'Insecure Cookie' `
            -Severity 'Medium' `
            -Confidence 'Medium' `
            -CWE 'CWE-614' `
            -OWASP 'A05:2021' `
            -Description 'Cookie created without Secure flag. Cookie will be sent over unencrypted HTTP, exposing session tokens to network sniffing.' `
            -Remediation 'Set cookie.Secure = true. In web.config, set <httpCookies requireSSL="true" />. Use HTTPS for all authenticated pages.' `
            -References @('https://cwe.mitre.org/data/definitions/614.html')
    }

    # =========================================================================
    # SEC-AUTH-007: Cookie without HttpOnly flag
    # CWE-1004
    # =========================================================================
    $cookieHttpOnlyPatterns = @(
        'new\s+HttpCookie\s*\([^)]*\)(?!.*HttpOnly\s*=\s*true)',
        'cookie\.HttpOnly\s*=\s*false',
        'httpCookies\s+httpOnlyCookies\s*=\s*["'']false["'']'
    )
    foreach ($chp in $cookieHttpOnlyPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $chp `
            -WhitelistPatterns @('HttpOnly\s*=\s*true', 'httpOnlyCookies\s*=\s*["'']true') `
            -RuleId 'SEC-AUTH-007' `
            -Category 'Insecure Cookie' `
            -Severity 'Medium' `
            -Confidence 'Medium' `
            -CWE 'CWE-1004' `
            -OWASP 'A05:2021' `
            -Description 'Cookie without HttpOnly flag. JavaScript can access this cookie, enabling session theft via XSS attacks.' `
            -Remediation 'Set cookie.HttpOnly = true. In web.config, set <httpCookies httpOnlyCookies="true" />.' `
            -References @('https://cwe.mitre.org/data/definitions/1004.html')
    }

    return $findings
}

Export-ModuleMember -Function 'Invoke-AuthenticationRules'
