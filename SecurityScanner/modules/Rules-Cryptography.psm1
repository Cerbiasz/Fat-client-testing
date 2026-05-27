#Requires -Version 5.1
<#
.SYNOPSIS
    Cryptography rules: weak hashes, weak ciphers, hardcoded keys, insecure random, TLS, RSA.
#>

function Invoke-CryptographyRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Lines
    )

    $findings = @()

    # =========================================================================
    # SEC-CRYPT-001: Weak hash — MD5
    # CWE-327 | OWASP A02:2021
    # =========================================================================
    $md5Patterns = @(
        'MD5\.Create\(\)',
        'new\s+MD5CryptoServiceProvider\s*\(',
        'HashAlgorithm\.Create\s*\(\s*["'']MD5["'']\)',
        'System\.Security\.Cryptography\.MD5',
        'MD5Managed'
    )
    foreach ($mp in $md5Patterns) {
        # Check if used with password context for higher severity
        for ($i = 0; $i -lt $Lines.Count; $i++) {
            if ($Lines[$i] -notmatch $mp) { continue }
            if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }

            $sev = 'High'
            $conf = 'High'
            if (Test-ContextContains -Lines $Lines -LineIndex $i -Pattern '(?i)(password|passwd|pwd|secret|credential)' -Range 10) {
                $sev = 'Critical'
            }

            $findings += New-Finding `
                -RuleId 'SEC-CRYPT-001' `
                -Category 'Weak Cryptography' `
                -Severity $sev `
                -Confidence $conf `
                -CWE 'CWE-327' `
                -OWASP 'A02:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode (Get-TruncatedVulnCode -Line $Lines[$i]) `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description 'MD5 is cryptographically broken (Wang & Yu, 2004). Must not be used for password hashing, digital signatures, or integrity verification in security contexts.' `
                -Remediation 'Replace with SHA-256/SHA-512 for integrity checks, or PBKDF2/bcrypt/Argon2 for password hashing.' `
                -References @('https://cwe.mitre.org/data/definitions/327.html')
        }
    }

    # =========================================================================
    # SEC-CRYPT-002: Weak hash — SHA1
    # CWE-327
    # =========================================================================
    $sha1Patterns = @(
        'SHA1\.Create\(\)',
        'new\s+SHA1CryptoServiceProvider\s*\(',
        'SHA1Managed',
        'HashAlgorithm\.Create\s*\(\s*["'']SHA1["'']\)'
    )
    foreach ($sp in $sha1Patterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $sp `
            -WhitelistPatterns @('//\s*legacy', '//\s*compatibility', '//\s*deprecated', 'HMACSHA1') `
            -RuleId 'SEC-CRYPT-002' `
            -Category 'Weak Cryptography' `
            -Severity 'Medium' `
            -Confidence 'High' `
            -CWE 'CWE-327' `
            -OWASP 'A02:2021' `
            -Description 'SHA-1 is deprecated by NIST (2011) and practically broken (SHAttered, 2017). Should not be used for signatures, certificates, or MAC.' `
            -Remediation 'Replace with SHA-256 or SHA-512. For HMAC contexts, HMAC-SHA256 is recommended.' `
            -References @('https://cwe.mitre.org/data/definitions/327.html')
    }

    # =========================================================================
    # SEC-CRYPT-003: DES / 3DES / ECB mode
    # CWE-327
    # =========================================================================
    $desPatterns = @(
        @{ P = 'new\s+DESCryptoServiceProvider\s*\(|DES\.Create\(\)'; D = 'DES (56-bit key) is broken since 1998.' },
        @{ P = 'new\s+TripleDESCryptoServiceProvider\s*\(|TripleDES\.Create\(\)'; D = '3DES is vulnerable to SWEET32 (CVE-2016-2183), deprecated by NIST.' },
        @{ P = 'CipherMode\.ECB'; D = 'ECB mode has no diffusion — identical plaintext blocks produce identical ciphertext. Never secure.' }
    )
    foreach ($dp in $desPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $dp.P `
            -RuleId 'SEC-CRYPT-003' `
            -Category 'Weak Cryptography' `
            -Severity 'High' `
            -Confidence 'High' `
            -CWE 'CWE-327' `
            -OWASP 'A02:2021' `
            -Description $dp.D `
            -Remediation 'Use AES (128/256-bit) with CBC or GCM mode. AES-128 is acceptable per NIST SP 800-131A until 2030+.' `
            -References @('https://cwe.mitre.org/data/definitions/327.html')
    }

    # Weak key size (56/64 bit — DES range)
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match 'KeySize\s*=\s*(56|64)\b') {
            if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }
            $findings += New-Finding `
                -RuleId 'SEC-CRYPT-003' `
                -Category 'Weak Cryptography' `
                -Severity 'High' `
                -Confidence 'Medium' `
                -CWE 'CWE-327' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode (Get-TruncatedVulnCode -Line $Lines[$i]) `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description ('Symmetric key size of {0} bits is insecure (DES-range).' -f $Matches[1]) `
                -Remediation 'Use AES with 128-bit or 256-bit key size.' `
                -References @('https://cwe.mitre.org/data/definitions/327.html')
        }
    }

    # =========================================================================
    # SEC-CRYPT-004: Hardcoded cryptographic key / IV
    # CWE-321, CWE-329
    # =========================================================================
    $keyPatterns = @(
        @{ P = '\.Key\s*=\s*new\s+byte\[\]\s*\{[^}]+\}'; D = 'Hardcoded cryptographic key in byte array.' },
        @{ P = '\.IV\s*=\s*new\s+byte\[\]\s*\{[^}]+\}'; D = 'Hardcoded initialization vector (IV) in byte array.' },
        @{ P = '\.Key\s*=\s*Encoding\.\w+\.GetBytes\s*\(\s*["''][^"'']+["'']\)'; D = 'Cryptographic key derived from hardcoded string literal.' },
        @{ P = 'private\s+(static\s+)?(readonly\s+)?(byte\[\]|string)\s+\w*(key|Key|KEY|secret|Secret|iv|IV)\w*\s*=\s*["''\{]'; D = 'Private field with key/secret/IV name assigned a literal value.' },
        @{ P = 'byte\[\]\s+\w*(Key|key|KEY|IV|iv)\w*\s*=\s*new\s+byte\[\]\s*\{'; D = 'Field declaration with Key/IV name initialized with hardcoded byte array.' },
        @{ P = '(?:string|var)\s+\w*(Key|key|KEY|Secret|secret|IV|iv)\w*\s*=\s*["''][^"'']{8,}["'']'; D = 'String field with Key/Secret/IV name assigned a hardcoded literal value (8+ chars).' }
    )
    foreach ($kp in $keyPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $kp.P `
            -WhitelistPatterns @('//\s*test', '//\s*sample', '//\s*example', '//\s*placeholder', 'TODO', 'FIXME') `
            -RuleId 'SEC-CRYPT-004' `
            -Category 'Hardcoded Crypto Key' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-321' `
            -OWASP 'A02:2021' `
            -Description $kp.D `
            -Remediation 'Store keys in a secure vault (Azure Key Vault, DPAPI ProtectedData, HSM). Never embed cryptographic material in source code.' `
            -References @('https://cwe.mitre.org/data/definitions/321.html', 'https://cwe.mitre.org/data/definitions/329.html')
    }

    # =========================================================================
    # SEC-CRYPT-005: System.Random for security-sensitive operations
    # CWE-338
    # =========================================================================
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -notmatch 'new\s+Random\s*\(') { continue }
        if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }

        # Only flag if in context of security-sensitive operations
        if (-not (Test-ContextContains -Lines $Lines -LineIndex $i -Pattern '(?i)(token|password|salt|key|session|nonce|secret|auth|credential)' -Range 15)) { continue }

        # Whitelist: already using secure RNG
        if (Test-WhitelistMatch -Lines $Lines -LineIndex $i -WhitelistPatterns @('RNGCryptoServiceProvider', 'RandomNumberGenerator\.Create') -ContextRange 15) { continue }

        $findings += New-Finding `
            -RuleId 'SEC-CRYPT-005' `
            -Category 'Insecure Randomness' `
            -Severity 'High' `
            -Confidence 'Medium' `
            -CWE 'CWE-338' `
            -OWASP 'A02:2021' `
            -FilePath $FilePath `
            -LineNumber ($i + 1) `
            -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
            -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
            -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
            -VulnerableCode (Get-TruncatedVulnCode -Line $Lines[$i]) `
            -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
            -Description 'System.Random is not cryptographically secure. Used in a security-sensitive context (token/password/salt/key generation).' `
            -Remediation 'Use RNGCryptoServiceProvider or RandomNumberGenerator.Create() for cryptographic operations.' `
            -References @('https://cwe.mitre.org/data/definitions/338.html')
    }

    # =========================================================================
    # SEC-CRYPT-006: Disabled SSL/TLS certificate validation
    # CWE-295
    # =========================================================================
    $tlsPatterns = @(
        @{ P = 'ServerCertificateValidationCallback\s*=.*?(?:true|delegate|=>.*?true)'; D = 'SSL/TLS certificate validation disabled — accepts any certificate. Vulnerable to MITM.' },
        @{ P = 'ServerCertificateValidationCallback\s*\+=?\s*delegate[^{]*\{[^}]*return\s+true'; D = 'Certificate validation callback always returns true.' },
        @{ P = 'SecurityProtocol\s*=\s*SecurityProtocolType\.Ssl3'; D = 'SSL 3.0 is insecure (POODLE attack, CVE-2014-3566).' },
        @{ P = 'SslProtocols\.Ssl3'; D = 'SSL 3.0 protocol usage detected.' }
    )
    foreach ($tp in $tlsPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $tp.P `
            -RuleId 'SEC-CRYPT-006' `
            -Category 'Insecure TLS/SSL' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-295' `
            -OWASP 'A02:2021' `
            -Description $tp.D `
            -Remediation 'Never disable certificate validation. Use ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13.' `
            -References @('https://cwe.mitre.org/data/definitions/295.html')
    }

    # TLS 1.0 only (without TLS 1.2+)
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern 'SecurityProtocol\s*=\s*SecurityProtocolType\.Tls\b(?!\s*\|\s*SecurityProtocolType\.Tls1[23])' `
        -RuleId 'SEC-CRYPT-006' `
        -Category 'Insecure TLS/SSL' `
        -Severity 'High' `
        -Confidence 'High' `
        -CWE 'CWE-327' `
        -OWASP 'A02:2021' `
        -Description 'TLS 1.0 only — does not include TLS 1.2 or higher. TLS 1.0 is deprecated (RFC 8996).' `
        -Remediation 'Set SecurityProtocol to include Tls12 | Tls13.' `
        -References @('https://cwe.mitre.org/data/definitions/327.html')

    # =========================================================================
    # SEC-CRYPT-007: Weak RSA key size
    # CWE-326
    # =========================================================================
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '(?:new\s+RSACryptoServiceProvider|RSA\.Create)\s*\(\s*(\d+)\s*\)') {
            $keySize = [int]$Matches[1]
            if ($keySize -lt 2048) {
                if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }
                $findings += New-Finding `
                    -RuleId 'SEC-CRYPT-007' `
                    -Category 'Weak Cryptography' `
                    -Severity 'High' `
                    -Confidence 'High' `
                    -CWE 'CWE-326' `
                    -OWASP 'A02:2021' `
                    -FilePath $FilePath `
                    -LineNumber ($i + 1) `
                    -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                    -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                    -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                    -VulnerableCode (Get-TruncatedVulnCode -Line $Lines[$i]) `
                    -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                    -Description "RSA key size of $keySize bits is insufficient. NIST recommends minimum 2048 bits (3072+ preferred)." `
                    -Remediation 'Use RSA with at least 2048-bit key size: new RSACryptoServiceProvider(2048) or RSA.Create(3072).' `
                    -References @('https://cwe.mitre.org/data/definitions/326.html')
            }
        }
    }

    return $findings
}

Export-ModuleMember -Function 'Invoke-CryptographyRules'
