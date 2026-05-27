#Requires -Version 5.1
<#
.SYNOPSIS
    .NET Framework specific rules: reflection, unsafe code, CAS, DateTime seed,
    ViewState, ReDoS.
#>

function Invoke-DotNetSpecificRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Lines
    )

    $findings = @()

    # =========================================================================
    # SEC-DNT-001: Reflection — dynamic code loading from external input
    # CWE-470, CWE-502
    # =========================================================================
    $reflectionPatterns = @(
        @{ P = 'Assembly\.Load\s*\(.*(\+|\$"|user|param|Request\.|Convert\.From)'; D = 'Assembly.Load with dynamic input' },
        @{ P = 'Assembly\.LoadFrom\s*\(.*(\+|\$"|user|param|Request\.)'; D = 'Assembly.LoadFrom with dynamic path' },
        @{ P = 'Assembly\.LoadFile\s*\(.*(\+|\$"|user|param)'; D = 'Assembly.LoadFile with dynamic path' },
        @{ P = 'Activator\.CreateInstance\s*\(.*Type\.GetType\s*\(.*(\+|\$"|user|param)'; D = 'Activator.CreateInstance with dynamic type from external source' },
        @{ P = 'Type\.GetType\s*\(.*(\+|\$"|Request\.|user|param)'; D = 'Type.GetType with dynamic type name from external input' }
    )
    foreach ($rp in $reflectionPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $rp.P `
            -RuleId 'SEC-DNT-001' `
            -Category 'Unsafe Reflection' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-470' `
            -OWASP 'A08:2021' `
            -Description ('{0}. Loading assemblies or types from user-controlled input enables arbitrary code execution.' -f $rp.D) `
            -Remediation 'Use an allowlist of permitted assembly names/types. Never pass user input directly to Assembly.Load or Type.GetType.' `
            -References @('https://cwe.mitre.org/data/definitions/470.html')
    }

    # =========================================================================
    # SEC-DNT-002: unsafe code / pointer operations
    # CWE-119, CWE-120
    # =========================================================================
    $unsafePatterns = @(
        @{ P = 'unsafe\s+(?:class|struct|void|static|public|private|internal)'; D = 'Unsafe code block declared. Direct pointer manipulation bypasses .NET memory safety.'; S = 'Medium'; C = 'Low' },
        @{ P = 'fixed\s*\(\s*\w+\*'; D = 'Fixed pointer statement — pinned memory with direct pointer access.'; S = 'Medium'; C = 'Low' },
        @{ P = 'stackalloc\s+\w+\['; D = 'Stack allocation — risk of stack overflow if size comes from external input.'; S = 'Medium'; C = 'Low' },
        @{ P = 'Marshal\.(Copy|PtrToStructure|StructureToPtr).*(?:user|param|input|Request\.)'; D = 'Marshal operations with potentially user-controlled data. Memory corruption risk.'; S = 'High'; C = 'Medium' }
    )
    foreach ($up in $unsafePatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $up.P `
            -RuleId 'SEC-DNT-002' `
            -Category 'Unsafe Code' `
            -Severity $up.S `
            -Confidence $up.C `
            -CWE 'CWE-119' `
            -Description $up.D `
            -Remediation 'Avoid unsafe code unless absolutely necessary. If required, validate all buffer sizes and pointer arithmetic. Consider SafeHandle for interop.' `
            -References @('https://cwe.mitre.org/data/definitions/119.html')
    }

    # =========================================================================
    # SEC-DNT-003: CAS manipulation (legacy but may indicate bypass attempt)
    # CWE-732
    # =========================================================================
    $casPatterns = @(
        'SecurityAction\.RequestMinimum|SecurityAction\.RequestOptional|SecurityAction\.RequestRefuse',
        'PermissionSet\s*\(\s*PermissionState\.Unrestricted\s*\)',
        'AppDomain\.CurrentDomain\.SetPermissionPolicy'
    )
    foreach ($cp in $casPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $cp `
            -RuleId 'SEC-DNT-003' `
            -Category 'CAS Bypass' `
            -Severity 'Medium' `
            -Confidence 'Low' `
            -CWE 'CWE-732' `
            -Description 'Code Access Security (CAS) manipulation detected. In .NET 4.x, CAS is largely obsolete but PermissionState.Unrestricted may indicate sandbox bypass intent.' `
            -Remediation 'Review purpose of CAS permissions. In .NET 4+, prefer operating system-level security (process isolation, file ACLs) over CAS.' `
            -References @('https://cwe.mitre.org/data/definitions/732.html')
    }

    # =========================================================================
    # SEC-DNT-004: Insecure Randomness — DateTime as seed
    # CWE-338
    # =========================================================================
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern 'new\s+Random\s*\(\s*(?:DateTime|Environment\.TickCount|unchecked\s*\(\s*\(int\s*\)\s*DateTime|\(int\s*\)\s*DateTime)' `
        -RuleId 'SEC-DNT-004' `
        -Category 'Insecure Randomness' `
        -Severity 'Medium' `
        -Confidence 'High' `
        -CWE 'CWE-338' `
        -Description 'System.Random seeded with DateTime or TickCount — predictable seed makes output guessable. Multiple instances created at the same time produce identical sequences.' `
        -Remediation 'For security-sensitive operations, use RNGCryptoServiceProvider or RandomNumberGenerator.Create(). For non-security uses, use parameterless new Random() constructor.' `
        -References @('https://cwe.mitre.org/data/definitions/338.html')

    # =========================================================================
    # SEC-DNT-005: ViewState without MAC (ASP.NET WebForms only)
    # CWE-642
    # =========================================================================
    $viewStatePatterns = @(
        'EnableViewStateMac\s*=\s*["'']?false',
        'ViewStateEncryptionMode\s*=\s*["'']?Never',
        'Page\.EnableViewStateMac\s*=\s*false'
    )
    foreach ($vp in $viewStatePatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $vp `
            -RuleId 'SEC-DNT-005' `
            -Category 'Insecure ViewState' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-642' `
            -OWASP 'A08:2021' `
            -Description 'ViewState MAC validation disabled. This enables Remote Code Execution via ViewState deserialization gadgets. Applies to ASP.NET WebForms only.' `
            -Remediation 'Never disable ViewStateMac. In .NET 4.5.2+, the MAC is enforced by default. Remove any EnableViewStateMac="false" settings.' `
            -References @('https://cwe.mitre.org/data/definitions/642.html')
    }

    # =========================================================================
    # SEC-DNT-006: ReDoS — Regex with external input
    # CWE-1333
    # =========================================================================
    # Use tighter pattern — limit match scope to ~120 chars after Regex( to avoid false positives on single-line files
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern 'new\s+Regex\s*\([^)]{0,80}(?:\+|\$"|Request\.|Request\[)' `
        -RuleId 'SEC-DNT-006' `
        -Category 'ReDoS' `
        -Severity 'Medium' `
        -Confidence 'Medium' `
        -CWE 'CWE-1333' `
        -OWASP 'A06:2021' `
        -Description 'Regex pattern constructed from external input. Attacker can craft a malicious pattern causing catastrophic backtracking (ReDoS), leading to CPU exhaustion.' `
        -Remediation 'Never use user input as regex pattern. If unavoidable, set RegexOptions.MatchTimeout and use Regex.IsMatch with a timeout.' `
        -References @('https://cwe.mitre.org/data/definitions/1333.html')

    # =========================================================================
    # SEC-DNT-008: Unsafe XSLT — EnableScript
    # CWE-611
    # =========================================================================
    $xsltPatterns = @(
        'XsltSettings\s*\(\s*true',
        'XsltSettings\.TrustedXslt',
        'EnableScript\s*=\s*true'
    )
    foreach ($xp in $xsltPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $xp `
            -RuleId 'SEC-DNT-008' `
            -Category 'Unsafe XSLT' `
            -Severity 'High' `
            -Confidence 'High' `
            -CWE 'CWE-611' `
            -OWASP 'A05:2021' `
            -Description 'XSLT transformation with scripting enabled. Attacker-controlled XSLT can execute arbitrary code via embedded C#/VB scripts.' `
            -Remediation 'Use XsltSettings.Default (scripting disabled). Never use XsltSettings.TrustedXslt or EnableScript=true with untrusted input.' `
            -References @('https://cwe.mitre.org/data/definitions/611.html')
    }

    # =========================================================================
    # SEC-DNT-009: CSRF — POST without ValidateAntiForgeryToken
    # CWE-352
    # =========================================================================
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '\[HttpPost\]') {
            if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }
            # Skip API controllers — they use Bearer/JWT, not anti-forgery tokens
            if (Test-ContextContains -Lines $Lines -LineIndex $i -Pattern '\[ApiController\]|ControllerBase|WebApi|\[FromBody\]' -Range 50) { continue }
            # Check next 5 lines for ValidateAntiForgeryToken
            if (Test-ContextContains -Lines $Lines -LineIndex $i -Pattern 'ValidateAntiForgeryToken|AntiForgeryToken|__RequestVerificationToken' -Range 5) { continue }

            $findings += New-Finding `
                -RuleId 'SEC-DNT-009' `
                -Category 'CSRF' `
                -Severity 'Medium' `
                -Confidence 'Medium' `
                -CWE 'CWE-352' `
                -OWASP 'A01:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode (Get-TruncatedVulnCode -Line $Lines[$i]) `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description '[HttpPost] action without [ValidateAntiForgeryToken]. Cross-Site Request Forgery allows attackers to submit forms on behalf of authenticated users.' `
                -Remediation 'Add [ValidateAntiForgeryToken] attribute to all POST actions and include @Html.AntiForgeryToken() in forms.' `
                -References @('https://cwe.mitre.org/data/definitions/352.html')
        }
    }

    # =========================================================================
    # SEC-DNT-010: Request validation disabled
    # CWE-554
    # =========================================================================
    $reqValPatterns = @(
        '\[ValidateInput\s*\(\s*false\s*\)\]',
        'ValidateRequest\s*=\s*["'']?false',
        'requestValidationMode\s*=\s*["'']2\.0["'']',
        'pages\s+validateRequest\s*=\s*["'']false["'']'
    )
    foreach ($rv in $reqValPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $rv `
            -RuleId 'SEC-DNT-010' `
            -Category 'Request Validation Disabled' `
            -Severity 'High' `
            -Confidence 'High' `
            -CWE 'CWE-554' `
            -OWASP 'A03:2021' `
            -Description 'ASP.NET request validation disabled. This built-in XSS protection rejects input containing HTML/script tags. Disabling exposes application to XSS attacks.' `
            -Remediation 'Keep request validation enabled. If specific fields need HTML input, use [AllowHtml] on individual model properties instead of disabling globally.' `
            -References @('https://cwe.mitre.org/data/definitions/554.html')
    }

    # =========================================================================
    # SEC-DNT-011: OutputCache on Authorize methods
    # CWE-524
    # =========================================================================
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '\[OutputCache') {
            if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }
            if (Test-ContextContains -Lines $Lines -LineIndex $i -Pattern '\[Authorize' -Range 5) {
                $findings += New-Finding `
                    -RuleId 'SEC-DNT-011' `
                    -Category 'Caching Sensitive Data' `
                    -Severity 'Medium' `
                    -Confidence 'High' `
                    -CWE 'CWE-524' `
                    -OWASP 'A04:2021' `
                    -FilePath $FilePath `
                    -LineNumber ($i + 1) `
                    -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                    -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                    -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                    -VulnerableCode (Get-TruncatedVulnCode -Line $Lines[$i]) `
                    -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                    -Description '[OutputCache] on [Authorize] method. Cached pages may serve authenticated content to unauthenticated users or leak sensitive data across sessions.' `
                    -Remediation 'Remove OutputCache from authorized endpoints. Use VaryByCustom with user identity if caching is essential, or use no-store Cache-Control.' `
                    -References @('https://cwe.mitre.org/data/definitions/524.html')
            }
        }
    }

    # =========================================================================
    # SEC-DNT-012: XSS via Html.Raw
    # CWE-79
    # =========================================================================
    $xssPatterns = @(
        '@?Html\.Raw\s*\(',
        'HttpUtility\.HtmlDecode.*Response\.Write',
        'Response\.Write\s*\(.*Request\[',
        'innerHTML\s*=.*(?:Request|user|param|input)'
    )
    foreach ($xp in $xssPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $xp `
            -WhitelistPatterns @('HtmlEncode', 'AntiXss', 'Sanitize', 'HttpUtility\.HtmlEncode') `
            -RuleId 'SEC-DNT-012' `
            -Category 'Cross-Site Scripting' `
            -Severity 'High' `
            -Confidence 'Medium' `
            -CWE 'CWE-79' `
            -OWASP 'A03:2021' `
            -Description 'Unencoded output to HTML. Html.Raw() bypasses Razor auto-encoding. User input rendered without encoding enables XSS attacks.' `
            -Remediation 'Avoid Html.Raw() with user-controlled data. Use @Html.Encode() or Razor default encoding. Apply AntiXss library for rich-text scenarios.' `
            -References @('https://cwe.mitre.org/data/definitions/79.html')
    }

    # =========================================================================
    # SEC-DNT-013: XmlReaderSettings unsafe — DtdProcessing / ProhibitDtd
    # CWE-611
    # =========================================================================
    $xxePatterns = @(
        'DtdProcessing\s*=\s*DtdProcessing\.Parse',
        'ProhibitDtd\s*=\s*false',
        'XmlReaderSettings.*DtdProcessing\.Parse',
        'new\s+XmlDocument\s*\(\s*\)(?!.*XmlResolver\s*=\s*null)',
        'XmlTextReader(?!.*DtdProcessing\s*=\s*DtdProcessing\.Prohibit)'
    )
    foreach ($xxp in $xxePatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $xxp `
            -WhitelistPatterns @('DtdProcessing\.Prohibit', 'XmlResolver\s*=\s*null') `
            -RuleId 'SEC-DNT-013' `
            -Category 'XXE Injection' `
            -Severity 'High' `
            -Confidence 'Medium' `
            -CWE 'CWE-611' `
            -OWASP 'A05:2021' `
            -Description 'XML parser with DTD processing enabled or unsafe defaults. Enables XXE (XML External Entity) attacks for file disclosure, SSRF, and DoS.' `
            -Remediation 'Set DtdProcessing = DtdProcessing.Prohibit and XmlResolver = null. Use XmlReader.Create() with secure XmlReaderSettings.' `
            -References @('https://cwe.mitre.org/data/definitions/611.html')
    }

    # =========================================================================
    # SEC-DNT-014: MachineKey hardcoded in config
    # CWE-321
    # =========================================================================
    $machineKeyPatterns = @(
        '<machineKey\s+[^>]*validationKey\s*=\s*"[A-Fa-f0-9]{20,}"',
        '<machineKey\s+[^>]*decryptionKey\s*=\s*"[A-Fa-f0-9]{20,}"',
        'MachineKey\.(?:ValidationKey|DecryptionKey)\s*=\s*["''][A-Fa-f0-9]{20,}'
    )
    foreach ($mk in $machineKeyPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $mk `
            -WhitelistPatterns @('AutoGenerate', 'IsolateApps') `
            -RuleId 'SEC-DNT-014' `
            -Category 'Hardcoded Crypto Key' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-321' `
            -OWASP 'A02:2021' `
            -Description 'MachineKey with hardcoded validation/decryption key in config. Enables ViewState forgery, cookie tampering, and RCE via deserialization.' `
            -Remediation 'Use machineKey with validation="AutoGenerate,IsolateApps" decryption="AutoGenerate,IsolateApps". For web farms, use Azure Key Vault or DPAPI.' `
            -References @('https://cwe.mitre.org/data/definitions/321.html')
    }

    # =========================================================================
    # SEC-DNT-015: FormsAuthentication insecure settings
    # CWE-614
    # =========================================================================
    $formsAuthPatterns = @(
        @{ P = '<forms\s+[^>]*requireSSL\s*=\s*"false"'; D = 'FormsAuthentication cookie sent over HTTP. Vulnerable to session hijacking via network sniffing.' },
        @{ P = '<forms\s+[^>]*cookieless\s*=\s*"(?:UseUri|Always)"'; D = 'FormsAuthentication using cookieless mode (URL-based session). Session ID exposed in URLs, referer headers, and logs.' },
        @{ P = '<forms\s+[^>]*protection\s*=\s*"None"'; D = 'FormsAuthentication with no encryption or validation. Auth ticket can be forged.' },
        @{ P = '<forms\s+[^>]*slidingExpiration\s*=\s*"true"[^>]*timeout\s*=\s*"\d{4,}"'; D = 'FormsAuthentication with very long timeout and sliding expiration. Increases session hijacking window.' }
    )
    foreach ($fa in $formsAuthPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $fa.P `
            -RuleId 'SEC-DNT-015' `
            -Category 'Insecure Authentication' `
            -Severity 'High' `
            -Confidence 'High' `
            -CWE 'CWE-614' `
            -OWASP 'A07:2021' `
            -Description $fa.D `
            -Remediation 'Set requireSSL="true", cookieless="UseCookies", protection="All". Use reasonable timeout values (20-30 minutes).' `
            -References @('https://cwe.mitre.org/data/definitions/614.html')
    }

    # =========================================================================
    # SEC-DNT-016: ViewStateUserKey not set (CSRF via ViewState)
    # CWE-352
    # =========================================================================
    # Check in Page_Init for ViewStateUserKey assignment
    if ($FilePath -match '\.(aspx\.cs|aspx\.vb)$') {
        $hasPageInit = $false
        $hasViewStateUserKey = $false
        for ($i = 0; $i -lt $Lines.Count; $i++) {
            if ($Lines[$i] -match 'Page_Init|OnInit') { $hasPageInit = $true }
            if ($Lines[$i] -match 'ViewStateUserKey\s*=') { $hasViewStateUserKey = $true }
        }
        if ($hasPageInit -and -not $hasViewStateUserKey) {
            $findings += New-Finding `
                -RuleId 'SEC-DNT-016' `
                -Category 'CSRF via ViewState' `
                -Severity 'Medium' `
                -Confidence 'Low' `
                -CWE 'CWE-352' `
                -OWASP 'A01:2021' `
                -FilePath $FilePath `
                -LineNumber 1 `
                -VulnerableCode 'Page_Init without ViewStateUserKey' `
                -Description 'ASP.NET WebForms page with Page_Init but no ViewStateUserKey assignment. Without per-user ViewState binding, CSRF attacks via ViewState are possible.' `
                -Remediation 'Set Page.ViewStateUserKey = Session.SessionID in Page_Init to bind ViewState to the user session.' `
                -References @('https://cwe.mitre.org/data/definitions/352.html')
        }
    }

    # =========================================================================
    # SEC-DNT-017: AllowHtml without encoding verification
    # CWE-79
    # =========================================================================
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern '\[AllowHtml\]' `
        -WhitelistPatterns @('HtmlEncode', 'AntiXss', 'Sanitize', 'HtmlSanitizer') `
        -RuleId 'SEC-DNT-017' `
        -Category 'Cross-Site Scripting' `
        -Severity 'Medium' `
        -Confidence 'Low' `
        -CWE 'CWE-79' `
        -OWASP 'A03:2021' `
        -Description '[AllowHtml] attribute disables request validation for this property. HTML input accepted without visible sanitization may enable stored XSS.' `
        -Remediation 'When using [AllowHtml], always sanitize output with HtmlSanitizer or AntiXss library before rendering. Never use Html.Raw() with AllowHtml data.' `
        -References @('https://cwe.mitre.org/data/definitions/79.html')

    return $findings
}

Export-ModuleMember -Function 'Invoke-DotNetSpecificRules'
