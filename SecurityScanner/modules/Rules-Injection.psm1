#Requires -Version 5.1
<#
.SYNOPSIS
    Injection rules: SQL (Oracle), XXE, Command, LDAP, XPath injection.
#>

function Invoke-InjectionRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Lines
    )

    $findings = @()

    # =========================================================================
    # SEC-ORA-001: Oracle SQL Injection via String Concatenation
    # CWE-89 | OWASP A03:2021
    # =========================================================================
    $sqlKeywords = '\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|EXEC(?:UTE)?|MERGE|CALL)\b'
    $concatPatterns = @(
        '(\+\s*\w+)',
        '(\+\s*")',
        '\bstring\.Format\b',
        '\$"[^"]*\{[^}]+\}',
        'String\.Concat',
        'StringBuilder\.(Append|AppendLine)'
    )
    $oracleContext = '(OracleCommand|OracleConnection|OracleDataAdapter|new\s+OracleCommand)'
    $sqlWhitelist = @(
        'OracleParameter',
        'CommandType\.StoredProcedure',
        '\.Parameters\.Add',
        '\.Parameters\.AddWithValue',
        '\.\s*Parameters\s*\.\s*Add\s*\(\s*":\w+'
    )

    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i]
        if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }

        $window = Get-SlidingWindowText -Lines $Lines -CenterLineIndex $i -WindowSize 7

        # Must have SQL keyword on or near this line
        if ($line -notmatch $sqlKeywords -and $window -notmatch $sqlKeywords) { continue }

        # Must have concatenation on this line
        $hasConcatOnLine = $false
        foreach ($cp in $concatPatterns) {
            if ($line -match $cp) { $hasConcatOnLine = $true; break }
        }
        if (-not $hasConcatOnLine) { continue }

        # Must have Oracle context within range
        if (-not (Test-ContextContains -Lines $Lines -LineIndex $i -Pattern $oracleContext -Range 15)) { continue }

        # Whitelist check
        if (Test-WhitelistMatch -Lines $Lines -LineIndex $i -WhitelistPatterns $sqlWhitelist -ContextRange 15) { continue }

        $findings += New-Finding `
            -RuleId 'SEC-ORA-001' `
            -Category 'SQL Injection' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-89' `
            -OWASP 'A03:2021' `
            -FilePath $FilePath `
            -LineNumber ($i + 1) `
            -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
            -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
            -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
            -VulnerableCode $line.Trim() `
            -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
            -Description 'String concatenation used to build SQL query passed to OracleCommand. User-supplied data may be injected into the SQL statement.' `
            -Remediation 'Use parameterized queries with OracleParameter. Replace concatenation with bind variables (:paramName) and add parameters via cmd.Parameters.Add().' `
            -References @('https://cwe.mitre.org/data/definitions/89.html', 'https://owasp.org/Top10/A03_2021-Injection/')
    }

    # =========================================================================
    # SEC-ORA-002: Dynamic EXECUTE IMMEDIATE (PL/SQL files)
    # CWE-89 | OWASP A03:2021
    # =========================================================================
    if ($FilePath -match '\.(sql|pks|pkb|trg|prc|fnc)$') {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern 'EXECUTE\s+IMMEDIATE\s.*?\|\|' `
            -RuleId 'SEC-ORA-002' `
            -Category 'SQL Injection' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-89' `
            -OWASP 'A03:2021' `
            -Description 'EXECUTE IMMEDIATE with string concatenation (||) in PL/SQL. Enables SQL injection in stored procedures.' `
            -Remediation 'Use EXECUTE IMMEDIATE with USING clause for bind variables instead of concatenation.' `
            -References @('https://cwe.mitre.org/data/definitions/89.html')

        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern 'DBMS_SQL\.(PARSE|EXECUTE).*?\|\|' `
            -RuleId 'SEC-ORA-002' `
            -Category 'SQL Injection' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-89' `
            -OWASP 'A03:2021' `
            -Description 'DBMS_SQL with string concatenation in PL/SQL. Enables SQL injection.' `
            -Remediation 'Use bind variables with DBMS_SQL.BIND_VARIABLE instead of concatenation.' `
            -References @('https://cwe.mitre.org/data/definitions/89.html')
    }

    # =========================================================================
    # SEC-ORA-003: CommandText dynamic build
    # CWE-89 | OWASP A03:2021
    # =========================================================================
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern '\.CommandText\s*=\s*.*?(\+|String\.Format|string\.Concat|\$")' `
        -ContextPattern 'OracleCommand|SqlCommand|DbCommand' `
        -WhitelistPatterns @('\.CommandType\s*=\s*CommandType\.StoredProcedure', 'OracleParameter', '\.Parameters\.Add') `
        -RuleId 'SEC-ORA-003' `
        -Category 'SQL Injection' `
        -Severity 'Critical' `
        -Confidence 'High' `
        -CWE 'CWE-89' `
        -OWASP 'A03:2021' `
        -Description 'CommandText property is set using string concatenation. This enables SQL injection.' `
        -Remediation 'Use parameterized queries. Set CommandText with bind variable placeholders and add OracleParameter objects.' `
        -References @('https://cwe.mitre.org/data/definitions/89.html')

    # =========================================================================
    # SEC-XML-001: XXE — XmlDocument without XmlResolver=null
    # CWE-611 | OWASP A05:2021
    # =========================================================================
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern 'new\s+XmlDocument\s*\(' `
        -WhitelistPatterns @('\.XmlResolver\s*=\s*null') `
        -RuleId 'SEC-XML-001' `
        -Category 'XXE Injection' `
        -Severity 'High' `
        -Confidence 'Medium' `
        -CWE 'CWE-611' `
        -OWASP 'A05:2021' `
        -Description 'XmlDocument instantiated without setting XmlResolver to null. In .NET Framework 4.x, this allows XML External Entity (XXE) attacks by default.' `
        -Remediation 'Set doc.XmlResolver = null immediately after creating the XmlDocument instance.' `
        -References @('https://cwe.mitre.org/data/definitions/611.html', 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/')

    # XXE via XmlTextReader
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern 'new\s+XmlTextReader\s*\(' `
        -WhitelistPatterns @('\.ProhibitDtd\s*=\s*true', 'DtdProcessing\.Prohibit') `
        -RuleId 'SEC-XML-001' `
        -Category 'XXE Injection' `
        -Severity 'High' `
        -Confidence 'Medium' `
        -CWE 'CWE-611' `
        -OWASP 'A05:2021' `
        -Description 'XmlTextReader without DTD processing prohibition. Vulnerable to XXE.' `
        -Remediation 'Set reader.DtdProcessing = DtdProcessing.Prohibit or reader.ProhibitDtd = true.' `
        -References @('https://cwe.mitre.org/data/definitions/611.html')

    # =========================================================================
    # SEC-CMD-001: OS Command Injection
    # CWE-78 | OWASP A03:2021
    # =========================================================================
    $cmdPatterns = @(
        @{ Pattern = 'Process\.Start\s*\(.*?(\+|\$"|string\.Format)'; Desc = 'Process.Start with dynamic argument' },
        @{ Pattern = 'ProcessStartInfo\s*\{[^}]*FileName\s*=.*?(\+|\$"|string\.Format)'; Desc = 'ProcessStartInfo.FileName with concatenation' },
        @{ Pattern = '(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe).*?(\+|\$")'; Desc = 'Shell interpreter invocation with dynamic input' }
    )

    foreach ($cp in $cmdPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $cp.Pattern `
            -WhitelistPatterns @('^\s*//.*Process\.Start', 'Path\.Combine\(.*?Assembly\.GetExecutingAssembly') `
            -RuleId 'SEC-CMD-001' `
            -Category 'Command Injection' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-78' `
            -OWASP 'A03:2021' `
            -Description ('OS Command Injection: {0}. External data passed to system command execution.' -f $cp.Desc) `
            -Remediation 'Avoid passing user input to Process.Start. Use allowlists for permitted commands and validate/sanitize all arguments.' `
            -References @('https://cwe.mitre.org/data/definitions/78.html')
    }

    # =========================================================================
    # SEC-LDAP-001: LDAP Injection
    # CWE-90 | OWASP A03:2021
    # =========================================================================
    $ldapPatterns = @(
        'DirectorySearcher.*?Filter\s*=.*?(\+|\$"|string\.Format)',
        'DirectoryEntry.*?Path\s*=.*?LDAP://.*?(\+|\$")',
        'new\s+DirectorySearcher\s*\([^)]*(\+|\$")'
    )
    foreach ($lp in $ldapPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $lp `
            -RuleId 'SEC-LDAP-001' `
            -Category 'LDAP Injection' `
            -Severity 'High' `
            -Confidence 'High' `
            -CWE 'CWE-90' `
            -OWASP 'A03:2021' `
            -Description 'LDAP filter or path built with string concatenation. User input may alter LDAP query logic.' `
            -Remediation 'Sanitize LDAP special characters (*, (, ), \, NUL) or use parameterized LDAP queries.' `
            -References @('https://cwe.mitre.org/data/definitions/90.html')
    }

    # =========================================================================
    # SEC-XPATH-001: XPath Injection
    # CWE-643 | OWASP A03:2021
    # =========================================================================
    $xpathPatterns = @(
        'SelectNodes\s*\(.*?(\+|\$"|string\.Format)',
        'SelectSingleNode\s*\(.*?(\+|\$"|string\.Format)',
        'XPathExpression.*?Compile\s*\(.*?(\+|\$")',
        '\.CreateNavigator\(\).*?Select\s*\(.*?(\+|\$")'
    )
    foreach ($xp in $xpathPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $xp `
            -RuleId 'SEC-XPATH-001' `
            -Category 'XPath Injection' `
            -Severity 'High' `
            -Confidence 'Medium' `
            -CWE 'CWE-643' `
            -OWASP 'A03:2021' `
            -Description 'XPath expression built via string concatenation with potentially untrusted input.' `
            -Remediation 'Use XPathExpression.Compile with XsltContext and variables, or validate/sanitize input against XPath special characters.' `
            -References @('https://cwe.mitre.org/data/definitions/643.html')
    }

    return $findings
}

Export-ModuleMember -Function 'Invoke-InjectionRules'
