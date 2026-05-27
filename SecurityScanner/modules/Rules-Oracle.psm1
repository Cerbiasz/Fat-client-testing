#Requires -Version 5.1
<#
.SYNOPSIS
    Oracle ODP.NET specific rules: connection pooling creds, exception handling,
    excessive privileges, bulk operations, config credentials, TNS injection.
#>

function Invoke-OracleRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Lines
    )

    $findings = @()
    $isConfigFile = $FilePath -match '\.(config|xml|resx)$'

    # =========================================================================
    # SEC-ORA-010: Connection string with hardcoded credentials
    # CWE-798
    # =========================================================================
    $connStrPatterns = @(
        '(?i)Data Source\s*=.*;\s*User\s*Id\s*=\s*[^;{]+;\s*Password\s*=\s*(?!\{)[^;''"]{3,}',
        'OracleConnection\s*\(\s*["''].*Password=(?!\s*\{|\s*@|\s*%)[^;''"]{3,}'
    )
    foreach ($cp in $connStrPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $cp `
            -WhitelistPatterns @('(?i)(test|mock|fake|placeholder|changeme|TODO)') `
            -RuleId 'SEC-ORA-010' `
            -Category 'Hardcoded Credentials' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-798' `
            -OWASP 'A07:2021' `
            -Description 'Oracle connection string with hardcoded credentials. Database password exposed in source code or configuration.' `
            -Remediation 'Use Oracle Wallet, DPAPI encrypted config sections, Azure Key Vault, or environment variables for connection string credentials.' `
            -References @('https://cwe.mitre.org/data/definitions/798.html')
    }

    # SYS/SYSTEM login
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern '(?i)User\s*ID=SYSTEM|User\s*ID=SYS\b|DBA\s+Privilege' `
        -RuleId 'SEC-ORA-010' `
        -Category 'Excessive Privileges' `
        -Severity 'Critical' `
        -Confidence 'High' `
        -CWE 'CWE-250' `
        -OWASP 'A04:2021' `
        -Description 'Application connects to Oracle as SYS/SYSTEM — these are DBA accounts. Application should use a least-privilege account.' `
        -Remediation 'Create a dedicated application schema with minimal required grants. Never use SYS/SYSTEM for application connections.' `
        -References @('https://cwe.mitre.org/data/definitions/250.html')

    # =========================================================================
    # SEC-ORA-011: Missing OracleException handling
    # CWE-209
    # =========================================================================
    $oracleExecPatterns = @(
        '\.ExecuteNonQuery\s*\(',
        '\.ExecuteReader\s*\(',
        '\.ExecuteScalar\s*\('
    )
    foreach ($ep in $oracleExecPatterns) {
        for ($i = 0; $i -lt $Lines.Count; $i++) {
            if ($Lines[$i] -notmatch $ep) { continue }
            if (Test-IsDeadCode -Lines $Lines -LineIndex $i) { continue }

            # Must be in Oracle context
            if (-not (Test-ContextContains -Lines $Lines -LineIndex $i -Pattern 'OracleCommand|OracleConnection|OracleDataAdapter' -Range 20)) { continue }

            # Must have try-catch
            if (Test-ContextContains -Lines $Lines -LineIndex $i -Pattern 'try\s*\{|catch\s*\(' -Range 20) { continue }

            $findings += New-Finding `
                -RuleId 'SEC-ORA-011' `
                -Category 'Information Disclosure' `
                -Severity 'Medium' `
                -Confidence 'Low' `
                -CWE 'CWE-209' `
                -OWASP 'A05:2021' `
                -FilePath $FilePath `
                -LineNumber ($i + 1) `
                -FunctionName (Get-ContainingMethod -Lines $Lines -LineIndex $i) `
                -ClassName (Get-ContainingClass -Lines $Lines -LineIndex $i) `
                -Namespace (Get-ContainingNamespace -Lines $Lines -LineIndex $i) `
                -VulnerableCode $Lines[$i].Trim() `
                -CodeContext (Get-CodeContext -Lines $Lines -LineNumber ($i + 1)) `
                -Description 'Oracle command execution without visible try-catch. Unhandled OracleException may expose schema details, table names, and SQL to the user.' `
                -Remediation 'Wrap Oracle operations in try-catch(OracleException). Log details server-side and show generic error to user.' `
                -References @('https://cwe.mitre.org/data/definitions/209.html')
        }
    }

    # =========================================================================
    # SEC-ORA-012: Excessive Oracle privileges
    # CWE-250
    # =========================================================================
    $privPatterns = @(
        '(?i)GRANT\s+(?:DBA|SYSDBA|EXECUTE\s+ANY|CREATE\s+ANY|DROP\s+ANY|ALL\s+PRIVILEGES)',
        '(?i)CONNECT\s+AS\s+(?:SYSDBA|SYSOPER)',
        'OracleConnection.*DBAPrivilege\s*=\s*DBAPrivilege\.SYSDBA'
    )
    foreach ($pp in $privPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $pp `
            -RuleId 'SEC-ORA-012' `
            -Category 'Excessive Privileges' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-250' `
            -OWASP 'A04:2021' `
            -Description 'Code grants or uses DBA-level Oracle privileges. Application accounts should follow the principle of least privilege.' `
            -Remediation 'Use a dedicated application account with only the required object-level grants (SELECT, INSERT, UPDATE on specific tables).' `
            -References @('https://cwe.mitre.org/data/definitions/250.html')
    }

    # =========================================================================
    # SEC-ORA-013: Bulk operations without size validation
    # CWE-400
    # =========================================================================
    $bulkPatterns = @(
        @{ P = 'OracleBulkCopy\s*\('; D = 'OracleBulkCopy without visible input size validation. Verify that record count/file size is checked before bulk insert.' },
        @{ P = 'OracleDataAdapter\.Fill\s*\('; D = 'OracleDataAdapter.Fill without visible row limit. Verify that query includes ROWNUM/FETCH FIRST or that MaxRecords is set.' }
    )
    foreach ($bp in $bulkPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $bp.P `
            -RuleId 'SEC-ORA-013' `
            -Category 'Denial of Service' `
            -Severity 'Low' `
            -Confidence 'Low' `
            -CWE 'CWE-400' `
            -Description $bp.D `
            -Remediation 'Validate input size before bulk operations. Use ROWNUM or FETCH FIRST N ROWS in queries. Set MaxRecords on DataAdapter.' `
            -References @('https://cwe.mitre.org/data/definitions/400.html')
    }

    # =========================================================================
    # SEC-CFG-001: Hardcoded credentials in config/XML files
    # CWE-260, CWE-312
    # =========================================================================
    if ($isConfigFile) {
        $cfgPatterns = @(
            @{
                P = '<add\s+[^>]*(?i)(?:key|name)=["''][^"'']*(?:password|passwd|pwd|secret|apikey|api.key|token)[^"'']*["''][^>]*(?i)value=["''](?!\s*\{|\s*%|\s*\$)[^"'']{3,}["'']'
                D = 'Config file <add> element with credential-named key and non-empty, non-placeholder value.'
            },
            @{
                P = '<add\s+[^>]*connectionString=["''][^"'']*(?i)Password\s*=\s*(?!\s*\{|\s*%)[^;''"]{3,}'
                D = 'Connection string in config file with hardcoded password.'
            },
            @{
                P = '(?i)(password|secret|token|apikey)\s*=\s*["''](?!\s*\{|\s*%)[^"'']{3,}["'']'
                D = 'Generic credential pattern in XML/config file.'
            }
        )
        $cfgWhitelist = @('value=""', 'value="changeme"', '<!--')

        foreach ($cfp in $cfgPatterns) {
            $findings += Invoke-RegexRuleOnFile `
                -FilePath $FilePath -Lines $Lines `
                -Pattern $cfp.P `
                -WhitelistPatterns $cfgWhitelist `
                -RuleId 'SEC-CFG-001' `
                -Category 'Hardcoded Credentials (Config)' `
                -Severity 'High' `
                -Confidence 'High' `
                -CWE 'CWE-260' `
                -OWASP 'A07:2021' `
                -Description $cfp.D `
                -Remediation 'Use encrypted config sections (aspnet_regiis -pe), Azure Key Vault, or DPAPI. Never store plaintext credentials in config files checked into source control.' `
                -References @('https://cwe.mitre.org/data/definitions/260.html', 'https://cwe.mitre.org/data/definitions/312.html')
        }
    }

    # =========================================================================
    # SEC-ORA-014: TNS Injection
    # CWE-74
    # =========================================================================
    $tnsPatterns = @(
        '(?i)Data Source\s*=\s*["'']?\s*\(DESCRIPTION.*\+',
        '(?i)TNS_ADMIN.*\+|tnsnames.*string\.Format|tnsnames.*\$"'
    )
    foreach ($tp in $tnsPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $tp `
            -RuleId 'SEC-ORA-014' `
            -Category 'TNS Injection' `
            -Severity 'High' `
            -Confidence 'Medium' `
            -CWE 'CWE-74' `
            -OWASP 'A03:2021' `
            -Description 'TNS connection descriptor built dynamically with string concatenation. May allow connection redirection to a malicious Oracle instance.' `
            -Remediation 'Use static TNS entries in tnsnames.ora or LDAP-based name resolution. Never build TNS descriptors from user input.' `
            -References @('https://cwe.mitre.org/data/definitions/74.html')
    }

    return $findings
}

Export-ModuleMember -Function 'Invoke-OracleRules'
