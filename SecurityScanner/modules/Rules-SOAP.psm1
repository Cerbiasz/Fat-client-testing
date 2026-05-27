#Requires -Version 5.1
<#
.SYNOPSIS
    SOAP/WCF/WebServices rules: unsafe deserialization, missing security,
    HTTP endpoints, SOAPAction manipulation, WSDL exposure.
#>

function Invoke-SOAPRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Lines
    )

    $findings = @()

    # =========================================================================
    # SEC-SOAP-001: SOAP response deserialization without validation
    # CWE-502, CWE-20
    # =========================================================================
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern 'XmlSerializer.*Deserialize\s*\(' `
        -WhitelistPatterns @('XmlSchema', 'Validate', 'XmlSchemaSet') `
        -RuleId 'SEC-SOAP-001' `
        -Category 'Unsafe Deserialization' `
        -Severity 'Medium' `
        -Confidence 'Medium' `
        -CWE 'CWE-502' `
        -OWASP 'A08:2021' `
        -Description 'XmlSerializer.Deserialize called without visible schema validation. Malicious SOAP responses may inject unexpected XML structures.' `
        -Remediation 'Validate XML against XSD schema before deserialization. Use XmlReaderSettings with XmlSchemaSet for validation.' `
        -References @('https://cwe.mitre.org/data/definitions/502.html')

    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern 'WebClient\.DownloadString.*XmlDocument\.LoadXml' `
        -RuleId 'SEC-SOAP-001' `
        -Category 'Unsafe Deserialization' `
        -Severity 'High' `
        -Confidence 'High' `
        -CWE 'CWE-502' `
        -OWASP 'A08:2021' `
        -Description 'HTTP response directly loaded into XmlDocument without validation. Vulnerable to XXE and XML injection.' `
        -Remediation 'Validate and sanitize HTTP responses before XML parsing. Set XmlResolver = null on XmlDocument.' `
        -References @('https://cwe.mitre.org/data/definitions/502.html')

    # =========================================================================
    # SEC-SOAP-002: BasicHttpBinding without transport security
    # CWE-319
    # =========================================================================
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern 'new\s+BasicHttpBinding\s*\(\s*\)' `
        -WhitelistPatterns @('Security\.Mode\s*=\s*BasicHttpSecurityMode\.Transport', 'SecurityMode\.Transport') `
        -RuleId 'SEC-SOAP-002' `
        -Category 'Insecure WCF Binding' `
        -Severity 'High' `
        -Confidence 'Medium' `
        -CWE 'CWE-319' `
        -OWASP 'A02:2021' `
        -Description 'BasicHttpBinding instantiated without transport security. Data transmitted in cleartext by default.' `
        -Remediation 'Set Security.Mode = BasicHttpSecurityMode.Transport or use BasicHttpsBinding.' `
        -References @('https://cwe.mitre.org/data/definitions/319.html')

    $secNonePatterns = @(
        'BasicHttpBinding.*SecurityMode\.None',
        'NetTcpBinding.*SecurityMode\.None',
        '<security\s+mode="None"'
    )
    foreach ($sn in $secNonePatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $sn `
            -RuleId 'SEC-SOAP-002' `
            -Category 'Insecure WCF Binding' `
            -Severity 'High' `
            -Confidence 'High' `
            -CWE 'CWE-319' `
            -OWASP 'A02:2021' `
            -Description 'WCF binding with SecurityMode.None — no transport or message security.' `
            -Remediation 'Set SecurityMode to Transport or TransportWithMessageCredential.' `
            -References @('https://cwe.mitre.org/data/definitions/319.html')
    }

    # =========================================================================
    # SEC-SOAP-008: BasicHttpBinding vs WSHttpBinding (thick client WCF)
    # CWE-319
    # =========================================================================
    $wcfBindingPatterns = @(
        @{ P = '<binding\s+[^>]*name\s*=\s*"[^"]*"[^>]*>[\s\S]*?<basicHttpBinding'; D = 'BasicHttpBinding in WCF config. Does not support message-level security by default.' },
        @{ P = 'new\s+BasicHttpBinding\s*\(\s*BasicHttpSecurityMode\.TransportCredentialOnly'; D = 'BasicHttpBinding with TransportCredentialOnly — credentials sent over HTTP without encryption.' },
        @{ P = 'BasicHttpBinding.*MessageEncoding\s*=\s*WSMessageEncoding\.Text'; D = 'BasicHttpBinding with Text encoding — SOAP messages transmitted as readable plaintext.' }
    )
    foreach ($wb in $wcfBindingPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $wb.P `
            -WhitelistPatterns @('SecurityMode\.Transport', 'BasicHttpsBinding') `
            -RuleId 'SEC-SOAP-008' `
            -Category 'Insecure WCF Binding' `
            -Severity 'High' `
            -Confidence 'Medium' `
            -CWE 'CWE-319' `
            -OWASP 'A02:2021' `
            -Description $wb.D `
            -Remediation 'Use WSHttpBinding (supports WS-Security) or BasicHttpsBinding. For thick clients, prefer NetTcpBinding with SecurityMode.Transport.' `
            -References @('https://cwe.mitre.org/data/definitions/319.html')
    }

    # =========================================================================
    # SEC-SOAP-003: WCF without client authentication
    # CWE-306
    # =========================================================================
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern '(?i)clientCredentialType="None"' `
        -RuleId 'SEC-SOAP-003' `
        -Category 'Missing Authentication' `
        -Severity 'High' `
        -Confidence 'High' `
        -CWE 'CWE-306' `
        -OWASP 'A07:2021' `
        -Description 'WCF endpoint configured with no client authentication. Any client can call the service without credentials.' `
        -Remediation 'Set clientCredentialType to Windows, Certificate, or UserName depending on security requirements.' `
        -References @('https://cwe.mitre.org/data/definitions/306.html')

    # =========================================================================
    # SEC-SOAP-004: HTTP (not HTTPS) SOAP endpoint
    # CWE-319
    # =========================================================================
    $httpPatterns = @(
        'Url\s*=\s*["'']http://(?!localhost|127\.0\.0\.1|::1)',
        '<endpoint\s+address="http://(?!localhost|127\.0\.0\.1)'
    )
    foreach ($hp in $httpPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $hp `
            -RuleId 'SEC-SOAP-004' `
            -Category 'Insecure Transport' `
            -Severity 'High' `
            -Confidence 'High' `
            -CWE 'CWE-319' `
            -OWASP 'A02:2021' `
            -Description 'SOAP/WCF endpoint uses HTTP instead of HTTPS. All data including SOAP messages and credentials transmitted in cleartext.' `
            -Remediation 'Use HTTPS for all external service endpoints. Configure TLS 1.2+ on the server.' `
            -References @('https://cwe.mitre.org/data/definitions/319.html')
    }

    # =========================================================================
    # SEC-SOAP-005: SOAPAction / XML namespace manipulation
    # CWE-918
    # =========================================================================
    $soapActionPatterns = @(
        'SoapAction\s*=.*(\+|\$"|string\.Format)',
        '(?i)soapaction.*\+.*(?:Request\.|user|param|input)',
        'WebRequest\.Create\s*\(.*\+'
    )
    foreach ($sa in $soapActionPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $sa `
            -RuleId 'SEC-SOAP-005' `
            -Category 'SOAP Action Manipulation' `
            -Severity 'High' `
            -Confidence 'Medium' `
            -CWE 'CWE-918' `
            -OWASP 'A10:2021' `
            -Description 'SOAPAction or WebRequest URL built dynamically from user input. May allow SSRF or operation spoofing.' `
            -Remediation 'Use static SOAPAction values and endpoint URLs. Validate against an allowlist of permitted endpoints.' `
            -References @('https://cwe.mitre.org/data/definitions/918.html')
    }

    # =========================================================================
    # SEC-SOAP-006: BinaryFormatter / SoapFormatter (RCE)
    # CWE-502
    # =========================================================================
    # NOTE: Main detection in Rules-Deserialization.psm1 — this covers SOAP-specific context
    $soapDeserPatterns = @(
        'IFormatter.*BinaryFormatter',
        'ObjectStateFormatter'
    )
    foreach ($sd in $soapDeserPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $sd `
            -RuleId 'SEC-SOAP-006' `
            -Category 'Unsafe Deserialization' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-502' `
            -OWASP 'A08:2021' `
            -Description 'IFormatter/ObjectStateFormatter usage detected. These deserializers allow arbitrary code execution via gadget chains.' `
            -Remediation 'Replace with System.Text.Json, DataContractSerializer, or protobuf-net. BinaryFormatter is deprecated as of .NET 8 (SYSLIB0011).' `
            -References @('https://cwe.mitre.org/data/definitions/502.html')
    }

    # =========================================================================
    # SEC-SOAP-007: WSDL metadata enabled in production
    # CWE-200
    # =========================================================================
    $wsdlPatterns = @(
        '<serviceMetadata\s+httpGetEnabled="true"',
        'ServiceMetadataBehavior.*HttpGetEnabled\s*=\s*true',
        'mexHttpBinding|mexTcpBinding'
    )
    foreach ($wp in $wsdlPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $wp `
            -RuleId 'SEC-SOAP-007' `
            -Category 'Information Disclosure' `
            -Severity 'Medium' `
            -Confidence 'Medium' `
            -CWE 'CWE-200' `
            -OWASP 'A05:2021' `
            -Description 'WCF service metadata (WSDL) enabled. Exposes service interface, operations, and data types to potential attackers.' `
            -Remediation 'Disable serviceMetadata in production. Set httpGetEnabled="false" and remove MEX endpoints.' `
            -References @('https://cwe.mitre.org/data/definitions/200.html')
    }

    return $findings
}

Export-ModuleMember -Function 'Invoke-SOAPRules'
