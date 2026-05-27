#Requires -Version 5.1
<#
.SYNOPSIS
    Deserialization rules: BinaryFormatter, SoapFormatter, JSON.NET TypeNameHandling,
    XmlSerializer with dynamic type, LosFormatter, NetDataContractSerializer, DataSet.ReadXml.
#>

function Invoke-DeserializationRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Lines
    )

    $findings = @()

    # =========================================================================
    # SEC-SOAP-006 / SEC-DESER-BINARY: BinaryFormatter, SoapFormatter, etc.
    # CWE-502 — ALWAYS Critical
    # =========================================================================
    $dangerousDeserializers = @(
        @{ P = 'new\s+BinaryFormatter\s*\('; N = 'BinaryFormatter' },
        @{ P = 'new\s+SoapFormatter\s*\('; N = 'SoapFormatter' },
        @{ P = 'BinaryFormatter\s*\{[^}]*\}\.Deserialize'; N = 'BinaryFormatter.Deserialize' },
        @{ P = 'BinaryFormatter.*\.Deserialize\s*\('; N = 'BinaryFormatter.Deserialize' },
        @{ P = 'SoapFormatter.*\.Deserialize\s*\('; N = 'SoapFormatter.Deserialize' },
        @{ P = 'new\s+NetDataContractSerializer\s*\('; N = 'NetDataContractSerializer' },
        @{ P = 'NetDataContractSerializer.*\.ReadObject\s*\('; N = 'NetDataContractSerializer.ReadObject' },
        @{ P = 'new\s+LosFormatter\s*\('; N = 'LosFormatter' },
        @{ P = 'LosFormatter.*\.Deserialize\s*\('; N = 'LosFormatter.Deserialize' }
    )

    foreach ($dd in $dangerousDeserializers) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $dd.P `
            -RuleId 'SEC-SOAP-006' `
            -Category 'Unsafe Deserialization' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-502' `
            -OWASP 'A08:2021' `
            -Description ('{0} is inherently insecure - deserializes type info from input stream, enabling RCE via gadget chains. Microsoft deprecated BinaryFormatter (SYSLIB0011).' -f $dd.N) `
            -Remediation 'Replace with System.Text.Json.JsonSerializer, DataContractSerializer (with known types), or protobuf-net. Never use BinaryFormatter/SoapFormatter/LosFormatter.' `
            -References @('https://cwe.mitre.org/data/definitions/502.html', 'https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide')
    }

    # =========================================================================
    # SEC-DESER-001: JSON.NET TypeNameHandling
    # CWE-502
    # =========================================================================
    $jsonNetPatterns = @(
        'TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Objects|Arrays|Auto)',
        'JsonSerializerSettings\s*\{[^}]*TypeNameHandling\s*=\s*TypeNameHandling\.(?!None)',
        'JsonConvert\.DeserializeObject.*TypeNameHandling\.(?!None)'
    )
    foreach ($jp in $jsonNetPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $jp `
            -WhitelistPatterns @('TypeNameHandling\.None', 'SerializationBinder', 'KnownTypesBinder') `
            -RuleId 'SEC-DESER-001' `
            -Category 'Unsafe Deserialization' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-502' `
            -OWASP 'A08:2021' `
            -Description 'Newtonsoft.Json TypeNameHandling set to All/Objects/Arrays/Auto. Enables RCE via JSON gadget chains (e.g., ObjectDataProvider, ActivitySurrogateSelector).' `
            -Remediation 'Set TypeNameHandling = TypeNameHandling.None (default). If type handling is required, use a strict SerializationBinder with an explicit type allowlist.' `
            -References @('https://cwe.mitre.org/data/definitions/502.html', 'https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf')
    }

    # =========================================================================
    # SEC-DESER-002: XmlSerializer with dynamic type
    # CWE-502
    # =========================================================================
    $xmlSerPatterns = @(
        'new\s+XmlSerializer\s*\(\s*Type\.GetType\s*\(',
        'new\s+XmlSerializer\s*\(\s*\w+\.GetType\s*\(\s*(?:Request\.|param|user|input)'
    )
    foreach ($xp in $xmlSerPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $xp `
            -RuleId 'SEC-DESER-002' `
            -Category 'Unsafe Deserialization' `
            -Severity 'High' `
            -Confidence 'High' `
            -CWE 'CWE-502' `
            -OWASP 'A08:2021' `
            -Description 'XmlSerializer instantiated with a type determined dynamically from external input. Attacker can control which type is deserialized.' `
            -Remediation 'Use XmlSerializer with compile-time known types only. Never pass user-controlled type names to Type.GetType().' `
            -References @('https://cwe.mitre.org/data/definitions/502.html')
    }

    # =========================================================================
    # SEC-DESER-003: LosFormatter (ViewState without MAC)
    # CWE-502
    # =========================================================================
    # Already covered in SEC-SOAP-006 above for LosFormatter itself
    # This catches the specific ViewState pattern
    $findings += Invoke-RegexRuleOnFile `
        -FilePath $FilePath -Lines $Lines `
        -Pattern 'new\s+LosFormatter\s*\(\s*\)' `
        -RuleId 'SEC-DESER-003' `
        -Category 'Unsafe Deserialization' `
        -Severity 'Critical' `
        -Confidence 'High' `
        -CWE 'CWE-502' `
        -OWASP 'A08:2021' `
        -Description 'LosFormatter without MAC validation — vulnerable to RCE via ViewState deserialization gadgets.' `
        -Remediation 'Do not use LosFormatter. For ASP.NET ViewState, ensure enableViewStateMac="true" (default in .NET 4.5.2+). Prefer JSON-based state management.' `
        -References @('https://cwe.mitre.org/data/definitions/502.html')

    # =========================================================================
    # SEC-DESER-004: JavaScriptSerializer with SimpleTypeResolver
    # CWE-502
    # =========================================================================
    $jsSerPatterns = @(
        'new\s+JavaScriptSerializer\s*\(\s*new\s+SimpleTypeResolver',
        'JavaScriptTypeResolver.*SimpleTypeResolver',
        'JavaScriptSerializer\s*\{[^}]*TypeResolver\s*=\s*new\s+SimpleTypeResolver'
    )
    foreach ($jsp in $jsSerPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $jsp `
            -RuleId 'SEC-DESER-004' `
            -Category 'Unsafe Deserialization' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-502' `
            -OWASP 'A08:2021' `
            -Description 'JavaScriptSerializer with SimpleTypeResolver enables arbitrary type instantiation. Attacker-controlled JSON can achieve RCE via ObjectDataProvider or similar gadgets.' `
            -Remediation 'Remove SimpleTypeResolver. Use JavaScriptSerializer without a type resolver, or migrate to System.Text.Json.JsonSerializer.' `
            -References @('https://cwe.mitre.org/data/definitions/502.html', 'https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf')
    }

    # =========================================================================
    # SEC-DESER-005: DataContractJsonSerializer with dynamic type
    # CWE-502
    # =========================================================================
    $dcjsPatterns = @(
        'new\s+DataContractJsonSerializer\s*\(\s*Type\.GetType\s*\(',
        'new\s+DataContractJsonSerializer\s*\(\s*\w+\.GetType\s*\(\s*(?:Request\.|param|user|input)',
        'DataContractJsonSerializer\s*\(\s*typeof\s*\(\s*object\s*\)\s*\)'
    )
    foreach ($dcp in $dcjsPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $dcp `
            -RuleId 'SEC-DESER-005' `
            -Category 'Unsafe Deserialization' `
            -Severity 'High' `
            -Confidence 'High' `
            -CWE 'CWE-502' `
            -OWASP 'A08:2021' `
            -Description 'DataContractJsonSerializer instantiated with dynamic or overly broad type. Attacker may control which type is deserialized, leading to RCE.' `
            -Remediation 'Use DataContractJsonSerializer with compile-time known types only. Prefer System.Text.Json with strict type handling.' `
            -References @('https://cwe.mitre.org/data/definitions/502.html')
    }

    # =========================================================================
    # SEC-DESER-006: Exotic dangerous deserializers
    # CWE-502 (FsPickler, SharpSerializer, MessagePack LZ4, FastJson)
    # =========================================================================
    $exoticDeserializers = @(
        @{ P = 'FsPickler.*(?:Deserialize|UnPickle|Read)'; N = 'FsPickler' },
        @{ P = 'SharpSerializer.*(?:Deserialize|Read)'; N = 'SharpSerializer' },
        @{ P = 'new\s+SharpSerializer\s*\('; N = 'SharpSerializer' },
        @{ P = 'MessagePackSerializer\.(?:Deserialize|Unpack)'; N = 'MessagePack' },
        @{ P = 'fastJSON\.JSON\.ToObject'; N = 'fastJSON' },
        @{ P = 'JSON\.Parse.*TypeInfo'; N = 'fastJSON with TypeInfo' }
    )
    foreach ($ed in $exoticDeserializers) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $ed.P `
            -RuleId 'SEC-DESER-006' `
            -Category 'Unsafe Deserialization' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-502' `
            -OWASP 'A08:2021' `
            -Description ('{0} deserializer detected. Known to be exploitable via gadget chains (ysoserial.net). Can achieve Remote Code Execution.' -f $ed.N) `
            -Remediation 'Replace with System.Text.Json.JsonSerializer or DataContractSerializer with known types. These serializers are listed as dangerous in ysoserial.net.' `
            -References @('https://cwe.mitre.org/data/definitions/502.html', 'https://github.com/pwntester/ysoserial.net')
    }

    # =========================================================================
    # SEC-DESER-007: .NET Remoting TypeFilterLevel.Full
    # CWE-502
    # =========================================================================
    $remotingPatterns = @(
        'TypeFilterLevel\s*=\s*TypeFilterLevel\.Full',
        'TypeFilterLevel\.Full',
        'new\s+BinaryServerFormatterSinkProvider',
        'new\s+BinaryClientFormatterSinkProvider',
        'new\s+SoapServerFormatterSinkProvider',
        'RemotingConfiguration\.Configure\s*\('
    )
    foreach ($rmp in $remotingPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $rmp `
            -RuleId 'SEC-DESER-007' `
            -Category 'Unsafe Deserialization' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-502' `
            -OWASP 'A08:2021' `
            -Description '.NET Remoting with TypeFilterLevel.Full or formatter sink providers. Enables arbitrary type deserialization and RCE via gadget chains.' `
            -Remediation '.NET Remoting is deprecated. Migrate to WCF or gRPC. If unavoidable, set TypeFilterLevel.Low (though still not fully safe).' `
            -References @('https://cwe.mitre.org/data/definitions/502.html', 'https://github.com/pwntester/ysoserial.net')
    }

    # =========================================================================
    # SEC-DNT-007: DataSet.ReadXml / DataTable.ReadXml (RCE)
    # CWE-502 — CVE-2020-1147
    # =========================================================================
    $dataSetPatterns = @(
        '(?:DataSet|DataTable)\.ReadXml\s*\(',
        '(?:DataSet|DataTable)\.ReadXmlSchema\s*\('
    )
    foreach ($ds in $dataSetPatterns) {
        $findings += Invoke-RegexRuleOnFile `
            -FilePath $FilePath -Lines $Lines `
            -Pattern $ds `
            -RuleId 'SEC-DNT-007' `
            -Category 'Unsafe Deserialization' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -CWE 'CWE-502' `
            -OWASP 'A08:2021' `
            -Description 'DataSet/DataTable.ReadXml is vulnerable to RCE via XML deserialization (CVE-2020-1147). Microsoft Security Advisory confirms this as critical.' `
            -Remediation 'Avoid DataSet.ReadXml with untrusted input. Use typed DataSets, DTOs with System.Text.Json, or apply the .NET SerializationGuard.' `
            -References @('https://cwe.mitre.org/data/definitions/502.html', 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1147')
    }

    return $findings
}

Export-ModuleMember -Function 'Invoke-DeserializationRules'
