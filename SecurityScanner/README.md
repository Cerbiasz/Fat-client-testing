# .NET Security Scanner v2.1.0

Skaner bezpieczenstwa kodu zrodlowego dla aplikacji .NET Framework 4.8 (fat client) z Oracle DB i SOAP/WCF.

## Szybki start

```powershell
# Pelny skan z raportem HTML
.\Invoke-SecurityScan.ps1 -SourcePath "C:\Projects\MyApp\src" -OutputPath ".\report.html"

# Skan z raportem JSON
.\Invoke-SecurityScan.ps1 -SourcePath ".\decompiled" -OutputPath ".\report.html" -JsonOutput ".\report.json"

# Tylko Critical i High
.\Invoke-SecurityScan.ps1 -SourcePath ".\src" -OutputPath ".\report.html" -Severity "Critical,High"

# Z wykluczeniami i verbose
.\Invoke-SecurityScan.ps1 -SourcePath ".\src" -OutputPath ".\report.html" `
    -ExcludePaths "obj,bin,\.Designer\.cs$" `
    -MaxFileSizeMB 10 `
    -EnableVerbose
```

## Testowanie na przykladach

```powershell
# Skan podatnego kodu (powinien znalezc 30+ findings)
.\Invoke-SecurityScan.ps1 -SourcePath ".\tests\VulnerableApp.cs" -OutputPath ".\test_vuln.html" -JsonOutput ".\test_vuln.json" -ScanTests

# Skan bezpiecznego kodu (powinien znalezc 0 findings)
.\Invoke-SecurityScan.ps1 -SourcePath ".\tests\SecureApp.cs" -OutputPath ".\test_safe.html" -ScanTests

# Skan konfiguracji
.\Invoke-SecurityScan.ps1 -SourcePath ".\tests\VulnerableConfig.config" -OutputPath ".\test_config.html"
```

## Moduly regul

| Modul | Reguly | Zakres |
|-------|--------|--------|
| Rules-Injection | SEC-ORA-001..003, SEC-XML-001, SEC-CMD-001, SEC-LDAP-001, SEC-XPATH-001 | SQL/XML/OS/LDAP/XPath injection |
| Rules-Cryptography | SEC-CRYPT-001..007 | MD5, SHA1, DES, hardcoded keys, Random, TLS, RSA |
| Rules-Authentication | SEC-AUTH-001..005 | Hardcoded creds, plain text passwords, weak hashing, auth bypass |
| Rules-DataExposure | SEC-DATA-001..004 | Sensitive logging, data in URLs, stack traces, IDOR |
| Rules-Oracle | SEC-ORA-010..014, SEC-CFG-001 | Oracle connection creds, exception handling, privileges, TNS, config |
| Rules-SOAP | SEC-SOAP-001..007 | SOAP/WCF security, HTTP endpoints, WSDL, SOAPAction |
| Rules-Deserialization | SEC-SOAP-006, SEC-DESER-001..003, SEC-DNT-007 | BinaryFormatter, JSON.NET, DataSet.ReadXml |
| Rules-FileSystem | SEC-FILE-001..003 | Path traversal, insecure temp files, ZIP slip |
| Rules-NetworkSecurity | SEC-NET-001..003 | TLS config, open redirect, SSRF |
| Rules-DotNetSpecific | SEC-DNT-001..006 | Reflection, unsafe code, CAS, ViewState, ReDoS |

## Konfiguracja

Plik `scanner-config.json`:

```json
{
  "excluded_paths": ["obj", "bin"],
  "excluded_rules": ["SEC-ORA-013"],
  "severity_overrides": { "SEC-CRYPT-002": "Low" },
  "custom_sensitive_keywords": ["PESEL", "NIP"]
}
```

## Redukcja false positive

Skaner implementuje wielowarstwowa weryfikacje:
1. **Dead code detection** - pomija komentarze, `#if DEBUG`, `[Obsolete]`
2. **Test file detection** - pliki z Test/Mock/Stub w nazwie
3. **Whitelist patterns** - np. `OracleParameter` w poblizu anuluje SQL injection finding
4. **Context analysis** - sliding window 15 linii w gore/dol
5. **Confidence levels** - Low confidence = wymaga manualnej weryfikacji

## Struktura raportow

**HTML**: interaktywny raport z filtrami, sortowaniem, detalami per finding, statystykami.
**JSON**: maszynowo czytelny format SARIF-like z pelnym kontekstem.

## Znane ograniczenia

- Strip komentarzy moze blednie obciac `//` wewnatrz string literalow (np. URLi)
- Analiza taint jest uproszczona (regex-based, nie pelny AST)
- Reguly SEC-DNT-005 (ViewState) dotycza tylko ASP.NET WebForms
- SEC-ORA-013 (bulk ops) wymaga zawsze manualnej weryfikacji (Confidence: Low)

## Wymagania

- PowerShell 5.1+ (Windows) lub PowerShell 7+ (cross-platform)
- Brak zewnetrznych zaleznosci
