# Przechwytywanie ruchu sieciowego

---

## Aplikacje obsługujące proxy (HTTP/HTTPS)

### Burp Suite

1. Ustaw proxy: `127.0.0.1:8080`
2. Skonfiguruj proxy aplikacji lub systemu, by wskazywał na Burp
3. Test walidacji certyfikatu TLS: uruchom Burp **bez** zainstalowanego CA w systemie → jeśli aplikacja nadal się łączy = brak walidacji certyfikatu

### OWASP ZAP

Taka sama konfiguracja jak Burp, darmowa alternatywa.

---

## Aplikacje bez obsługi proxy (niestandardowe protokoły)

### Echo Mirage

- Hookowanie WinSock API — przechwytuje ruch na poziomie gniazd sieciowych
- Działa dla dowolnej aplikacji TCP/UDP niezależnie od protokołu
- Reguły wstrzykiwania do modyfikacji ruchu w locie

### Proxifier / ProxyCap

- Wymusza kierowanie ruchu dowolnej aplikacji przez proxy SOCKS/HTTP
- Użyj z Burp w trybie invisible proxy

### Wireshark

```
# Przechwytywanie ruchu Oracle TNS
Capture filter: tcp port 1521

# Filtr wyświetlania — pakiety danych TNS
tcp.port == 1521 && data

# Filtr wyświetlania — cały ruch TNS
tcp.port == 1521
```

Szukaj: poświadczenia w plaintexcie w fazie uwierzytelniania TNS, nieszyfrowane zapytania SQL.

---

## Co sprawdzić w przechwyconym ruchu

**Oracle TNS bez szyfrowania:**
- Poświadczenia widoczne w fazie autoryzacji
- Zapytania SQL i wyniki w plaintexcie

**HTTP zamiast HTTPS:**
- Komunikacja z wewnętrznymi API po HTTP
- Hasła w ciele żądania POST lub w query stringu

**Wyłączona walidacja certyfikatu w .NET:**
```csharp
// BAD — całkowite wyłączenie walidacji certyfikatu
ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
```

```csharp
// BAD — HttpClientHandler bez walidacji
var handler = new HttpClientHandler();
handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;
```

**Wrażliwe dane w URL:**
```
# BAD — hasło i token w parametrach URL
https://api.internal/login?token=abc123&password=xyz789
```

**Self-signed cert akceptowany bez ostrzeżenia** — aplikacja nie informuje użytkownika o niezaufanym certyfikacie.
