# OWASP Desktop App Security Top 10 (2021)

Klasyfikacja zagrożeń dla aplikacji desktopowych z uwzględnieniem specyfiki .NET + Oracle.

---

## DA1 — Injections (Wstrzyknięcia)

Wstrzyknięcia SQL, LDAP, XML, poleceń systemu operacyjnego.

**Co sprawdzić / wektory ataku**
- Wstrzyknięcia Oracle SQL przez ODP.NET (`OracleCommand` bez parametryzacji)
- Konkatenacja stringów w zapytaniach: `"SELECT * FROM users WHERE id = '" + input + "'"`
- Wstrzyknięcia OS Command przez `Process.Start()` z danymi użytkownika
- Wstrzyknięcia LDAP w modułach uwierzytelniania Active Directory
- Wstrzyknięcia XML/XPath w parsowaniu dokumentów

**Przykład podatności**
```csharp
// BAD — konkatenacja zamiast parametrów
string query = "SELECT * FROM users WHERE username = '" + txtUser.Text + "'";
OracleCommand cmd = new OracleCommand(query, conn);
```

**Narzędzia**
- dnSpyEx — analiza kodu pod kątem budowy zapytań
- Burp Suite / Echo Mirage — modyfikacja danych wejściowych w locie
- ODAT — testowanie wstrzyknięć Oracle bezpośrednio

---

## DA2 — Broken Authentication & Session Management (Błędy uwierzytelniania i sesji)

Obejście uwierzytelniania, zakodowane poświadczenia, słabe tokeny sesji.

**Co sprawdzić / wektory ataku**
- Hardkodowane dane logowania w kodzie źródłowym (`if (user == "admin" && pass == "secret")`)
- Token sesji przechowywany w rejestrze lub pliku lokalnym bez ochrony
- Brak blokady konta po wielokrotnych nieudanych próbach logowania
- Sesja nie wygasa po wylogowaniu (token nadal ważny)
- Uwierzytelnianie po stronie klienta — weryfikacja w kodzie .NET, łatwa do patchowania

**Przykład podatności**
- Po dekompilacji w dnSpy: metoda `ValidateLogin()` zwraca `true` na podstawie porównania ze stałą wartością
- Token sesji zapisany jako `HKCU\Software\AppName\SessionToken` w plaintexcie

**Narzędzia**
- dnSpyEx — analiza logiki uwierzytelniania, patchowanie warunków
- Regshot — śledzenie zmian w rejestrze po zalogowaniu
- Process Hacker — szukanie tokenów w pamięci procesu

---

## DA3 — Sensitive Data Exposure (Ujawnienie wrażliwych danych)

Zakodowane sekrety w DLL/EXE, konfiguracja w plaintexcie, hasła w logach, AES z hardkodowanym kluczem/IV.

**Co sprawdzić / wektory ataku**
- Hardkodowane klucze szyfrowania i wektory IV w kodzie .NET
- Connection stringi z hasłami w `App.config` / `appsettings.json`
- Hasła i tokeny w plikach logów
- Dane wrażliwe pozostające w pamięci procesu po wylogowaniu
- Pliki tymczasowe z wrażliwą zawartością i zbyt szerokim ACL

**Przykład podatności**
```csharp
// BAD — klucz i IV zaszyty w kodzie
byte[] key = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
byte[] iv  = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
```

**Narzędzia**
- dnSpyEx / ILSpy — szukanie stałych kryptograficznych
- `strings` / `findstr` — wyciąganie stringów z binarek
- Process Hacker — analiza pamięci procesu
- ProcMon — monitorowanie zapisu plików tymczasowych

---

## DA4 — XXE (XML External Entity)

Przetwarzanie XML z zewnętrznymi encjami w parserach .NET.

**Co sprawdzić / wektory ataku**
- `XmlDocument` z `XmlResolver` ustawionym na wartość inną niż `null`
- `XmlReader` bez `DtdProcessing = DtdProcessing.Prohibit`
- `XmlTextReader` z domyślnymi ustawieniami (DTD włączone)
- Pliki XML importowane przez użytkownika bez walidacji

**Przykład podatności**
```csharp
// BAD — XmlDocument z domyślnym resolverem
XmlDocument doc = new XmlDocument();
doc.Load(userSuppliedXmlPath);
// Atak: plik XML zawiera <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
```

**Narzędzia**
- dnSpyEx — szukanie instancji `XmlDocument`, `XmlReader`, `XmlTextReader`
- Burp Suite — podmiana plików XML w żądaniach

---

## DA5 — Security Misconfiguration (Błędna konfiguracja bezpieczeństwa)

Pliki konfiguracyjne dostępne dla wszystkich, buildy debug w produkcji, zbędne usługi, słabe ACL na katalogach aplikacji.

**Co sprawdzić / wektory ataku**
- `App.config` z hasłami czytelny przez zwykłego użytkownika
- Build typu Debug wdrożony na produkcję (`#if DEBUG` aktywne)
- Katalog instalacji aplikacji z uprawnieniami zapisu dla `Users`/`Everyone`
- Zbędne porty/usługi nasłuchujące (np. debug endpoint)
- Oracle listener bez ograniczenia dostępu

**Przykład podatności**
```powershell
# BAD — wszyscy mogą czytać plik z hasłami
icacls "C:\Program Files\App\App.config"
# Wynik: Everyone:(R)
```

**Narzędzia**
- `icacls` / `Get-Acl` — sprawdzanie uprawnień plików
- AccessChk (Sysinternals) — audyt uprawnień katalogów
- ProcMon — wykrywanie ładowania zasobów z niezabezpieczonych ścieżek

---

## DA6 — Insecure Communication (Nieszyfrowana komunikacja)

TNS Oracle w plaintexcie, brak walidacji certyfikatów TLS w .NET `HttpClient`.

**Co sprawdzić / wektory ataku**
- Ruch Oracle TNS bez szyfrowania (`SQLNET.ENCRYPTION_CLIENT` brak lub `REQUESTED`)
- `HttpClient` z wyłączoną walidacją certyfikatów (`ServerCertificateValidationCallback` zwracający `true`)
- Komunikacja HTTP zamiast HTTPS do wewnętrznych API
- Hasła przesyłane w URL (query string)

**Przykład podatności**
```csharp
// BAD — wyłączona walidacja certyfikatu
ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
```

**Narzędzia**
- Wireshark — przechwytywanie TNS (`tcp.port == 1521`)
- Burp Suite — test walidacji certyfikatów (self-signed cert)
- Echo Mirage — przechwytywanie ruchu na poziomie WinSock

---

## DA7 — Poor Code Quality (Niska jakość kodu)

Brak ASLR/DEP na EXE/DLL, przepełnienia buforów, flagi debug, brak obfuskacji.

**Co sprawdzić / wektory ataku**
- Brak flag ASLR (DynamicBase) i DEP (NXCompat) w nagłówkach PE
- Brak obfuskacji — dekompilacja daje czytelny kod źródłowy
- Flagi debugowe aktywne w wersji produkcyjnej
- Nieobsłużone wyjątki ujawniające informacje wewnętrzne (ścieżki, connection stringi)

**Przykład podatności**
- PESecurity: `ASLR: False, DEP: False, CFG: False`
- Dekompilacja w dnSpy daje pełny, czytelny kod C# bez obfuskacji

**Narzędzia**
- PESecurity — sprawdzanie flag ochrony binarek
- BinSkim — automatyczny audyt binarek
- CFF Explorer — ręczna inspekcja nagłówków PE
- DIE (Detect It Easy) — wykrywanie obfuskatorów

---

## DA8 — Code Tampering (Modyfikacja kodu)

Brak podpisywania assembly, brak kontroli integralności, łatwe patchowanie przez dnSpy.

**Co sprawdzić / wektory ataku**
- Brak Authenticode signature na EXE/DLL
- Brak strong name signing na assembly .NET
- Aplikacja nie weryfikuje integralności własnych plików przy starcie
- Łatwość patchowania logiki biznesowej (zmiana `if (licensed)` na `if (true)`)
- Podmiana DLL w katalogu aplikacji bez wykrycia

**Przykład podatności**
- `sigcheck.exe app.exe` → `Signed: Unsigned`
- W dnSpy: edycja instrukcji IL, zmiana `brfalse` na `brtrue` — pominięcie sprawdzenia licencji

**Narzędzia**
- sigcheck (Sysinternals) — weryfikacja podpisu cyfrowego
- sn.exe — sprawdzanie strong name (`sn.exe -v app.dll`)
- dnSpyEx — patchowanie IL i debugowanie
- CFF Explorer — inspekcja charakterystyk DLL

---

## DA9 — Known Vulnerabilities (Znane podatności)

Przestarzały .NET Framework, stary ODP.NET, niezałatany klient Oracle.

**Co sprawdzić / wektory ataku**
- Wersja .NET Framework — czy jest wspierana (EOL)?
- Wersja ODP.NET / Oracle Client — czy są znane CVE?
- Użycie bibliotek NuGet z podatnościami
- Przestarzałe komponenty trzecie (log4net, Newtonsoft.Json — starsze wersje)

**Przykład podatności**
- .NET Framework 4.5.2 — EOL od 2022, brak łatek bezpieczeństwa
- Oracle Client 11g — znane CVE dotyczące TNS Poison attack

**Narzędzia**
- CFF Explorer — sprawdzenie wersji .NET runtime
- `dotnet list package --vulnerable` (projekty .NET Core/5+)
- NVD / CVE Search — weryfikacja wersji komponentów

---

## DA10 — Insufficient Logging & Monitoring (Niewystarczające logowanie i monitoring)

Brak śladu audytowego, wrażliwe dane w logach, brak alertów.

**Co sprawdzić / wektory ataku**
- Brak logowania prób nieudanego logowania
- Brak logowania operacji uprzywilejowanych
- Hasła i tokeny logowane w plikach dziennika
- Brak alertów na anomalne zachowania (wielokrotne błędy logowania)
- Oracle: `audit_trail = NONE`

**Przykład podatności**
```
# BAD — hasło w logu aplikacji
2024-01-15 10:23:45 [INFO] User login attempt: user=admin, password=P@ssw0rd123
# BAD — pełne zapytanie SQL w logu z danymi użytkownika
2024-01-15 10:24:01 [ERROR] ORA-00942: SELECT * FROM users WHERE ssn='123-45-6789'
```

**Narzędzia**
- `Select-String` / `findstr` — przeszukiwanie logów pod kątem wrażliwych danych
- Event Viewer — analiza logów Windows
- SQLPlus — `SELECT VALUE FROM V$PARAMETER WHERE NAME = 'audit_trail'`
