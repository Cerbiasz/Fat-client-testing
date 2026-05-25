# Pliki konfiguracyjne, rejestr i magazyn lokalny

---

## App.config / Web.config (.NET Framework)

Lokalizacja: ten sam katalog co plik EXE.

**Co szukać:**
```xml
<!-- BAD — hasło Oracle w plaintexcie -->
<connectionStrings>
  <add name="OracleConn"
       connectionString="Data Source=PROD;User Id=app_user;Password=S3cr3t!;" />
</connectionStrings>

<!-- BAD — klucz API zakodowany w appSettings -->
<appSettings>
  <add key="ApiKey" value="sk-prod-abc123..." />
</appSettings>
```

**Sprawdzanie uprawnień:**
```powershell
Get-Acl "C:\Program Files\App\App.config" | Format-List

# BAD — Everyone lub Users mają dostęp do odczytu pliku z poświadczeniami
icacls "C:\Program Files\App\App.config"
```

---

## appsettings.json (.NET Core / .NET 5+)

```powershell
# Rekurencyjne wyszukiwanie connection stringów
Get-ChildItem -Path C:\app -Recurse -Filter "appsettings*.json" |
  Select-String -Pattern "password|secret|connectionString" -CaseSensitive:$false
```

---

## Pliki konfiguracyjne Oracle

### Typowe lokalizacje

- `%ORACLE_HOME%\network\admin\tnsnames.ora`
- `C:\Oracle\product\<wersja>\client\network\admin\tnsnames.ora`

### tnsnames.ora — co sprawdzić

```
# Zanotuj SID, host, port — użyj w ODAT
PROD =
  (DESCRIPTION =
    (ADDRESS = (PROTOCOL = TCP)(HOST = db.internal.corp)(PORT = 1521))
    (CONNECT_DATA = (SERVICE_NAME = PROD))
  )
```

### sqlnet.ora — ustawienia szyfrowania

```
# GOOD — szyfrowanie wymuszone
SQLNET.ENCRYPTION_CLIENT = REQUIRED
SQLNET.ENCRYPTION_TYPES_CLIENT = (AES256)

# BAD — szyfrowanie niewymuszone
SQLNET.ENCRYPTION_CLIENT = REQUESTED
# lub brak wpisu — szyfrowanie domyślnie wyłączone
```

---

## Rejestr Windows

### Ręczne sprawdzenie

```powershell
reg query HKCU\Software\[NazwaAplikacji] /s
reg query HKLM\Software\[NazwaAplikacji] /s
```

### PowerShell

```powershell
Get-ChildItem -Path "HKCU:\Software\[NazwaAplikacji]" -Recurse |
  Get-ItemProperty |
  Select-String -Pattern "password|token|secret"
```

**Oznaki niebezpiecznego przechowywania:**
- Hasło jako wartość `REG_SZ` w plaintexcie
- Wartość zaszyfrowana, ale klucz przechowywany obok (lub w DLL — sprawdź w dnSpy)

---

## Pliki logów

### Typowe lokalizacje

```
C:\ProgramData\[NazwaAplikacji]\logs\
C:\Users\[Użytkownik]\AppData\Local\[NazwaAplikacji]\logs\
C:\Program Files\[NazwaAplikacji]\logs\
Event Viewer: Windows Logs → Application
```

### Wyszukiwanie wrażliwych danych

```powershell
Select-String -Path "C:\ProgramData\AppName\logs\*.log" `
  -Pattern "password|token|ORA-|exception|stack" -CaseSensitive:$false
```

---

## Red flags

- Connection string z hasłem w plaintexcie w `App.config` / `appsettings.json`
- `icacls` pokazuje `Everyone:(R)` lub `Users:(R)` na pliku konfiguracyjnym z poświadczeniami
- `SQLNET.ENCRYPTION_CLIENT = REQUESTED` zamiast `REQUIRED` (lub brak wpisu)
- Hasło w rejestrze jako `REG_SZ` bez szyfrowania
- Klucz szyfrowania przechowywany w tym samym katalogu co zaszyfrowane dane
- Kody `ORA-` z pełnym zapytaniem SQL w pliku logów
- Stack trace z wewnętrznymi ścieżkami i nazwami klas w logach
- Hasła lub tokeny uwierzytelniania widoczne w logach debug
- Plik tnsnames.ora czytelny przez nieuprzywilejowanego użytkownika zawierający adresy produkcyjnych baz
