# Analiza binarna .NET (EXE / DLL)

---

## Identyfikacja

Potwierdzenie, że binarka jest aplikacją .NET:

```bash
file app.exe
# Wynik zawierający "PE32 executable" + "Mono/.Net assembly" = .NET
```

```bash
strings app.exe | grep -iE "password|secret|token|api.key|connectionstring|Data Source"
```

```powershell
findstr /s /i "password api_key secret token connectionstring" C:\path\to\app\*.*
```

- **CFF Explorer** → sprawdź obecność "CLI Header" w Optional Header → Data Directories
- **DIE (Detect It Easy)** → automatycznie wykrywa runtime (.NET, wersja Framework, obfuskator)

---

## Dekompilacja

### dnSpyEx

Repozytorium: https://github.com/dnSpyEx/dnSpy

- Otwieranie: przeciągnij EXE/DLL do okna dnSpy
- Nawigacja: panel Assemblies → przestrzeń nazw → klasa → metoda
- Breakpoint: `F9`, start debugowania: `F5` (Debug → Start Debugging)
- Edycja IL: prawym → Edit IL Instructions
- Zastosowanie: patchowanie sprawdzeń autoryzacji, ekstrakcja zakodowanych kluczy, debugowanie connection stringów na żywo

### ILSpy

Repozytorium: https://github.com/icsharpcode/ILSpy

```bash
# Dekompilacja do kodu C# (CLI)
ilspycmd app.exe -o ./decompiled/
```

- Plugin: Reflexil (edytor assembly)

### dotPeek (JetBrains)

- Darmowy dekompilator, dobry dla zaobfuskowanego kodu
- Wbudowany Process Explorer do analizy działających procesów

---

## Deobfuskacja

### de4dot

Repozytorium: https://github.com/de4dot/de4dot

```bash
# Automatyczna detekcja obfuskatora i usunięcie obfuskacji
de4dot.exe app.exe
```

- Wynik: `app-cleaned.exe` — następnie otwórz w dnSpy
- Wspierane obfuskatory: ConfuserEx, Dotfuscator, SmartAssembly, Eazfuscator i inne

---

## Co szukać w zdekompilowanym kodzie

**Zakodowane poświadczenia** — szukaj literałów stringowych pasujących do wzorców password/user:
```csharp
// BAD
private const string DbUser = "app_admin";
private const string DbPass = "Pr0d_S3cret!";
```

**AES z zakodowanym kluczem/IV:**
```csharp
// BAD — klucz i IV zaszyty na stałe
byte[] key = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
byte[] iv  = new byte[] { 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34,
                           0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34 };
```

**Budowa connection stringów** — szukaj:
- `OracleConnection`, `OleDbConnection`, `SqlConnection`
- `new OracleConnectionStringBuilder()`

**Logika obejścia uwierzytelniania:**
```csharp
// BAD — backdoor
if (username == "admin" && password == "backdoor") return true;
```

**Flagi debug:**
```csharp
// BAD — flaga debug w produkcji
#if DEBUG
    ShowDebugPanel();
#endif
bool isDebugMode = Environment.GetEnvironmentVariable("DEBUG") == "1";
```

**Obejście licencji/trialu** — porównanie dat przechowywanych w pliku lokalnym lub rejestrze.

---

## Sprawdzanie ochrony binarek

### PESecurity (PowerShell)

```powershell
# Import modułu
Import-Module .\PESecurity.psm1

# Sprawdzenie pojedynczego pliku
Get-PESecurityProperties -File C:\app\app.exe

# Sprawdzenie całego katalogu
Get-PESecurityProperties -Directory C:\app\ | Format-Table
```

Flagi do weryfikacji:
| Flaga | Opis | Oczekiwana wartość |
|-------|------|--------------------|
| ASLR (DynamicBase) | Losowy adres bazowy | `True` |
| DEP (NXCompat) | Zapobieganie wykonywaniu danych | `True` |
| SafeSEH | Bezpieczna obsługa wyjątków (32-bit) | `True` |
| ControlFlowGuard | Ochrona przepływu sterowania | `True` |
| Authenticode | Podpis cyfrowy | `True` (Signed) |

### BinSkim

```bash
binskim analyze app.exe --output report.sarif
```

### Sigcheck (Sysinternals)

```powershell
# Pojedynczy plik
sigcheck.exe -a app.exe

# Cały katalog
sigcheck.exe -nobanner -accepteula -a C:\app\*.exe
```

### CFF Explorer

- Optional Header → DLL Characteristics:
  - `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` = ASLR
  - `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` = DEP

---

## Red flags

- Binarka .NET bez obfuskacji — pełny czytelny kod po dekompilacji
- `ASLR: False` lub `DEP: False` w wynikach PESecurity
- `Signed: Unsigned` w sigcheck — brak podpisu cyfrowego
- Hardkodowane `byte[] key` / `byte[] iv` w klasach kryptograficznych
- Connection string z hasłem w plaintexcie budowany przez konkatenację
- `#if DEBUG` bloki aktywne w wersji produkcyjnej
- Metoda `ValidateLogin()` porównująca z zakodowanymi stałymi
- Brak strong name signing na assembly (`sn.exe -v` zwraca błąd)
- Obfuskator wykryty przez DIE, ale po de4dot kod w pełni czytelny (słaba obfuskacja)
