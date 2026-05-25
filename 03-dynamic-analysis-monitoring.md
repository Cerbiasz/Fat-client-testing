# Analiza dynamiczna i monitoring systemu

---

## Monitoring procesów — system plików i rejestr

### Process Monitor (ProcMon) — Sysinternals

Konfiguracja filtrów dla docelowej aplikacji:

```
Filter → Process Name → is → app.exe → Add
Filter → Operation → contains → WriteFile → Add    (zapis plików)
Filter → Path → contains → password → Add           (ścieżki z "password")
```

**Co szukać:**
- Aplikacja zapisuje poświadczenia do przewidywalnej ścieżki tymczasowej
- Aplikacja ładuje DLL z katalogu, w którym użytkownik ma zapis (wektor DLL hijacking)
- Aplikacja przechowuje dane w `HKCU\Software\[NazwaAplikacji]` w plaintexcie
- Plik tworzony z nadmiernymi uprawnieniami (`Everyone: Full Control`)

### Regshot

1. Wykonaj snapshot 1 **przed** uruchomieniem aplikacji
2. Uruchom aplikację, zaloguj się, wykonaj typowe operacje
3. Wykonaj snapshot 2
4. Porównaj → szukaj nowych kluczy HKCU z wrażliwymi wartościami

---

## Analiza pamięci

### Process Hacker 2 / System Informer

- Prawym na proces → Properties → Memory → Strings
- Filtruj stringi: minimalna długość 8 znaków, szukaj `password`, `oracle`, `Data Source`
- Zrzut: prawym na proces → Create Dump File → otwórz w HxD lub `strings`
- **Po wylogowaniu**: ponowny zrzut → sprawdź, czy poświadczenia nadal są w pamięci (wskaźnik DA3 + DA10)

```powershell
# Wyciąganie stringów z pamięci procesu (wymaga strings.exe z Sysinternals)
.\strings.exe -accepteula -n 8 \\.\pid\<PID> | findstr /i "password token secret"
```

---

## DLL Hijacking

### Wykrywanie za pomocą ProcMon

Filtr:
```
Operation:  CreateFile
Path:       ends with .dll
Result:     NAME NOT FOUND
```

Każdy wynik `NAME NOT FOUND` dla DLL w ścieżce, gdzie użytkownik ma uprawnienia zapisu = potencjalny hijack.

### Weryfikacja uprawnień katalogu

```powershell
icacls "C:\ścieżka\do\katalogu"
```

### Tworzenie PoC DLL

```bash
# Generowanie DLL uruchamiającego kalkulator (wystarczające jako PoC)
msfvenom -p windows/x64/exec CMD=calc.exe -f dll -o hijack.dll
```

Umieść DLL w katalogu, który aplikacja przeszukuje jako pierwszy.

### DLLSpy (CyberArk)

Repozytorium: https://github.com/cyberark/DLLSpy

Automatyzuje wykrywanie podatności DLL hijacking w działających procesach.

---

## Testowanie GUI

- Testuj pola wejściowe pod kątem SQL injection: `' OR 1=1 --`, `admin'--`
- Sprawdź komunikaty błędów: czy ujawniają kody Oracle `ORA-`, stack trace, connection stringi?
- Sprawdź, czy pola akceptują więcej danych niż oczekiwano (powierzchnia ataku buffer overflow)
- Testuj nawigację klawiaturą (Tab) w poszukiwaniu ukrytych/wyłączonych pól
- W dnSpy: patchuj `button.Enabled = false` → `button.Enabled = true` aby odblokować ukryte elementy UI

### CSV Injection w polach eksportu

```
=cmd|' /C calc'!A0
```

Jeśli aplikacja eksportuje dane do CSV/Excel bez sanityzacji — możliwe zdalne wykonanie kodu po otwarciu pliku.

### Pola wrażliwe

- Czy pole hasła pozwala na kopiowanie (Ctrl+C)? Nie powinno.
- Czy po wklejeniu hasło jest widoczne w schowku? Sprawdź zawartość schowka po wylogowaniu.
