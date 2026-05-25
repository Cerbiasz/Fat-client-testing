# Checklist — analiza dynamiczna

## Przygotowanie przed testem

- [ ] Snapshot maszyny wirtualnej przed testami
- [ ] Regshot — wykonaj snapshot 1 przed uruchomieniem aplikacji
- [ ] ProcMon uruchomiony z aktywnym filtrem na nazwę aplikacji
- [ ] Wireshark przechwytuje na odpowiednim interfejsie

## Uruchomienie aplikacji i rekonesans

- [ ] Zapisz wszystkie procesy uruchomione przez aplikację (Process Explorer)
- [ ] Zapisz wszystkie otwarte połączenia sieciowe (TCPView)
- [ ] Zapisz wszystkie utworzone/zmodyfikowane pliki (ProcMon)
- [ ] Zapisz wszystkie zmiany w rejestrze (Regshot snapshot 2 po zalogowaniu)
- [ ] Zanotuj DLL ładowane z katalogu, w którym użytkownik ma zapis (ProcMon: `NAME NOT FOUND` + katalog z zapisem)

## Testowanie uwierzytelniania

- [ ] Testuj domyślne/typowe poświadczenia (`admin/admin`, `admin/admin123`, `oracle/oracle`)
- [ ] Testuj SQL injection w polach logowania: `' OR '1'='1`, `admin'--`
- [ ] Testuj obejście uwierzytelniania przez modyfikację parametrów (jeśli obecny komponent webowy)
- [ ] Patchuj sprawdzenie uwierzytelniania w dnSpy — ustaw wynik weryfikacji poświadczeń na zawsze `true`
- [ ] Sprawdź czy token sesji jest przechowywany w rejestrze lub pliku lokalnym po zalogowaniu

## DLL Hijacking

- [ ] Filtr ProcMon: `Operation=CreateFile`, `Result=NAME NOT FOUND`, `Path ends with .dll`
- [ ] Zidentyfikuj DLL szukane w ścieżkach, w których użytkownik ma zapis
- [ ] Zweryfikuj zapisy do katalogu: `icacls <ścieżka>`
- [ ] Utwórz proof-of-concept DLL (uruchomienie `calc.exe` wystarczy jako PoC)
- [ ] Potwierdź załadowanie DLL po restarcie aplikacji

## Analiza pamięci

- [ ] W trakcie sesji: zrzuć pamięć procesu (Process Hacker → Create Dump)
- [ ] Szukaj w zrzucie: `password`, `token`, `Data Source`, `OracleConnection`
- [ ] Po wylogowaniu: ponowny zrzut → sprawdź czy poświadczenia nadal są w pamięci
- [ ] Użyj `strings.exe` na zrzucie: `strings.exe -n 8 dump.dmp | findstr /i "password oracle"`

## Ruch sieciowy

- [ ] Przechwyć ruch podczas logowania (Wireshark, filtr: `tcp.port==1521`)
- [ ] Czy ruch Oracle TNS jest szyfrowany? (sprawdź plaintextowe poświadczenia w przechwyceniu)
- [ ] Czy HTTPS jest używany dla wszystkich wywołań API?
- [ ] Walidacja certyfikatu TLS: skonfiguruj Burp z self-signed cert → czy aplikacja odrzuca?
- [ ] Jakiekolwiek plaintextowe poświadczenia w ciele POST HTTP lub parametrach URL?

## GUI / testowanie danych wejściowych

- [ ] SQL injection we wszystkich polach wejściowych (składnia Oracle: `' OR 1=1 --`, `' UNION SELECT ...`)
- [ ] Komunikaty błędów — czy ujawniają kody `ORA-`, stack trace, wewnętrzne ścieżki?
- [ ] Ukryte/wyłączone przyciski — patchuj w dnSpy aby odblokować
- [ ] CSV injection w polach eksportu: `=cmd|' /C calc'!A0`
- [ ] Sprawdź kopiowanie wrażliwych pól (hasła nie powinny być kopiowalne)

## System plików w trakcie działania

- [ ] Aplikacja tworzy pliki tymczasowe z wrażliwymi danymi?
- [ ] Pliki tymczasowe mają poprawny ACL (nie world-readable)?
- [ ] Aplikacja zapisuje do pliku logów wrażliwą zawartość w trakcie działania?
- [ ] Aktualizacje pobierane do katalogu z zapisem użytkownika bez weryfikacji podpisu?

## Po zakończeniu sesji

- [ ] Zweryfikuj, że aplikacja czyści wrażliwe dane z pamięci po wylogowaniu
- [ ] Zweryfikuj, że pliki logów nie rozrastają się bez ograniczeń z wrażliwą zawartością
- [ ] Zweryfikuj, że po zakończeniu sesji nie zostały poświadczenia w plikach tymczasowych
