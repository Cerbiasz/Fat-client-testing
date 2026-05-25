# Checklist — analiza statyczna

## Identyfikacja binarki

- [ ] Zidentyfikuj runtime: .NET, natywny, Java, Electron
      Narzędzie: CFF Explorer, DIE, `file`
- [ ] Zanotuj wersję .NET Framework (sprawdź czy nie jest EOL)
- [ ] Sprawdź czy binarka jest zaobfuskowana (DIE, próba otwarcia w dnSpy — jeśli nieczytelna)

## Ochrona binarna

- [ ] ASLR włączony (DynamicBase)
      Narzędzie: PESecurity, BinSkim, CFF Explorer → Optional Header
- [ ] DEP/NX włączony (NXCompat)
- [ ] SafeSEH włączony (dla 32-bit)
- [ ] Control Flow Guard (CFG) włączony
- [ ] Binarka podpisana cyfrowo (Authenticode)
      Narzędzie: `sigcheck.exe -a app.exe`
- [ ] Strong name signing na assembly .NET
      Narzędzie: `sn.exe -v app.dll`

## Dekompilacja — .NET

- [ ] Dekompiluj EXE i kluczowe DLL za pomocą dnSpyEx lub ILSpy
- [ ] Deobfuskuj jeśli potrzeba: `de4dot.exe app.exe`
- [ ] Szukaj zakodowanych poświadczeń (stringi username/password)
- [ ] Szukaj zakodowanych connection stringów (`OracleConnection`, `Data Source=`)
- [ ] Szukaj zakodowanych kluczy kryptograficznych / IV (`byte[] key = {...}`)
- [ ] Szukaj flag debug (`isDebug`, `buildType`, sprawdzenia zmiennej `DEBUG`)
- [ ] Szukaj wyłączonych elementów UI do ponownego włączenia (`button.Enabled = false`)
- [ ] Sprawdź logikę uwierzytelniania — czy istnieje backdoor / warunek obejścia?
- [ ] Sprawdź logikę licencji/trialu — czy wygaśnięcie jest przechowywane w pliku lokalnym lub rejestrze?
- [ ] Sprawdź mechanizm aktualizacji — czy URL aktualizacji jest zakodowany? Czy pakiet aktualizacji jest weryfikowany?

## Pliki konfiguracyjne

- [ ] `App.config` / `appsettings.json` obecny i czytelny?
- [ ] Connection stringi w plaintexcie lub słabo zaszyfrowane?
- [ ] Klucze API, tokeny w plikach konfiguracyjnych?
- [ ] ACL pliku: czy nieuprzywilejowany użytkownik może odczytać plik konfiguracyjny?
- [ ] `tnsnames.ora` / `sqlnet.ora` obecne i czytelne?
- [ ] Czy `SQLNET.ENCRYPTION_CLIENT = REQUIRED`?

## Rejestr

- [ ] `HKCU\Software\[NazwaAplikacji]` — wrażliwe dane przechowywane?
- [ ] `HKLM\Software\[NazwaAplikacji]` — poświadczenia, tokeny, klucze szyfrowania?

## Stringi w binarce

- [ ] `strings app.exe | grep -iE "password|secret|token|api.key|Data Source"`
- [ ] Ujawnione wewnętrzne adresy IP / nazwy hostów?
- [ ] Ujawnione wewnętrzne ścieżki endpointów API?

## Pliki logów

- [ ] Znaleziono lokalizację pliku logów?
- [ ] Logi zawierają błędy `ORA-` z pełnym zapytaniem SQL?
- [ ] Logi zawierają hasła lub tokeny?
- [ ] Logi zawierają stack trace z wewnętrznymi ścieżkami?
