# Laboratoria, podatne aplikacje i zasoby referencyjne

---

## Podatne aplikacje do ćwiczeń

### DVTA — Damn Vulnerable Thick Client App (C# .NET)

- Repozytorium (fork z dodatkowymi zabezpieczeniami — zalecany): https://github.com/srini0x00/dvta
- Oryginał: https://github.com/secvulture/dvta
- Setup: wymaga SQL Server + serwer FTP (instrukcja wideo w README repozytorium)

**Zawarte podatności:**
- Niebezpieczne lokalne przechowywanie danych
- Niebezpieczne logowanie (wrażliwe dane w logach)
- Słaba kryptografia (AES z zakodowanym kluczem)
- Brak obfuskacji kodu
- Ujawniona logika deszyfrowania
- SQL injection
- CSV injection
- Wrażliwe dane w pamięci procesu
- DLL hijacking
- Dane w plaintexcie w ruchu sieciowym
- Obejście zabezpieczeń po stronie klienta przez reverse engineering

---

## Standardy OWASP — bezpośrednie linki

| Standard | URL | Uwagi |
|----------|-----|-------|
| Desktop App Security Top 10 | https://owasp.org/www-project-desktop-app-security-top-10/ | Główna referencja dla aplikacji desktopowych |
| Desktop App Top 10 GitHub | https://github.com/OWASP/www-project-desktop-app-security-top-10 | Zawiera ranking ważności oparty na CVE |
| TASVS (Thick Client ASVS) | https://owasp.org/www-project-thick-client-application-security-verification-standard/ | Najnowsza v1.8, wrzesień 2024 |
| TASVS GitHub | https://github.com/OWASP/www-project-thick-client-application-security-verification-standard | Pobierz checklist TASVS_v1.8.xlsx |
| DASVS (Desktop App SVS) | https://afine.com/desktop-application-security-standard-introducing-dasvs | Nowszy standard, 2025/2026 |

---

## Linki do repozytoriów narzędzi

| Narzędzie | Repozytorium / Link | Przeznaczenie |
|-----------|----------------------|---------------|
| dnSpyEx | https://github.com/dnSpyEx/dnSpy | Dekompilator + debugger .NET |
| ILSpy | https://github.com/icsharpcode/ILSpy | Dekompilator .NET, wsparcie CLI |
| de4dot | https://github.com/de4dot/de4dot | Deobfuskator .NET |
| ODAT | https://github.com/quentinhardy/odat | Narzędzie do pentestingu Oracle |
| DLLSpy | https://github.com/cyberark/DLLSpy | Wykrywanie DLL hijacking |
| Database-Security-Audit | https://github.com/Jean-Francois-C/Database-Security-Audit | Skrypty i materiały do pentestingu Oracle |
| Oracle-Pentesting-Reference | https://github.com/hexrom/Oracle-Pentesting-Reference | Ściągawka Oracle (10g/11g) |
| RaKKeN Thick Client Index | https://github.com/RakeshKengale/RaKKeN/blob/master/Index/Thick_Client.md | Agregator narzędzi, laboratoriów, writeupów |
| buger-shack methodology | https://github.com/buger-shack/scriptkiddie/blob/main/thick-client-hacking/thick-client-pentesting-methodology.md | Metodologia + DLL hijacking |

---

## Artykuły referencyjne

- CyberArk — metodologia thick client: https://www.cyberark.com/resources/threat-research-blog/thick-client-penetration-testing-methodology
- NetSPI — seria thick client (części 1–6): https://www.netspi.com/blog/technical-blog/thick-application-penetration-testing/
- Kompleksowy checklist: https://hetmehta.com/resources/thick-client-checklist/
- afine.com — przewodnik po pentestingu thick client 2025: https://afine.com/how-to-perform-thick-client-penetration-testing

---

## Sysinternals Suite (wszystkie narzędzia)

Download: https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite

**Kluczowe narzędzia do tego typu zleceń:**

| Narzędzie | Zastosowanie |
|-----------|--------------|
| Process Monitor | Monitoring operacji na plikach, rejestrze, sieci w czasie rzeczywistym |
| Process Explorer | Zaawansowany menedżer zadań, inspekcja procesów i DLL |
| Regshot | Porównanie stanów rejestru przed/po operacji |
| TCPView | Monitoring aktywnych połączeń sieciowych |
| AccessChk | Audyt uprawnień do plików, katalogów, rejestru |
| Sigcheck | Weryfikacja podpisów cyfrowych binarek |
| strings.exe | Ekstrakcja stringów z plików binarnych i zrzutów pamięci |
| Autoruns | Identyfikacja programów uruchamianych automatycznie |
