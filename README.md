# Repozytorium wiedzy — Pentesting aplikacji desktopowych (.NET + Oracle)

Kompendium technik, narzędzi i checklist do testów bezpieczeństwa grubych klientów (thick client) opartych na platformie .NET z bazą danych Oracle.

## Spis treści

| # | Plik | Opis |
|---|------|------|
| 1 | [OWASP Desktop Top 10](01-owasp-desktop-top10.md) | Klasyfikacja DA1–DA10 z wektorami ataku dla .NET + Oracle |
| 2 | [Analiza binarna .NET](02-dotnet-binary-analysis.md) | Dekompilacja, deobfuskacja, ochrona binarek |
| 3 | [Analiza dynamiczna](03-dynamic-analysis-monitoring.md) | Monitoring procesów, pamięci, DLL hijacking, GUI |
| 4 | [Pliki konfiguracyjne i rejestr](04-config-files-registry.md) | App.config, tnsnames.ora, rejestr Windows, logi |
| 5 | [Baza danych Oracle](05-oracle-database.md) | Rekonesans, ODAT, SQLPlus, Metasploit, DBSAT |
| 6 | [Ruch sieciowy](06-network-traffic.md) | Przechwytywanie ruchu HTTP, TNS, niestandardowych protokołów |
| 7 | [Checklist — analiza statyczna](07-checklist-static.md) | Lista kontrolna do analizy bez uruchamiania aplikacji |
| 8 | [Checklist — analiza dynamiczna](08-checklist-dynamic.md) | Lista kontrolna do analizy w trakcie działania aplikacji |
| 9 | [Laboratoria i zasoby](09-labs-resources.md) | Podatne aplikacje treningowe, standardy OWASP, linki |

## Szybki start — kolejność narzędzi w typowym zleceniu

1. **Identyfikacja** — CFF Explorer / DIE → potwierdź, że to .NET
2. **Analiza statyczna** — dnSpyEx → dekompilacja, przegląd kodu, szukanie sekretów
3. **Konfiguracja** — `App.config`, `tnsnames.ora`, rejestr → dane logowania w plaintexcie
4. **Ochrona binarna** — PESecurity / BinSkim → ASLR, DEP, podpis cyfrowy
5. **Monitoring dynamiczny** — ProcMon + Regshot → obserwacja zmian w systemie plików i rejestrze
6. **Pamięć** — Process Hacker → zrzut pamięci procesu, szukanie haseł
7. **Sieć** — Wireshark (TNS 1521) + Burp Suite (HTTP/S) → przechwytywanie ruchu
8. **Baza Oracle** — ODAT → brute-force SID, poświadczenia, eskalacja uprawnień
9. **Raportowanie** — mapowanie znalezisk na OWASP Desktop Top 10 (DA1–DA10)
