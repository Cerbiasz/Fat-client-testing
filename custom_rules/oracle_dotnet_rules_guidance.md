# Custom DevSkim Rules — Oracle ODP.NET & .NET Thick Client Guidance

## CUSTOM001 — Hardcoded password in Oracle connection string

### What is the vulnerability?
Oracle ODP.NET connection strings containing hardcoded passwords expose database credentials directly in source code, compiled assemblies (easily decompiled with dnSpy/ILSpy), and version control history. Even if the password is later removed from source, it persists in git history.

### Why it matters
An attacker who gains read access to the repository, CI/CD artifacts, or the compiled binary can extract the Oracle database password and connect directly to the database, bypassing all application-level access controls.

### How to fix

**Before (vulnerable):**
```csharp
string connStr = "Data Source=ORCL;User Id=APP_USER;Password=S3cretPass!";
var conn = new OracleConnection(connStr);

// Or via builder:
var builder = new OracleConnectionStringBuilder();
builder.DataSource = "ORCL";
builder.UserID = "APP_USER";
builder.Password = "S3cretPass!";
```

**After (secure):**
```csharp
// Option 1: Read from a secure configuration provider
string connStr = Configuration.GetConnectionString("OracleDB");
// where the actual password is in Azure Key Vault, DPAPI-encrypted config, 
// or environment variable — never in source code.

// Option 2: Use Oracle Wallet (no password in connection string at all)
string connStr = "Data Source=ORCL;User Id=/;";
var conn = new OracleConnection(connStr);

// Option 3: Use DPAPI ProtectedData for local encryption
byte[] encrypted = Convert.FromBase64String(
    ConfigurationManager.AppSettings["EncryptedOraclePassword"]);
byte[] decrypted = ProtectedData.Unprotect(encrypted, null, 
    DataProtectionScope.LocalMachine);
string password = Encoding.UTF8.GetString(decrypted);
```

---

## CUSTOM002 — SQL injection via string concatenation in OracleCommand

### What is the vulnerability?
Building SQL queries by concatenating user input into the command string allows an attacker to inject arbitrary SQL statements. With Oracle, this can lead to data exfiltration, privilege escalation (e.g., via `DBMS_SCHEDULER`), or even OS command execution if the DB user has elevated privileges.

### Why it matters
Oracle-specific SQL injection can be particularly dangerous due to powerful PL/SQL packages (`UTL_FILE`, `UTL_HTTP`, `DBMS_SCHEDULER`, `DBMS_JAVA`) that can be abused for lateral movement from the database to the OS.

### How to fix

**Before (vulnerable):**
```csharp
string userId = txtUserId.Text;

// String concatenation — VULNERABLE
var cmd = new OracleCommand(
    "SELECT * FROM USERS WHERE USER_ID = '" + userId + "'", conn);

// String interpolation — EQUALLY VULNERABLE
cmd.CommandText = $"SELECT * FROM USERS WHERE USER_ID = '{userId}'";

// DataAdapter with concatenation — VULNERABLE
var adapter = new OracleDataAdapter(
    "SELECT * FROM ORDERS WHERE CUSTOMER = '" + custName + "'", conn);
```

**After (secure):**
```csharp
string userId = txtUserId.Text;

var cmd = new OracleCommand(
    "SELECT * FROM USERS WHERE USER_ID = :userId", conn);
cmd.Parameters.Add(new OracleParameter("userId", OracleDbType.Varchar2));
cmd.Parameters["userId"].Value = userId;

// DataAdapter — parameterized
var selectCmd = new OracleCommand(
    "SELECT * FROM ORDERS WHERE CUSTOMER = :custName", conn);
selectCmd.Parameters.Add(new OracleParameter("custName", custName));
var adapter = new OracleDataAdapter(selectCmd);
```

---

## CUSTOM003 — Unsafe .NET deserialization

### What is the vulnerability?
`BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, and `LosFormatter` deserialize type information from the input stream and can instantiate arbitrary types. An attacker who controls the serialized data can craft a payload (using gadget chains like `TypeConfuseDelegate`, `PSObject`, or `ObjectDataProvider`) that executes arbitrary code during deserialization — before any validation can occur. CWE-502.

### Why it matters
In thick client applications, serialized data often travels over the network, is stored in local files, or is exchanged via clipboard/IPC. Any of these channels can be intercepted or tampered with. Microsoft has officially deprecated `BinaryFormatter` as of .NET 8 with no workaround — it is fundamentally unsafe.

### How to fix

**Before (vulnerable):**
```csharp
// Deserializing user session from a file — VULNERABLE
BinaryFormatter formatter = new BinaryFormatter();
UserSession session;
using (FileStream fs = File.OpenRead("session.dat"))
{
    session = (UserSession)formatter.Deserialize(fs);
}

// SOAP deserialization from network — VULNERABLE
SoapFormatter soap = new SoapFormatter();
object data = soap.Deserialize(networkStream);
```

**After (secure):**
```csharp
// Option 1: Use System.Text.Json (recommended for .NET 6+)
UserSession session;
using (FileStream fs = File.OpenRead("session.json"))
{
    session = await JsonSerializer.DeserializeAsync<UserSession>(fs);
}

// Option 2: Use DataContractSerializer with known types
var serializer = new DataContractSerializer(typeof(UserSession));
using (var reader = XmlReader.Create("session.xml"))
{
    session = (UserSession)serializer.ReadObject(reader);
}

// Option 3: Use protobuf-net for binary serialization
UserSession session = Serializer.Deserialize<UserSession>(stream);
```

---

## CUSTOM004 — Oracle connection without encryption (manual review)

### What is the vulnerability?
Oracle database connections transmit data in cleartext by default. Without Oracle Advanced Security (Native Network Encryption) or TLS configured, all SQL queries, result sets, and credentials traverse the network unencrypted. An attacker on the same network segment can capture sensitive data via packet sniffing.

### Why it matters
Thick client applications often run on corporate LANs where network segmentation may be imperfect. ARP spoofing, VLAN hopping, or a compromised switch can give an attacker visibility into database traffic. Even if the password is encrypted during authentication (via Oracle O5LOGON), subsequent query data is still cleartext.

### How to fix

**Verify encryption is configured.** This rule flags OracleConnection instantiations for manual review — check that one of the following is in place:

**Option 1: Oracle Native Network Encryption (sqlnet.ora on client and server):**
```
# sqlnet.ora (client side)
SQLNET.ENCRYPTION_CLIENT = REQUIRED
SQLNET.ENCRYPTION_TYPES_CLIENT = (AES256, AES192)
SQLNET.CRYPTO_CHECKSUM_CLIENT = REQUIRED
SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT = (SHA256)
```

**Option 2: TLS configuration in tnsnames.ora:**
```
ORCL =
  (DESCRIPTION =
    (ADDRESS = (PROTOCOL = TCPS)(HOST = db.example.com)(PORT = 2484))
    (CONNECT_DATA = (SERVICE_NAME = ORCL))
    (SECURITY = (SSL_SERVER_CERT_DN = "CN=db.example.com"))
  )
```

**Option 3: Verify programmatically after connection:**
```csharp
var conn = new OracleConnection(connStr);
conn.Open();

using var cmd = new OracleCommand(
    "SELECT network_service_banner FROM v$session_connect_info " +
    "WHERE sid = SYS_CONTEXT('USERENV', 'SID')", conn);
using var reader = cmd.ExecuteReader();
while (reader.Read())
{
    Console.WriteLine(reader.GetString(0));
    // Look for: "AES256 Encryption service adapter"
    // and "SHA256 Crypto-checksumming service adapter"
}
```
