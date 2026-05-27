using System;
using System.Data;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Services.Protocols;
using System.Xml;
using Newtonsoft.Json;
using Oracle.ManagedDataAccess.Client;

namespace VulnerableApp.DataAccess
{
    // =========================================================================
    // SEC-ORA-001: SQL Injection via string concatenation
    // =========================================================================
    public class UserRepository
    {
        private OracleConnection _conn;

        public DataTable GetUserById(int userId)
        {
            string sql = "SELECT * FROM USERS WHERE ID = " + userId;
            OracleCommand cmd = new OracleCommand(sql, _conn);
            return FillDataTable(cmd);
        }

        public DataTable SearchUsers(string searchTerm)
        {
            string query = "SELECT * FROM EMPLOYEES WHERE NAME LIKE '%" + searchTerm + "%'";
            var cmd = new OracleCommand(query, _conn);
            cmd.ExecuteReader();
            return null;
        }

        public void UpdateUser(string name, int id)
        {
            var cmd = new OracleCommand();
            cmd.Connection = _conn;
            cmd.CommandText = "UPDATE USERS SET NAME = '" + name + "' WHERE ID = " + id;
            cmd.ExecuteNonQuery();
        }

        public DataTable InterpolatedQuery(string status)
        {
            var cmd = new OracleCommand($"SELECT * FROM ORDERS WHERE STATUS = '{status}'", _conn);
            return FillDataTable(cmd);
        }

        public DataTable DataAdapterInjection(string filter)
        {
            var adapter = new OracleDataAdapter("SELECT * FROM PRODUCTS WHERE CATEGORY = '" + filter + "'", _conn);
            var dt = new DataTable();
            adapter.Fill(dt);
            return dt;
        }

        private DataTable FillDataTable(OracleCommand cmd) => null;
    }

    // =========================================================================
    // SEC-AUTH-001: Hardcoded credentials
    // =========================================================================
    public class DatabaseConfig
    {
        private string password = "Pr0duction_S3cret!";
        private string apikey = "sk-live-abc123def456ghi789";

        public OracleConnection GetConnection()
        {
            return new OracleConnection("Data Source=PRODDB;User Id=APP_USER;Password=OraclePass2024!");
        }

        public string ConnectionString = "Data Source=ORCL;User Id=SYS;Password=manager;DBA Privilege=SYSDBA";
    }

    // =========================================================================
    // SEC-CRYPT-001/002/003: Weak cryptography
    // =========================================================================
    public class WeakCrypto
    {
        public byte[] HashPassword(string password)
        {
            // SEC-CRYPT-001: MD5 for password
            MD5 md5 = MD5.Create();
            return md5.ComputeHash(Encoding.UTF8.GetBytes(password));
        }

        public byte[] HashWithSha1(string data)
        {
            // SEC-CRYPT-002: SHA1
            var sha = new SHA1CryptoServiceProvider();
            return sha.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        public void EncryptWithDES(byte[] data)
        {
            // SEC-CRYPT-003: DES
            var des = new DESCryptoServiceProvider();
            des.Mode = CipherMode.ECB;
            des.Key = Encoding.UTF8.GetBytes("12345678");
        }

        // SEC-CRYPT-004: Hardcoded key/IV
        private static readonly byte[] encryptionKey = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

        public void WeakRsa()
        {
            // SEC-CRYPT-007: RSA 1024-bit
            var rsa = new RSACryptoServiceProvider(1024);
        }
    }

    // =========================================================================
    // SEC-CRYPT-005: Insecure random for token
    // =========================================================================
    public class TokenGenerator
    {
        public string GenerateSessionToken()
        {
            var random = new Random();
            var tokenBytes = new byte[32];
            random.NextBytes(tokenBytes);
            return Convert.ToBase64String(tokenBytes);
        }
    }

    // =========================================================================
    // SEC-CRYPT-006: Disabled SSL validation
    // =========================================================================
    public class InsecureTls
    {
        public void DisableSslValidation()
        {
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
        }
    }

    // =========================================================================
    // SEC-SOAP-006 / SEC-DESER: Unsafe deserialization
    // =========================================================================
    public class UnsafeDeserialization
    {
        public object DeserializeBinary(Stream stream)
        {
            BinaryFormatter formatter = new BinaryFormatter();
            return formatter.Deserialize(stream);
        }

        public object DeserializeSoap(Stream stream)
        {
            SoapFormatter soap = new SoapFormatter();
            return soap.Deserialize(stream);
        }

        public void NetDataContract()
        {
            var serializer = new NetDataContractSerializer();
        }

        public void LosFormat()
        {
            var formatter = new LosFormatter();
            object result = formatter.Deserialize("base64data");
        }
    }

    // =========================================================================
    // SEC-DESER-001: JSON.NET TypeNameHandling
    // =========================================================================
    public class JsonDeserialize
    {
        public object DeserializeUnsafe(string json)
        {
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            };
            return JsonConvert.DeserializeObject(json, settings);
        }
    }

    // =========================================================================
    // SEC-DNT-007: DataSet.ReadXml
    // =========================================================================
    public class DataSetVuln
    {
        public DataSet LoadFromXml(string path)
        {
            var ds = new DataSet();
            ds.ReadXml(path);
            return ds;
        }
    }

    // =========================================================================
    // SEC-XML-001: XXE
    // =========================================================================
    public class XxeVulnerable
    {
        public void LoadXml(string userInput)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(userInput);
        }
    }

    // =========================================================================
    // SEC-CMD-001: Command injection
    // =========================================================================
    public class CommandInjection
    {
        public void RunCommand(string userInput)
        {
            System.Diagnostics.Process.Start("cmd.exe", "/c " + userInput);
        }
    }

    // =========================================================================
    // SEC-FILE-001: Path traversal
    // =========================================================================
    public class PathTraversal
    {
        public string ReadFile(string fileName)
        {
            string path = @"C:\AppData\" + fileName;
            return File.ReadAllText(path);
        }
    }

    // =========================================================================
    // SEC-DATA-001: Logging sensitive data
    // =========================================================================
    public class SensitiveLogging
    {
        public void LogCredentials(string password)
        {
            Console.WriteLine("User password: " + password);
        }
    }

    // =========================================================================
    // SEC-DATA-003: Stack trace to user
    // =========================================================================
    public class StackTraceExposure
    {
        public void ShowError(Exception ex)
        {
            System.Windows.Forms.MessageBox.Show(ex.StackTrace);
        }
    }

    // =========================================================================
    // SEC-SOAP-002: BasicHttpBinding without security
    // =========================================================================
    public class InsecureWcf
    {
        public void CreateBinding()
        {
            var binding = new System.ServiceModel.BasicHttpBinding();
            // No security mode set — defaults to None
        }
    }

    // =========================================================================
    // SEC-SOAP-004: HTTP endpoint
    // =========================================================================
    public class HttpEndpoint
    {
        public void CallService()
        {
            var client = new SoapHttpClientProtocol();
            client.Url = "http://api.external-service.com/soap/v1";
        }
    }

    // =========================================================================
    // SEC-DNT-001: Unsafe reflection
    // =========================================================================
    public class UnsafeReflection
    {
        public object LoadType(string userTypeName)
        {
            Type t = Type.GetType(userTypeName + ".Handler");
            return Activator.CreateInstance(t);
        }
    }

    // =========================================================================
    // SEC-NET-003: SSRF
    // =========================================================================
    public class SsrfVulnerable
    {
        public string FetchUrl(string userUrl)
        {
            var client = new WebClient();
            return client.DownloadString(userUrl + "/api/data");
        }
    }

    // =========================================================================
    // SEC-ORA-012: Excessive Oracle privileges
    // =========================================================================
    public class ExcessivePrivs
    {
        public void ConnectAsSysDba()
        {
            var conn = new OracleConnection("Data Source=ORCL;User ID=SYS;DBA Privilege=SYSDBA");
        }
    }

    // =========================================================================
    // SEC-DNT-005: ViewState without MAC
    // =========================================================================
    // In a .aspx page: <%@ Page EnableViewStateMac="false" %>
    public class ViewStateConfig
    {
        public void DisableViewStateMac()
        {
            // This would be in Page_Init
            // Page.EnableViewStateMac = false;  // VULNERABLE
        }
    }
}
