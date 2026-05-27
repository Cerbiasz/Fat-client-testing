using System;
using System.Data;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Oracle.ManagedDataAccess.Client;

namespace SecureApp.DataAccess
{
    /// <summary>
    /// This file contains SECURE code patterns.
    /// The scanner should produce ZERO findings for this file.
    /// </summary>
    public class SecureUserRepository
    {
        private OracleConnection _conn;

        // Parameterized query — SAFE
        public DataTable GetUserById(int userId)
        {
            string sql = "SELECT * FROM USERS WHERE ID = :userId";
            var cmd = new OracleCommand(sql, _conn);
            cmd.Parameters.Add("userId", OracleDbType.Int32).Value = userId;
            return FillDataTable(cmd);
        }

        // Stored procedure — SAFE
        public DataTable SearchUsers(string searchTerm)
        {
            var cmd = new OracleCommand("PKG_USERS.SEARCH_USERS", _conn);
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.Add("p_search", OracleDbType.Varchar2).Value = searchTerm;
            cmd.Parameters.Add("p_cursor", OracleDbType.RefCursor).Direction = ParameterDirection.Output;
            return FillDataTable(cmd);
        }

        // Parameterized update — SAFE
        public void UpdateUser(string name, int id)
        {
            var cmd = new OracleCommand("UPDATE USERS SET NAME = :name WHERE ID = :id", _conn);
            cmd.Parameters.Add("name", OracleDbType.Varchar2).Value = name;
            cmd.Parameters.Add("id", OracleDbType.Int32).Value = id;
            cmd.ExecuteNonQuery();
        }

        private DataTable FillDataTable(OracleCommand cmd) => null;
    }

    public class SecureCrypto
    {
        // AES-256 with proper key management — SAFE
        public byte[] Encrypt(byte[] data, byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                aes.Key = key; // key loaded from vault at runtime
                aes.GenerateIV();
                using (var encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        // PBKDF2 for password hashing — SAFE
        public byte[] HashPassword(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(32);
            }
        }

        // Secure random — SAFE
        public byte[] GenerateToken()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var bytes = new byte[32];
                rng.GetBytes(bytes);
                return bytes;
            }
        }

        // RSA 2048 — SAFE
        public RSA CreateRsaKey()
        {
            return RSA.Create(2048);
        }
    }

    public class SecureConnection
    {
        // Connection string from config — SAFE
        public OracleConnection GetConnection()
        {
            string connStr = System.Configuration.ConfigurationManager.ConnectionStrings["OracleDB"].ConnectionString;
            return new OracleConnection(connStr);
        }
    }

    public class SecureTls
    {
        // Proper TLS configuration — SAFE
        public void ConfigureTls()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
            ServicePointManager.CheckCertificateRevocationList = true;
        }
    }

    public class SecureXml
    {
        // XmlDocument with XmlResolver=null — SAFE
        public void LoadXml(string path)
        {
            var doc = new System.Xml.XmlDocument();
            doc.XmlResolver = null;
            doc.Load(path);
        }
    }

    public class SecureFileAccess
    {
        // Path validation — SAFE
        public string ReadFile(string fileName)
        {
            string basePath = AppDomain.CurrentDomain.BaseDirectory;
            string safeName = Path.GetFileName(fileName); // strips directory components
            string fullPath = Path.GetFullPath(Path.Combine(basePath, "uploads", safeName));

            if (!fullPath.StartsWith(basePath))
                throw new UnauthorizedAccessException("Path traversal attempt detected");

            return File.ReadAllText(fullPath);
        }
    }
}
