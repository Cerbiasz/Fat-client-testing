using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using Oracle.ManagedDataAccess.Client;

namespace TestSamples
{
    // CUSTOM001 — Hardcoded password in Oracle connection string
    public class HardcodedCredentials
    {
        public void ConnectWithHardcodedPassword()
        {
            string connStr = "Data Source=ORCL;User Id=APP_USER;Password=S3cretPass!";
            var conn = new OracleConnection(connStr);
            conn.Open();
        }

        public void ConnectViaBuilder()
        {
            var builder = new OracleConnectionStringBuilder();
            builder.DataSource = "ORCL";
            builder.UserID = "APP_USER";
            builder.Password = "MyHardcodedPass123";
        }
    }

    // CUSTOM002 — SQL injection via string concatenation
    public class SqlInjection
    {
        public void ConcatenatedQuery(OracleConnection conn, string userInput)
        {
            var cmd = new OracleCommand("SELECT * FROM USERS WHERE NAME = '" + userInput + "'", conn);
            cmd.ExecuteNonQuery();
        }

        public void InterpolatedQuery(OracleConnection conn, string userInput)
        {
            var cmd = new OracleCommand($"SELECT * FROM USERS WHERE ID = {userInput}", conn);
            cmd.ExecuteNonQuery();
        }

        public void DataAdapterConcatenation(OracleConnection conn, string filter)
        {
            var adapter = new OracleDataAdapter("SELECT * FROM ORDERS WHERE STATUS = '" + filter + "'", conn);
        }

        public void CommandTextConcatenation(OracleConnection conn, string table)
        {
            var cmd = new OracleCommand();
            cmd.Connection = conn;
            cmd.CommandText = "SELECT * FROM " + table + " WHERE 1=1";
            cmd.ExecuteReader();
        }

        public void CommandTextInterpolation(OracleConnection conn, string id)
        {
            var cmd = new OracleCommand();
            cmd.CommandText = $"DELETE FROM AUDIT_LOG WHERE ID = {id}";
            cmd.ExecuteNonQuery();
        }
    }

    // CUSTOM003 — Unsafe .NET deserialization
    public class UnsafeDeserialization
    {
        public object DeserializeWithBinaryFormatter(Stream stream)
        {
            var formatter = new BinaryFormatter();
            return formatter.Deserialize(stream);
        }

        public object DeserializeWithSoapFormatter(Stream stream)
        {
            var soap = new SoapFormatter();
            return soap.Deserialize(stream);
        }

        public void UseNetDataContractSerializer()
        {
            var serializer = new NetDataContractSerializer();
        }

        public void UseLosFormatter()
        {
            var formatter = new LosFormatter();
            object result = formatter.Deserialize("base64data");
        }
    }

    // CUSTOM004 — Oracle connection without encryption (manual review)
    public class UnencryptedConnection
    {
        public void BasicConnection()
        {
            var conn = new OracleConnection("Data Source=ORCL;User Id=/;");
            conn.Open();
        }

        public void BuilderConnection()
        {
            var builder = new OracleConnectionStringBuilder("Data Source=PROD_DB;");
        }
    }
}
