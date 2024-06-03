using System.Data;

using JGUZDV.OIDC.ProtocolServer.Model;

using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace JGUZDV.OIDC.Tools.ConfigUI.Data
{
    public class ConfigAppContext
    {
        private IServiceProvider _serviceProvider;

        public ConfigAppContext(IServiceProvider serviceProvider)
        {
            _serviceProvider = ServiceProvider;
        }

        public string? ConnectionString { get; private set; }

        public IServiceProvider? ServiceProvider { get; }
        
        public void SetConnection(string server, string database)
        {
            var builder = new SqlConnectionStringBuilder
            {
                DataSource = server,
                InitialCatalog = database,
                IntegratedSecurity = true,
                Encrypt = false
            };

            ConnectionString = builder.ConnectionString;
        }

        public async Task EnsureConnection()
        {
            
        }

        public Task Disconnect()
        {
            
            ConnectionString = null;

            return Task.CompletedTask;
        }
    }
}
