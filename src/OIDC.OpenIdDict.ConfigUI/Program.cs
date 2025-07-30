using JGUZDV.OIDC.ProtocolServer.Model;

using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace JGUZDV.OIDC.ConfigUI
{
    public static class Program
    {
        public static IServiceProvider? ServiceProvider { get; private set; }

        [System.STAThreadAttribute()]
        public static void Main(string[] args)
        {
            ServiceProvider = BuildServiceProvider(args);

            App app = new();
            app.InitializeComponent();
            app.Run();
        }


        public static IServiceProvider BuildServiceProvider(string[] args)
        {


            var serviceCollection = new ServiceCollection();

            var connectionBuilder = new SqlConnectionStringBuilder
            {
                DataSource = args[0],
                InitialCatalog = args[1],
                IntegratedSecurity = true,
                Encrypt = false
            };


#if DEBUG
            serviceCollection.AddBlazorWebViewDeveloperTools();
            serviceCollection.AddLogging(logging =>
            {
                logging.AddDebug();
            });
#endif

            serviceCollection.AddDbContext<ApplicationDbContext>(
                ef =>
                {
                    ef.UseSqlServer(connectionBuilder.ConnectionString);
                    ef.UseOpenIddict();
                }
            );

            serviceCollection.AddOpenIddict(oidc =>
            {
                oidc.AddCore(core =>
                {
                    core.UseEntityFrameworkCore(c =>
                    {
                        c.UseDbContext<ApplicationDbContext>();
                    });
                });
            });

            serviceCollection.AddWpfBlazorWebView();
            return serviceCollection.BuildServiceProvider();
        }
    }
}
