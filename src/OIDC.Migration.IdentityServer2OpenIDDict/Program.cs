using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using OIDC.Migration.IdentityServer2OpenIDDict;


var commands = new[] { "data", "keys" };

if (args.Length == 0 || !commands.Contains(args[0]))
{
    Console.WriteLine($"Known commands are {string.Join(", ", commands)}");
}

IHostBuilder builder = CreateHost();

if (args[0] == "data")
{

    builder.ConfigureServices(services =>
    {
        services.AddHostedService<DataMigrationWorker>();

        services.AddIdentityServer()
            .AddConfigurationStore(
                store =>
                {
                    store.ConfigureDbContext = context => context.UseSqlServer(args[1]);
                }
            );

        services.AddDbContext<OpenIddictDbContext>(options =>
        {
            options.UseSqlServer(args[2]);
            options.UseOpenIddict();
        });

        services.AddOpenIddict(opt =>
        {
            opt.AddCore(core =>
            {
                core.UseEntityFrameworkCore()
                    .UseDbContext<OpenIddictDbContext>();
            });
        });
    });
}

if (args[0] == "keys")
{
    builder.ConfigureServices(services =>
    {
        services.AddHostedService<KeyMigrationWorker>();

        services.AddDataProtection()
            .SetApplicationName("C:\\inetpub\\sites\\openid.uni-mainz.de")
            .PersistKeysToFileSystem(new DirectoryInfo(args[1]))
            .ProtectKeysWithDpapiNG()
            .DisableAutomaticKeyGeneration();

        services.Configure<KeyMigrationWorker.Options>(config =>
        {
            config.KeyPath = args[2];
            config.CertificatePath = args[3];
            config.CertificatePassword = args[4];
        });
    });
}


var host = builder.Build();
await host.RunAsync();


static IHostBuilder CreateHost()
{
    var builder = Host.CreateDefaultBuilder();
    builder.ConfigureLogging(logging =>
    {
        logging.SetMinimumLevel(LogLevel.Information);
        logging.AddFilter("Microsoft.AspNetCore.DataProtection.KeyManagement", LogLevel.Error);
        logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Error);
        logging.AddFilter("OIDC.Migration.IdentityServer2OpenIDDict", LogLevel.Information);
    });
    return builder;
}