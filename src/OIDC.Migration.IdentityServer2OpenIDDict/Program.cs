﻿using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using OIDC.Migration.IdentityServer2OpenIDDict;

var builder = Host.CreateDefaultBuilder(args);
builder.ConfigureLogging(logging =>
{
    logging.SetMinimumLevel(LogLevel.Information);
    logging.AddFilter("Microsoft.EntityFrameworkCore.Database.Command", LogLevel.Error);
    logging.AddFilter("OIDC.Migration.IdentityServer2OpenIDDict", LogLevel.Debug);
});

builder.ConfigureServices(services =>
{
    services.AddHostedService<MigrationWorker>();

    services.AddIdentityServer()
        .AddConfigurationStore(
            store =>
            {
                store.ConfigureDbContext = context => context.UseSqlServer(args[0]);
            }
        );

    services.AddDbContext<OpenIddictDbContext>(options =>
    {
        options.UseSqlServer(args[1]);
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

var host = builder.Build();
await host.RunAsync();