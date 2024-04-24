using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

internal class MigrationWorker : IHostedService
{
    private readonly IdentityServer4.EntityFramework.DbContexts.ConfigurationDbContext _srcContext;
    private readonly IdentityServer4.Stores.IClientStore _clientStore;
    private readonly IHostApplicationLifetime _hostApplicationLifetime;
    private readonly ILogger<MigrationWorker> _logger;

    public MigrationWorker(
        IdentityServer4.EntityFramework.DbContexts.ConfigurationDbContext srcContext,
        IdentityServer4.Stores.IClientStore clientStore,
        IHostApplicationLifetime hostApplicationLifetime,
        ILogger<MigrationWorker> logger
    )
    {
        _srcContext = srcContext;
        _clientStore = clientStore;
        _hostApplicationLifetime = hostApplicationLifetime;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _ = RunAsync(cancellationToken);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }


    private async Task RunAsync(CancellationToken ct)
    {
        var clientIds = await _srcContext.Clients
            .Select(x => x.ClientId)
            .ToListAsync(ct);

        foreach (var clientId in clientIds)
        {
            try
            {
                var srcClient = await _clientStore.FindClientByIdAsync(clientId);
                if (srcClient == null)
                    continue;

                var targetClient = new OpenIddictApplicationDescriptor
                {
                    ClientId = srcClient.ClientId,
                    ClientSecret = srcClient.ClientSecrets.FirstOrDefault()?.Value,
                    DisplayName = srcClient.ClientName,
                    ApplicationType = ApplicationTypes.Web,
                    ClientType = ClientTypes.Public,
                    ConsentType = ConsentTypes.Implicit,
                };

                targetClient.RedirectUris.UnionWith(srcClient.RedirectUris.Select(x => new Uri(x)));
                targetClient.PostLogoutRedirectUris.UnionWith(srcClient.PostLogoutRedirectUris.Select(x => new Uri(x)));

                foreach (var grantType in srcClient.AllowedGrantTypes)
                {
                    switch(grantType)
                    {
                        case "implicit":
                            targetClient.Permissions.Add(Permissions.GrantTypes.Implicit);
                            break;
                        case "hybrid":
                            targetClient.Permissions.Add(Permissions.GrantTypes.Implicit);
                            targetClient.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
                            break;
                        case "authorization_code":
                            targetClient.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
                            break;
                        case "client_credentials":
                            targetClient.Permissions.Add(Permissions.GrantTypes.ClientCredentials);
                            break;
                        case "password":
                            targetClient.Permissions.Add(Permissions.GrantTypes.Password);
                            break;
                        case "refresh_token":
                            targetClient.Permissions.Add(Permissions.GrantTypes.RefreshToken);
                            break;
                        default:
                            throw new NotSupportedException($"Grant type {grantType} is not supported");
                    }
                }

                foreach (var scope in srcClient.AllowedScopes)
                {
                    targetClient.Permissions.Add(Permissions.Prefixes.Scope + scope);
                }

            //        new applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            //    {
            //        ClientId = "sample",
            //        ClientSecret = "P@ssword!1",
            //        Permissions =
            //{
            //    Permissions.Scopes.Profile,
            //    Permissions.Prefixes.Scope + "sample",
            //    Permissions.Endpoints.Authorization,
            //    Permissions.Endpoints.Token,
            //    Permissions.GrantTypes.AuthorizationCode,
            //    Permissions.ResponseTypes.Code,
            //},
            //        Properties =
            //{
            //    { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(new[] { "some_claim" }) },
            //    { Constants.Properties.StaticClaims, JsonSerializer.SerializeToElement(new[] { new { Type="static_1", Value="uhh value!" } }) }
            //}
            //    });

                _logger.LogInformation("Client {clientId} has been loaded", clientId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error migrating client {clientId}", clientId);
            }

        }
        
        _hostApplicationLifetime.StopApplication();
    }
}