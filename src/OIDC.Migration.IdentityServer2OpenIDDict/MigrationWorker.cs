using System.Text.Json;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using OpenIddict.Abstractions;

using static OpenIddict.Abstractions.OpenIddictConstants;

internal class MigrationWorker : IHostedService
{
    private readonly IdentityServer4.EntityFramework.DbContexts.ConfigurationDbContext _srcContext;
    private readonly IdentityServer4.Stores.IClientStore _clientStore;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IHostApplicationLifetime _hostApplicationLifetime;
    private readonly ILogger<MigrationWorker> _logger;

    public MigrationWorker(
        IdentityServer4.EntityFramework.DbContexts.ConfigurationDbContext srcContext,
        IdentityServer4.Stores.IClientStore clientStore,
        IOpenIddictApplicationManager applicationManager,
        IHostApplicationLifetime hostApplicationLifetime,
        ILogger<MigrationWorker> logger
    )
    {
        _srcContext = srcContext;
        _clientStore = clientStore;
        _applicationManager = applicationManager;
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

                var targetClient = await _applicationManager.FindByClientIdAsync(srcClient.ClientId, ct);
                var clientDescriptor = CreateApplicationDescriptor(srcClient);
                
                if(clientDescriptor == null)
                    continue;

                if (targetClient == null)
                {
                    await _applicationManager.CreateAsync(clientDescriptor, ct);
                }
                else
                {
                    await _applicationManager.UpdateAsync(targetClient, clientDescriptor, ct);
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

    private OpenIddictApplicationDescriptor? CreateApplicationDescriptor(IdentityServer4.Models.Client srcClient)
    {
        try
        {
            var hasSecret = srcClient.ClientSecrets.Any();

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = srcClient.ClientId,
                ClientSecret = srcClient.ClientSecrets.FirstOrDefault()?.Value,
                DisplayName = srcClient.ClientName,
                ApplicationType = ApplicationTypes.Web,
                ClientType = hasSecret ? ClientTypes.Confidential : ClientTypes.Public,
                ConsentType = ConsentTypes.Implicit
            };

            descriptor.RedirectUris.UnionWith(srcClient.RedirectUris.Select(x => new Uri(x)));
            descriptor.PostLogoutRedirectUris.UnionWith(srcClient.PostLogoutRedirectUris.Select(x => new Uri(x)));

            foreach (var grantType in srcClient.AllowedGrantTypes)
            {
                switch (grantType)
                {
                    case "implicit":
                        descriptor.Permissions.Add(Permissions.GrantTypes.Implicit);
                        break;
                    case "hybrid":
                        descriptor.Permissions.Add(Permissions.GrantTypes.Implicit);
                        descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
                        break;
                    case "authorization_code":
                        descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
                        break;
                    case "client_credentials":
                        descriptor.Permissions.Add(Permissions.GrantTypes.ClientCredentials);
                        break;
                    case "password":
                        descriptor.Permissions.Add(Permissions.GrantTypes.Password);
                        break;
                    case "refresh_token":
                        descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);
                        break;
                    default:
                        throw new NotSupportedException($"Grant type {grantType} is not supported");
                }
            }

            foreach (var scope in srcClient.AllowedScopes)
            {
                descriptor.Permissions.Add(Permissions.Prefixes.Scope + scope);
            }

            return descriptor;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not create OpenIddict Client");

            var jsonClient = JsonSerializer.Serialize(srcClient, new JsonSerializerOptions(JsonSerializerDefaults.General)
            {
                WriteIndented = true
            });
            _logger.LogInformation(jsonClient);

            return null;
        }
    }
}