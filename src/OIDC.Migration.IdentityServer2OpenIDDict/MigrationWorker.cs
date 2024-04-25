using System.Text.Json;

using IdentityServer4.Stores;

using JGUZDV.OIDC.ProtocolServer.Data;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using OpenIddict.Abstractions;

using static OpenIddict.Abstractions.OpenIddictConstants;

internal class MigrationWorker : IHostedService
{
    private readonly IdentityServer4.EntityFramework.DbContexts.ConfigurationDbContext _srcContext;
    private readonly IdentityServer4.Stores.IClientStore _clientStore;
    private readonly IResourceStore _resourceStore;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly IHostApplicationLifetime _hostApplicationLifetime;
    private readonly ILogger<MigrationWorker> _logger;

    public MigrationWorker(
        IdentityServer4.EntityFramework.DbContexts.ConfigurationDbContext srcContext,
        IdentityServer4.Stores.IClientStore clientStore,
        IdentityServer4.Stores.IResourceStore resourceStore,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager,
        IHostApplicationLifetime hostApplicationLifetime,
        ILogger<MigrationWorker> logger
    )
    {
        _srcContext = srcContext;
        _clientStore = clientStore;
        _resourceStore = resourceStore;
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
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
        await MigrateScopes(ct);
        await MigrateClients(ct);

        _hostApplicationLifetime.StopApplication();
    }


    private async Task MigrateScopes(CancellationToken ct)
    {
        var resources = await _resourceStore.GetAllEnabledResourcesAsync();

        foreach(var scope in resources.IdentityResources)
        {
            var targetScope = await _scopeManager.FindByNameAsync(scope.Name, ct);
            var scopeDescriptor = CreateScopeDescriptor(scope);

            if (scopeDescriptor == null)
                continue;

            if (targetScope == null)
            {
                await _scopeManager.CreateAsync(scopeDescriptor, ct);
                _logger.LogInformation("Created new Scope with Name: {scopeName}", scope.Name);
            }
            else
            {
                await _scopeManager.UpdateAsync(targetScope, scopeDescriptor, ct);
                _logger.LogInformation("Updated existing Scope with Name: {scopeName}", scope.Name);
            }
        }

        //foreach (var scope in scopes)
        //{
        //    try
        //    {
        //        var scopeModel = await ScopeModel.FromScopeNameAsync(_resourceStore, scope.Name, ct);
        //        if (scopeModel == null)
        //            continue;

        //        var descriptor = new OpenIddictScopeDescriptor
        //        {
        //            Name = scopeModel.Name,
        //            Resources = scopeModel.Resources,
        //            DisplayName = scopeModel.DisplayName,
        //            Properties =
        //            {
        //                { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(scopeModel.RequestedClaimTypes) },
        //                { Constants.Properties.StaticClaims, JsonSerializer.SerializeToElement(scopeModel.StaticClaims) },
        //                { Constants.Properties.IsIdTokenScope, scopeModel.IsIdTokenScope }
        //            }
        //        };

        //        await _resourceStore.CreateScopeAsync(descriptor, ct);
        //        _logger.LogInformation("Created new Scope: {scopeName}", scopeModel.Name);
        //    }
        //    catch (Exception ex)
        //    {
        //        _logger.LogError(ex, "Error creating scope {scopeName}", scope.Name);
        //    }
        //}
    }

    private OpenIddictScopeDescriptor? CreateScopeDescriptor(IdentityServer4.Models.Resource srcScope)
    {
        var descriptor = new OpenIddictScopeDescriptor
        {
            Name = srcScope.Name,
            DisplayName = srcScope.DisplayName,
            Description = srcScope.Description,
            Properties =
            {
                { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(srcScope.UserClaims) }
            },
        };

        if(srcScope is IdentityServer4.Models.IdentityResource)
        {
            descriptor.Properties.Add(Constants.Properties.IsIdTokenScope, JsonSerializer.SerializeToElement(true));
        }

        return descriptor;
    }



    private async Task MigrateClients(CancellationToken ct)
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

                if (clientDescriptor == null)
                    continue;

                if (targetClient == null)
                {
                    await _applicationManager.CreateAsync(clientDescriptor, ct);
                    _logger.LogInformation("Created new Application for ClientId: {clientId}", clientId);
                }
                else
                {
                    await _applicationManager.UpdateAsync(targetClient, clientDescriptor, ct);
                    _logger.LogInformation("Updated existing Application with ClientId: {clientId}", clientId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating/updating client {clientId}", clientId);
            }
        }
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
                ConsentType = ConsentTypes.Implicit,
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Logout,
                }
            };

            descriptor.RedirectUris.UnionWith(srcClient.RedirectUris.Select(x => new Uri(x)));
            descriptor.PostLogoutRedirectUris.UnionWith(srcClient.PostLogoutRedirectUris.Select(x => new Uri(x)));

            foreach (var grantType in srcClient.AllowedGrantTypes)
            {
                switch (grantType)
                {
                    case "implicit":
                        descriptor.Permissions.Add(Permissions.GrantTypes.Implicit);
                        descriptor.Permissions.Add(Permissions.ResponseTypes.IdTokenToken);
                        break;
                    case "hybrid":
                        descriptor.Permissions.Add(Permissions.GrantTypes.Implicit);
                        descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
                        descriptor.Permissions.Add(Permissions.Endpoints.Token);
                        descriptor.Permissions.Add(Permissions.ResponseTypes.CodeIdToken);
                        break;
                    case "authorization_code":
                        descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
                        descriptor.Permissions.Add(Permissions.Endpoints.Token);
                        descriptor.Permissions.Add(Permissions.ResponseTypes.Code);
                        break;
                    case "client_credentials":
                        descriptor.Permissions.Add(Permissions.GrantTypes.ClientCredentials);
                        descriptor.Permissions.Add(Permissions.Endpoints.Token);
                        break;
                    //case "refresh_token":
                    //    descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);
                    //    descriptor.Permissions.Add(Permissions.Endpoints.Token);
                    //    break;
                    default:
                        throw new NotSupportedException($"Grant type {grantType} is not supported");
                }
            }

            if(srcClient.AllowOfflineAccess)
            {
                descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);
                descriptor.Permissions.Add(Permissions.Endpoints.Token);
            }

            foreach (var scope in srcClient.AllowedScopes)
            {
                descriptor.Permissions.Add(Permissions.Prefixes.Scope + scope);
            }

            if(srcClient.Claims.Any())
            {
                var claims = srcClient.Claims.Select(x => (x.Type, x.Value));
                descriptor.Properties.Add("staticClaims", JsonSerializer.SerializeToElement(claims));
            }


            
            // TODO: Permission: refresh-token 
            

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