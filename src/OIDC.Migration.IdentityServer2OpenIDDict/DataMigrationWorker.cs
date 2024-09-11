using System.Text.Json;

using JGUZDV.OIDC.ProtocolServer.Model;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore.Models;

using static OpenIddict.Abstractions.OpenIddictConstants;

internal class DataMigrationWorker : IHostedService
{
    private readonly IdentityServer4.EntityFramework.DbContexts.ConfigurationDbContext _srcContext;
    private readonly IdentityServer4.Stores.IClientStore _clientStore;
    private readonly IdentityServer4.Stores.IResourceStore _resourceStore;
    private readonly OpenIddictApplicationManager<OpenIddictEntityFrameworkCoreApplication> _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly IHostApplicationLifetime _hostApplicationLifetime;
    private readonly ILogger<DataMigrationWorker> _logger;

    public DataMigrationWorker(
        IdentityServer4.EntityFramework.DbContexts.ConfigurationDbContext srcContext,
        IdentityServer4.Stores.IClientStore clientStore,
        IdentityServer4.Stores.IResourceStore resourceStore,
        OpenIddictApplicationManager<OpenIddictEntityFrameworkCoreApplication> applicationManager,
        IOpenIddictScopeManager scopeManager,
        IHostApplicationLifetime hostApplicationLifetime,
        ILogger<DataMigrationWorker> logger
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
        var allRessources = await _resourceStore.GetAllResourcesAsync();

        var scopeResources = new List<IdentityServer4.Models.Resource>();
        scopeResources.AddRange(allRessources.IdentityResources);
        scopeResources.AddRange(allRessources.ApiScopes);

        foreach (var scope in scopeResources)
        {
            var targetScope = await _scopeManager.FindByNameAsync(scope.Name, ct);
            var resources = await _resourceStore.FindApiResourcesByScopeNameAsync(new List<string> { scope.Name });

            var scopeDescriptor = CreateScopeDescriptor(scope, resources);

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
    }

    private OpenIddictScopeDescriptor? CreateScopeDescriptor(
        IdentityServer4.Models.Resource srcScope, 
        IEnumerable<IdentityServer4.Models.ApiResource> resources)
    {
        var descriptor = new OpenIddictScopeDescriptor
        {
            Name = srcScope.Name,
            DisplayName = srcScope.DisplayName,
            Description = srcScope.Description,
        };

        foreach(var resource in resources)
        {
            descriptor.Resources.Add(resource.Name);
        }

        var props = new ScopeProperties()
        {
            RequestedClaimTypes = new(srcScope.UserClaims),
        };

        if(string.Equals(srcScope.Name, "openid", StringComparison.OrdinalIgnoreCase))
        {
            props.RequestedClaimTypes.Add("zdv_sub");
            props.RequestedClaimTypes.Add("zdv_upn");
        }

        if (srcScope is IdentityServer4.Models.IdentityResource)
        {
            props.TargetToken = new() { Destinations.IdentityToken };
        }

        descriptor.Properties.Add(CustomProperties.PropertyName, props.Serialize());

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
            var validSecrets = srcClient.ClientSecrets
                .Where(x => !x.Expiration.HasValue || x.Expiration > DateTime.UtcNow);
            var hasSecret = srcClient.ClientSecrets.Any();

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = srcClient.ClientId,
                ClientSecret = validSecrets.FirstOrDefault()?.Value,
                DisplayName = srcClient.ClientName,
                ApplicationType = ApplicationTypes.Web,
                ClientType = validSecrets.Any() ? ClientTypes.Confidential : ClientTypes.Public,
                ConsentType = ConsentTypes.Implicit,
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Logout,
                }
            };

            descriptor.RedirectUris.UnionWith(CreateUris(srcClient.RedirectUris));
            descriptor.PostLogoutRedirectUris.UnionWith(CreateUris(srcClient.PostLogoutRedirectUris));

            foreach (var grantType in srcClient.AllowedGrantTypes)
            {
                switch (grantType)
                {
                    case "implicit":
                        descriptor.Permissions.Add(Permissions.GrantTypes.Implicit);
                        descriptor.Permissions.Add(Permissions.ResponseTypes.IdToken);
                        descriptor.Permissions.Add(Permissions.ResponseTypes.IdTokenToken);
                        break;
                    case "hybrid":
                        descriptor.Permissions.Add(Permissions.GrantTypes.Implicit);
                        descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
                        descriptor.Permissions.Add(Permissions.Endpoints.Token);
                        descriptor.Permissions.Add(Permissions.ResponseTypes.CodeIdToken);
                        descriptor.Permissions.Add(Permissions.ResponseTypes.CodeIdTokenToken);
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

            var props = new ApplicationProperties();
            props.StaticClaims.AddRange(
                srcClient.Claims.Select(x => new Claim(x.Type, x.Value))
            );


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

            descriptor.Properties.Add(CustomProperties.PropertyName, props.Serialize());
            return descriptor;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not create OpenIddict Client");

            var jsonClient = JsonSerializer.Serialize(srcClient, 
                new JsonSerializerOptions(JsonSerializerDefaults.General)
                {
                    WriteIndented = true
                }
            );
            _logger.LogInformation(jsonClient);

            return null;
        }
    }

    private IEnumerable<Uri> CreateUris(ICollection<string> redirectUris)
    {
        var result = new List<Uri>();

        foreach (var uri in redirectUris.Where(x => x != "https:///signin-oidc" && x != "https:///"))
        {
            var replacedUri = ReplaceRegex(uri);
            try
            {
                result.Add(new Uri(replacedUri));
            }
            catch
            {
                _logger.LogError("The URI {uri} ({replacedUri}) could not be used.", uri, replacedUri);
            }
        }

        return result;
    }

    private string ReplaceRegex(string potentialRegexUri)
    {
        return potentialRegexUri
            .Replace("^", "")
            .Replace("$", "")
            .Replace("[\\d\\w\\.-]*\\.", "__.")
            .Replace("[\\d\\w\\.-]*.", "__.")
            .Replace("[\\d\\w\\.-]*", "__.")
            .Replace("[\\w\\d]+.", "__.")
            .Replace("\\.", ".");
    }
}