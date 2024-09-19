using System.Collections.Immutable;

using JGUZDV.OIDC.ProtocolServer.Model;

using OpenIddict.Abstractions;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.OpenIddictExt;

public class OIDCContextProvider(IOpenIddictApplicationManager applicationManager, IOpenIddictScopeManager scopeManager)
{
    private readonly IOpenIddictApplicationManager _applicationManager = applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager = scopeManager;

    public Task<OIDCContext> CreateContextAsync(OpenIddictRequest request, CancellationToken ct)
        => CreateContextAsync(request, null, ct);

    public async Task<OIDCContext> CreateContextAsync(OpenIddictRequest request, ImmutableArray<string>? requestedScopes, CancellationToken ct)
    {
        var clientId = request.ClientId!;
        var scopeNames = requestedScopes ?? request.GetScopes();
        
        var application = await ApplicationModel.FromClientIdAsync(_applicationManager, clientId, ct);
        var scopes = await ScopeModel.FromScopeNamesAsync(_scopeManager, scopeNames, ct);

        if (scopeNames.Contains(Scopes.OfflineAccess))
        {
            scopes = scopes.Add(new ScopeModel(Scopes.OfflineAccess, Scopes.OfflineAccess, [], new()));
        }

        return new OIDCContext(request, application, scopes);
    }
}