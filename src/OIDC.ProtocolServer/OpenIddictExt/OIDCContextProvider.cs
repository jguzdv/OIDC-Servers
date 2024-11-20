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
        
        // As offline_access is not mentioned in the database for every application, this method would discard it when
        // the IOpenIddictScopeManager is asked for allowed scopes (which are taken from the db). To prevent loosing
        // the scope offline_access when requested, it is explicitly added in the statement within the next if clause.
        var scopes = await ScopeModel.FromScopeNamesAsync(_scopeManager, scopeNames, ct);

        if (scopeNames.Contains(Scopes.OfflineAccess))
        {
            scopes = scopes.Add(new ScopeModel(Scopes.OfflineAccess, Scopes.OfflineAccess, [], new()));
        }

        return new OIDCContext(request, application, scopes);
    }
}