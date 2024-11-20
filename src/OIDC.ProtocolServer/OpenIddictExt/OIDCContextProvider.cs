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
        
        // Hier an dieser Stelle würde offline_access rausfliegen, weil dieser Scope nicht in der Datenbank eingetragen wird.
        // Er würde zwar vom Client beim /authorize übertragen, aber hier dann wieder rausfliegen.
        var scopes = await ScopeModel.FromScopeNamesAsync(_scopeManager, scopeNames, ct);

        // OfflineAccess wird von OpenIdDict intern behandelt. 
        // Thomas hat das konfigurieren von Scopes über die Datenbank selbst hineingebracht, von Seiten OpenIdDict existiert das gar nicht.
        // Weil offline_access (siehe oben) hier nicht mehr da sein würde, weil nicht in der DB eingetragen, wird er hier nochmal explizit 
        // hinzugefügt, wenn er in scopeNames (per request übergebene Scope-Auflistung) drin ist.
        if (scopeNames.Contains(Scopes.OfflineAccess))
        {
            scopes = scopes.Add(new ScopeModel(Scopes.OfflineAccess, Scopes.OfflineAccess, [], new()));
        }

        return new OIDCContext(request, application, scopes);
    }
}