using System.Collections.Immutable;

using OpenIddict.Abstractions;

namespace JGUZDV.OIDC.ProtocolServer.Data
{
    public record ScopeModel(
        string Name,
        string DisplayName,
        ImmutableArray<string> Resources,
        ImmutableArray<(string Type, string Value)> StaticClaims,
        ImmutableArray<string> RequestedClaimTypes
        )
    {
        public static async Task<ScopeModel?> From(
            IOpenIddictScopeManager scopeManager,
            string scopeName, CancellationToken ct)
        {
            var scope = await scopeManager.FindByNameAsync(scopeName, ct);
            if (scope == null) return null;

            return await From(scopeManager, scope, ct);
        }

        private static async Task<ScopeModel?> From(IOpenIddictScopeManager scopeManager, object scope, CancellationToken ct)
        {
            var props = await scopeManager.GetPropertiesAsync(scope, ct);
            var scopeProps = new ScopeProperties(props);

            return new ScopeModel(
                await scopeManager.GetNameAsync(scope, ct),
                await scopeManager.GetDisplayNameAsync(scope, ct),
                await scopeManager.GetResourcesAsync(scope, ct),
                scopeProps.StaticClaims.ToImmutableArray(),
                scopeProps.ClaimTypes.ToImmutableArray()
                );
        }
    }
}
