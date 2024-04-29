using System.Collections.Immutable;

using OpenIddict.Abstractions;

namespace JGUZDV.OIDC.ProtocolServer.Data
{
    public record ScopeModel(
        string Name,
        string? DisplayName,
        ImmutableArray<string> Resources,
        ScopeProperties Properties)
    {
        public static async Task<ScopeModel?> FromScopeNameAsync(
            IOpenIddictScopeManager scopeManager,
            string scopeName, CancellationToken ct)
        {
            var scope = await scopeManager.FindByNameAsync(scopeName, ct);
            if (scope == null) return null;

            return await FromScopeObject(scopeManager, scope, ct);
        }

        internal static async Task<ImmutableArray<ScopeModel>> FromScopeNamesAsync(IOpenIddictScopeManager scopeManager, ImmutableArray<string> scopeNames, CancellationToken ct)
        {
            var tasks = new List<Task<ScopeModel>>();
            await foreach (var scope in scopeManager.FindByNamesAsync(scopeNames, ct))
                tasks.Add(FromScopeObject(scopeManager, scope, ct));

            return (await Task.WhenAll(tasks))
                .ToImmutableArray();
        }

        private static async Task<ScopeModel> FromScopeObject(IOpenIddictScopeManager scopeManager, object scope, CancellationToken ct)
        {
            var props = await scopeManager.GetPropertiesAsync(scope, ct);
            var scopeProps = ScopeProperties.DeserializeFromProperties(props);

            return new ScopeModel(
                (await scopeManager.GetNameAsync(scope, ct))!,
                await scopeManager.GetDisplayNameAsync(scope, ct),
                await scopeManager.GetResourcesAsync(scope, ct),
                scopeProps
                );
        }
    }
}
