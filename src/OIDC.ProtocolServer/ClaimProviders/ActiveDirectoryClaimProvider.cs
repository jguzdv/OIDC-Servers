using JGUZDV.ActiveDirectory.ClaimProvider;
using JGUZDV.ActiveDirectory.ClaimProvider.Configuration;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders;

public class ActiveDirectoryClaimProviderFacade : IClaimProvider
{
    private readonly ADClaimProvider _provider;
    private readonly IOptions<ActiveDirectoryOptions> _options;

    public ActiveDirectoryClaimProviderFacade(ADClaimProvider provider, IOptions<ActiveDirectoryOptions> options)
    {
        _provider = provider;
        _options = options;
    }

    public bool CanProvideAnyOf(IEnumerable<string> claimTypes) =>
        _options.Value.ClaimSources.Select(x => x.ClaimType)
            .Intersect(claimTypes, StringComparer.OrdinalIgnoreCase)
            .Any();

    public Task<List<(string Type, string Value)>> GetClaimsAsync(ClaimsPrincipal currentUser, IEnumerable<string> claimTypes, CancellationToken ct)
        =>Task.FromResult(_provider.GetClaims(currentUser, claimTypes));
}
