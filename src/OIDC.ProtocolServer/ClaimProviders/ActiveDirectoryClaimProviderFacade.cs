using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.ActiveDirectory;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders;

public class ActiveDirectoryClaimProviderFacade : IClaimProvider
{
    private readonly DirectoryEntryProvider _directoryEntryProvider;
    private readonly JGUZDV.ActiveDirectory.Claims.IClaimProvider _provider;

    public ActiveDirectoryClaimProviderFacade(
        DirectoryEntryProvider directoryEntryProvider,
        JGUZDV.ActiveDirectory.Claims.IClaimProvider provider)
    {
        _directoryEntryProvider = directoryEntryProvider;
        _provider = provider;
    }

    public bool CanProvideAnyOf(IEnumerable<string> claimTypes) =>
        _provider.GetProvidedClaimTypes(claimTypes.ToArray()).Any();

    public Task<List<(string Type, string Value)>> GetClaimsAsync(ClaimsPrincipal subject, IEnumerable<string> claimTypes, CancellationToken ct)
    {
        var userEntry = _directoryEntryProvider.GetUserEntryFromPrincipal(subject);
        var result = _provider.GetClaims(userEntry, claimTypes.ToArray());
        return Task.FromResult(result.ToList());
    }
}
