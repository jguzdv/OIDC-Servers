using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.ActiveDirectory;
using JGUZDV.OIDC.ProtocolServer.Configuration;

using Microsoft.Extensions.Options;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders;

internal class ActiveDirectoryClaimProviderFacade : IClaimProvider
{
    private readonly IOptions<ProtocolServerOptions> _options;
    private readonly DirectoryEntryProvider _directoryEntryProvider;
    private readonly JGUZDV.ActiveDirectory.Claims.IClaimProvider _provider;

    public ActiveDirectoryClaimProviderFacade(
        IOptions<ProtocolServerOptions> options,
        DirectoryEntryProvider directoryEntryProvider,
        JGUZDV.ActiveDirectory.Claims.IClaimProvider provider)
    {
        _options = options;
        _directoryEntryProvider = directoryEntryProvider;
        _provider = provider;
    }

    public string[] RequiredClaimTypes => [
        _options.Value.SubjectClaimType,
        Claims.Subject
        ];

    public string[] ProvidedClaimTypes => 
        _provider.GetProvidedClaimTypes().ToArray();

    public bool CanProvideAnyOf(IEnumerable<string> claimTypes) =>
        _provider.GetProvidedClaimTypes(claimTypes.ToArray()).Any();

    public Task<List<Model.Claim>> GetClaimsAsync(ClaimsPrincipal subject, IEnumerable<Model.Claim> knownClaims, IEnumerable<string> claimTypes, CancellationToken ct)
    {
        var userEntry = _directoryEntryProvider.GetUserEntryFromPrincipal(subject);
        var result = _provider.GetClaims(userEntry, claimTypes.ToArray());
        return Task.FromResult(result.Select(x => new Model.Claim(x.Type, x.Value)).ToList());
    }
}
