using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.ActiveDirectory;
using JGUZDV.OIDC.ProtocolServer.Configuration;
using JGUZDV.OIDC.ProtocolServer.Model;

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

    public ClaimType[] RequiredClaimTypes => [
        new(_options.Value.SubjectClaimType)
        ];

    public ClaimType[] ProvidedClaimTypes => 
        _provider.GetProvidedClaimTypes().Select(x => new ClaimType(x)).ToArray();

    
    public bool CanProvideAnyOf(IEnumerable<ClaimType> claimTypes) =>
        _provider.GetProvidedClaimTypes(claimTypes.Select(x => x.Type).ToArray()).Any();


    public Task AddProviderClaimsToContext(ClaimProviderContext context, CancellationToken ct)
    {
        var userEntry = _directoryEntryProvider.GetUserEntryFromPrincipal(context.User);
        var claims = _provider.GetClaims(userEntry, context.RequestedClaimTypes.Select(x => x.Type).ToArray());
        foreach (var claim in claims)
        {
            context.AddClaim(new Model.Claim(claim.Type, claim.Value));
        }

        return Task.CompletedTask;
    }

}
