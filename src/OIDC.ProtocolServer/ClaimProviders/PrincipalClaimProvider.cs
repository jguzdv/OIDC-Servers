using JGUZDV.OIDC.ProtocolServer.Configuration;
using JGUZDV.OIDC.ProtocolServer.Model;

using Microsoft.Extensions.Options;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders;

/// <summary>
/// This will take the currently authenticated user and map the claims from the principal to the claims requested by the client.
/// </summary>
internal class PrincipalClaimProvider : IClaimProvider
{
    //TODO: Make this TWO claims provider - one for local users and one for remote users?
    private readonly ILookup<ClaimType, PrincipalClaimProviderOptions.PrincipalClaimType> _claimTypeMaps;

    public ClaimType[] RequiredClaimTypes => Array.Empty<ClaimType>();
    public ClaimType[] ProvidedClaimTypes => _claimTypeMaps
            .SelectMany(x => x.Select(pct => new ClaimType(pct.AsClaimType ?? pct.ClaimType)))
            .ToArray();

    public PrincipalClaimProvider(IOptions<ProtocolServerOptions> options)
    {
        _claimTypeMaps = options.Value.PrincipalClaimProvider
            .ClaimTypeMaps
            .ToLookup(
                x => new ClaimType(x.ClaimType), 
                x => x);
    }

    public bool CanProvideAnyOf(IEnumerable<ClaimType> claimTypes) => 
        _claimTypeMaps
            .Select(x => x.Key)
            .Intersect(claimTypes)
            .Any();



    public Task AddProviderClaimsToContext(ClaimProviderContext context, CancellationToken ct)
    {
        foreach (var claim in context.User.Claims)
        {
            var claimTypeMaps = _claimTypeMaps[claim.Type];
            if (!claimTypeMaps.Any())
            {
                continue;
            }

            foreach (var claimTypeMap in claimTypeMaps)
            {
                var actualType = claimTypeMap.AsClaimType ?? claimTypeMap.ClaimType;
                var claimValue = claimTypeMap.Transformation switch
                {
                    ClaimTransformationMethod.Base64DecodeGuid => new Guid(Convert.FromBase64String(claim.Value)).ToString(),
                    _ => claim.Value,
                };

                context.AddClaim(new(actualType, claimValue));
            }
        }

        return Task.CompletedTask;
    }
}
