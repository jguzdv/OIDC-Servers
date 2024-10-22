using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.Configuration;

using Microsoft.Extensions.Options;

using static JGUZDV.OIDC.ProtocolServer.Configuration.PrincipalClaimProviderOptions.PrincipalClaimType;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders;

/// <summary>
/// This will take the currently authenticated user and map the claims from the principal to the claims requested by the client.
/// </summary>
internal class PrincipalClaimProvider : IClaimProvider
{
    private readonly ILookup<string, PrincipalClaimProviderOptions.PrincipalClaimType> _claimTypeMaps;

    public int ExecutionOrder => 1;

    public PrincipalClaimProvider(IOptions<ProtocolServerOptions> options)
    {
        _claimTypeMaps = options.Value.PrincipalClaimProvider
            .ClaimTypeMaps
            .ToLookup(x => x.ClaimType, x => x, StringComparer.OrdinalIgnoreCase);
    }

    public bool CanProvideAnyOf(IEnumerable<string> claimTypes) => 
        _claimTypeMaps
            .Select(x => x.Key)
            .Intersect(claimTypes, StringComparer.OrdinalIgnoreCase)
            .Any();

    public Task<List<Model.Claim>> GetClaimsAsync(ClaimsPrincipal currentUser, IEnumerable<Model.Claim> knownClaims, IEnumerable<string> claimTypes, CancellationToken ct)
    {
        var result = new List<Model.Claim>();

        foreach(var claim in currentUser.Claims)
        {
            var claimTypeMaps = _claimTypeMaps[claim.Type];
            if(!claimTypeMaps.Any())
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

                result.Add(new Model.Claim(actualType, claimValue));
            }
        }

        return Task.FromResult(result.Where(x => claimTypes.Contains(x.Type, StringComparer.OrdinalIgnoreCase)).ToList());
    }
}
