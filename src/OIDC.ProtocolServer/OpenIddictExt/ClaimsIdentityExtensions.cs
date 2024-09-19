using System.Collections.Immutable;
using System.Security.Claims;

using OpenIddict.Abstractions;

namespace JGUZDV.OIDC.ProtocolServer.OpenIddictExt
{
    public static class ClaimsIdentityExtensions
    {
        public static void SetClaims(this ClaimsIdentity identity, IEnumerable<Model.Claim> claims)
        {
            // Claims may be single value or multi value. So we group by type and add them accordingly.
            foreach (var claimTypeClaims in claims.GroupBy(x => x.Type, StringComparer.OrdinalIgnoreCase))
            {
                if (claimTypeClaims.Count() == 1)
                {
                    identity.SetClaim(claimTypeClaims.Key, claimTypeClaims.First().Value);
                }
                else
                {
                    identity.SetClaims(claimTypeClaims.Key, claimTypeClaims.Select(x => x.Value).Distinct().ToImmutableArray());
                }
            }
        }
    }
}
