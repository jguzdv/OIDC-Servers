using System.Collections.Immutable;
using System.Security.Claims;

using OpenIddict.Abstractions;

namespace JGUZDV.OIDC.ProtocolServer.OpenIddictExt
{
    public static class ClaimsIdentityExtensions
    {
        // Some claims are defined to be arrays by the OIDC spec. We'll need to handle them accordingly.
        private static readonly HashSet<string> _arrayTypeClaims = ["amr"];

        public static void SetClaims(this ClaimsIdentity identity, IEnumerable<Model.Claim> claims)
        {
            // Claims may be single value or multi value. So we group by type and add them accordingly.
            foreach (var claimTypeClaims in claims.GroupBy(x => x.Type, StringComparer.OrdinalIgnoreCase))
            {
                var forceArraySemantics = _arrayTypeClaims.Contains(claimTypeClaims.Key);

                if(forceArraySemantics || claimTypeClaims.Count() > 1)
                {
                    identity.SetClaims(claimTypeClaims.Key, claimTypeClaims.Select(x => x.Value).Distinct().ToImmutableArray());
                }
                else
                {
                    identity.SetClaim(claimTypeClaims.Key, claimTypeClaims.First().Value);
                }
            }
        }
    }
}
