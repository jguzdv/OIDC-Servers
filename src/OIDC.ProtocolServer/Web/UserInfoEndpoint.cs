using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.ClaimProviders;
using JGUZDV.OIDC.ProtocolServer.Model;

using OpenIddict.Abstractions;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.Web;

public partial class Endpoints
{
    public static partial class OIDC
    {
        public static async Task<IResult> UserInfo(
            ClaimsPrincipal user,
            IOpenIddictScopeManager scopeManager,
            IEnumerable<IClaimProvider> claimProviders,
            CancellationToken ct)
        {
            var userSubject = user.GetClaim(Claims.Subject);
            if (string.IsNullOrWhiteSpace(userSubject))
            {
                return Results.BadRequest(new OpenIddictResponse
                {
                    Error = Errors.InvalidRequest,
                    ErrorDescription = "The user is not authenticated."
                });
            }

            var userScopes = user.GetScopes();

            var scopes = await ScopeModel.FromScopeNamesAsync(scopeManager, user.GetScopes(), ct);
            var idClaims = scopes
                .Where(x => x.Properties.TargetToken.Contains(Destinations.IdentityToken))
                .SelectMany(x => x.Properties.RequestedClaimTypes)
                .Except([Claims.Subject], StringComparer.OrdinalIgnoreCase) // We'll add the subject from the current user
                .ToHashSet();

            var userClaims = new List<(string Type, string Value)>
        {
            (Claims.Subject, userSubject)
        };

            foreach (var cp in claimProviders)
            {
                var claims = await cp.GetClaimsAsync(user, idClaims.Distinct(), ct);
                userClaims.AddRange(claims);
            }

            // OpenIddict will accept userinfo claims as a dictionary<string, object>
            // Since multiple claim providers might produce the same type, we'll group them by type
            var result = userClaims.DistinctBy(x => (x.Type, x.Value))
                .ToLookup(x => x.Type, x => x.Value, StringComparer.OrdinalIgnoreCase)
                .ToDictionary<IGrouping<string, string>, string, object>(
                    x => x.Key,
                    x => x.Count() == 1 ? x.First() : x.ToArray()
                );

            return Results.Ok(result);
        }
    }
}
