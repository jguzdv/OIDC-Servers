using System.Linq;

using JGUZDV.OIDC.ProtocolServer.ClaimProviders;
using JGUZDV.OIDC.ProtocolServer.Model;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.Web.Controllers
{
    public class UserInfoController(
        IOpenIddictScopeManager scopeManager)
        : ControllerBase
    {
        private readonly IOpenIddictScopeManager _scopeManager = scopeManager;

        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo"), Produces("application/json")]
        public async Task<IActionResult> UserInfo(
            [FromServices] IEnumerable<IClaimProvider> claimProviders,
            CancellationToken ct)
        {
            var userSubject = User.GetClaim(Claims.Subject);
            if(string.IsNullOrWhiteSpace(userSubject))
            {
                return BadRequest(new OpenIddictResponse
                {
                    Error = Errors.InvalidRequest,
                    ErrorDescription = "The user is not authenticated."
                });
            }

            var userScopes = User.GetScopes();

            var scopes = await ScopeModel.FromScopeNamesAsync(_scopeManager, User.GetScopes(), ct);
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
                var claims = await cp.GetClaimsAsync(User, idClaims.Distinct(), ct);
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

            return Ok(result);
        }
    }
}
