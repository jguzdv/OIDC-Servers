using System.Collections.Immutable;
using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.ClaimProviders;
using JGUZDV.OIDC.ProtocolServer.Configuration;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using OpenIddict.Abstractions;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.OpenIddictExt
{
    public class IdentityProvider(IEnumerable<IClaimProvider> claimProviders, IOptions<ProtocolServerOptions> options)
    {
        private readonly IEnumerable<IClaimProvider> _claimProviders = claimProviders;
        private readonly IOptions<ProtocolServerOptions> _options = options;

        private readonly HashSet<string> _essentialClaims =
        [
            options.Value.SubjectClaimType,
            options.Value.PersonIdentifierClaimType
        ];

        private static readonly IEnumerable<string> IdTokenOnly = [Destinations.IdentityToken];
        private static readonly IEnumerable<string> AccessTokenOnly = [Destinations.AccessToken];
        private static readonly IEnumerable<string> BothTokens = [Destinations.IdentityToken, Destinations.AccessToken];


        public async Task<ClaimsIdentity> CreateIdentityAsync(
            ClaimsPrincipal subjectUser,
            OIDCContext context,
            CancellationToken ct)
        {
            // Determine, which claims are requested by the client application and to which token they should be added.
            // Also collect "resources" (=> Audience) that are requested by the client application.
            HashSet<string> idTokenClaims = [..context.Application.Properties.RequestedClaimTypes, .._options.Value.DefaultIdTokenClaims];
            HashSet<string> accessTokenClaims = [.._options.Value.DefaultAccessTokenClaims];
            var resources = new HashSet<string>();

            foreach (var scope in context.Scopes)
            {
                if (scope.Properties.TargetToken.Contains(Destinations.IdentityToken))
                    idTokenClaims.UnionWith(scope.Properties.RequestedClaimTypes);

                if (scope.Properties.TargetToken.Contains(Destinations.AccessToken) || !scope.Properties.TargetToken.Any())
                    accessTokenClaims.UnionWith(scope.Properties.RequestedClaimTypes);

                resources.UnionWith(scope.Resources);
            }

            // Load all claims that are requested by the client application
            var requestedClaims = new HashSet<string>(idTokenClaims.Concat(accessTokenClaims).Concat(_essentialClaims));
            var subjectClaims = await LoadSubjectClaims(subjectUser, requestedClaims, ct);


            // Create the claims-based identity that will be used by OpenIddict to generate tokens.
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // Add scope and audience claims
            // Note: The granted scopes match the requested scope
            // but you may want to allow the user to uncheck specific scopes.
            // For that, simply restrict the list of scopes before calling SetScopes.
            identity.SetScopes(context.Scopes.Select(x => x.Name));
            identity.SetResources(context.Scopes.SelectMany(x => x.Resources));

            identity.SetClaims(subjectClaims);

            // Currently _all_ claims will be added to the access token and _some_ claims will be added to the id token.
            identity.SetDestinations(c => GetDestinations(c, idTokenClaims, accessTokenClaims));

            return identity;
        }


        private async Task<List<Model.Claim>> LoadSubjectClaims(ClaimsPrincipal subject, HashSet<string> requestedClaimTypes, CancellationToken ct)
        {
            var userClaims = new List<Model.Claim>();
            foreach (var cp in _claimProviders.OrderBy(x => x.ExecutionOrder))
            {
                if (!cp.CanProvideAnyOf(requestedClaimTypes))
                {
                    continue;
                }

                var claims = await cp.GetClaimsAsync(subject, userClaims, requestedClaimTypes, ct);
                userClaims.AddRange(claims.Select(x => new Model.Claim(x.Type, x.Value)));
            }

            return userClaims;
        }


        private static IEnumerable<string> GetDestinations(Claim claim, HashSet<string> idTokenClaims, HashSet<string> accessTokenClaims)
        {
            if(accessTokenClaims.Contains(claim.Type, StringComparer.OrdinalIgnoreCase))
                yield return Destinations.AccessToken;

            if(idTokenClaims.Contains(claim.Type, StringComparer.OrdinalIgnoreCase))
                yield return Destinations.IdentityToken;
        }
    }
}
