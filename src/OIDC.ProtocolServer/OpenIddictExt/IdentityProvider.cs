using System.Collections.Immutable;
using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.ClaimProviders;

using Microsoft.IdentityModel.Tokens;

using OpenIddict.Abstractions;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.OpenIddictExt
{
    public class IdentityProvider(IEnumerable<IClaimProvider> claimProviders)
    {
        private readonly IEnumerable<IClaimProvider> _claimProviders = claimProviders;

        //TODO: would probably be better to have this in the options
        private readonly ISet<string> _remoteClaimTypes = new HashSet<string>()
        {
            Claims.AuthenticationMethodReference,
            Constants.ClaimTypes.MFAAuthTime
        };

        private static readonly IEnumerable<string> BothTokens = [Destinations.IdentityToken, Destinations.AccessToken];
        private static readonly IEnumerable<string> AccessToken = [Destinations.AccessToken];


        public async Task<ClaimsIdentity> CreateIdentityAsync(
            ClaimsPrincipal subjectUser,
            OIDCContext context,
            CancellationToken ct)
        {
            // Determine, which claims are requested by the client application and to which token they should be added.
            // Also collect "resources" (=> Audience) that are requested by the client application.
            var idTokenClaims = new HashSet<string>(context.Application.Properties.RequestedClaimTypes);
            var accessTokenClaims = new HashSet<string>();
            var resources = new HashSet<string>();

            foreach (var scope in context.Scopes)
            {
                if (scope.Properties.TargetToken.Contains(Destinations.IdentityToken))
                    idTokenClaims.UnionWith(scope.Properties.RequestedClaimTypes);

                //TODO: if (scope.Properties.TargetToken.Contains(Destinations.AccessToken))
                accessTokenClaims.UnionWith(scope.Properties.RequestedClaimTypes);

                resources.UnionWith(scope.Resources);
            }

            // Load all claims that are requested by the client application
            var requestedClaims = new HashSet<string>(idTokenClaims.Concat(accessTokenClaims));
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


            // Copy claims from the remote identity to the new identity
            foreach (var remoteClaim in subjectUser.Claims.Where(x => _remoteClaimTypes.Contains(x.Type)))
            {
                identity.AddClaim(remoteClaim.Type, remoteClaim.Value);
            }

            identity.SetClaims(subjectClaims);

            // Currently _all_ claims will be added to the access token and _some_ claims will be added to the id token.
            identity.SetDestinations(c => GetDestinations(c, idTokenClaims));

            return identity;
        }


        private async Task<List<Model.Claim>> LoadSubjectClaims(ClaimsPrincipal subject, HashSet<string> requestedClaims, CancellationToken ct)
        {
            var userClaims = new List<Model.Claim>();
            foreach (var cp in _claimProviders)
            {
                var claims = await cp.GetClaimsAsync(subject, requestedClaims, ct);
                userClaims.AddRange(claims.Select(x => new Model.Claim(x.Type, x.Value)));
            }

            return userClaims;
        }


        private static IEnumerable<string> GetDestinations(Claim claim, HashSet<string> idTokenClaims)
        {
            return idTokenClaims.Contains(claim.Type, StringComparer.OrdinalIgnoreCase)
                ? BothTokens : AccessToken;
        }
    }
}
