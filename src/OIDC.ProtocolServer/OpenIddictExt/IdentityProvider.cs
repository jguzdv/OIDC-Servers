using System.Collections.Immutable;
using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.ClaimProviders;
using JGUZDV.OIDC.ProtocolServer.Configuration;
using JGUZDV.OIDC.ProtocolServer.Model;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using OpenIddict.Abstractions;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.OpenIddictExt
{
    public class IdentityProvider {
        private readonly HashSet<ClaimType> _essentialClaims;

        private readonly List<IClaimProvider> _claimProviders;
        private readonly IOptions<ProtocolServerOptions> _options;

        public IdentityProvider(IEnumerable<IClaimProvider> claimProviders, IOptions<ProtocolServerOptions> options)
        {
            _options = options;

            _claimProviders = claimProviders.ToList();
            OrderClaimProviders(_claimProviders);

            _essentialClaims =
            [
                options.Value.SubjectClaimType,
                options.Value.PersonIdentifierClaimType
            ];
        }

        public async Task<ClaimsIdentity> CreateIdentityAsync(
            ClaimsPrincipal subjectUser,
            OIDCContext context,
            CancellationToken ct)
        {
            // Determine, which claims are requested by the client application and to which token they should be added.
            // Also collect "resources" (=> Audience) that are requested by the client application.
            HashSet<ClaimType> idTokenClaims = [..context.Application.Properties.RequestedClaimTypes, .._options.Value.DefaultIdTokenClaims];
            HashSet<ClaimType> accessTokenClaims = [.._options.Value.DefaultAccessTokenClaims];
            var resources = new HashSet<string>();

            foreach (var scope in context.Scopes)
            {
                var scopeClaimTypes = scope.Properties.RequestedClaimTypes.Select(x => new ClaimType(x));

                if (scope.Properties.TargetToken.Contains(Destinations.IdentityToken))
                    idTokenClaims.UnionWith(scopeClaimTypes);

                if (scope.Properties.TargetToken.Contains(Destinations.AccessToken) || !scope.Properties.TargetToken.Any())
                    accessTokenClaims.UnionWith(scopeClaimTypes);

                resources.UnionWith(scope.Resources);
            }

            // Load all claims that are requested by the client application
            var requestedClaims = new HashSet<ClaimType>(idTokenClaims.Concat(accessTokenClaims).Concat(_essentialClaims));
            var userClaims = await LoadUserClaims(subjectUser, requestedClaims, ct);

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

            // Add all static claims
            var staticClaims = GetStaticClaimsAndUpdateClaimSets(context, idTokenClaims, accessTokenClaims);
            userClaims.AddRange(staticClaims);

            // Add all claims to the identity and set their destinations
            identity.SetClaims(userClaims);
            identity.SetDestinations(c => GetDestinations(c, idTokenClaims, accessTokenClaims));

            return identity;
        }

        
        public async Task<List<Model.Claim>> LoadUserClaims(ClaimsPrincipal user, HashSet<ClaimType> requestedClaimTypes, CancellationToken ct)
        {
            var userClaims = new List<Model.Claim>();
            var claimProviderContext = new ClaimProviderContext
            {
                User = user,
                RequestedClaimTypes = _claimProviders.SelectMany(x => x.RequiredClaimTypes)
                    .Concat(requestedClaimTypes)
                    .ToHashSet(),
            };

            foreach (var cp in _claimProviders)
            {
                if (!cp.CanProvideAnyOf(requestedClaimTypes))
                {
                    continue;
                }

                await cp.AddProviderClaimsToContext(claimProviderContext, ct);
            }

            return claimProviderContext.Claims.ToList();
        }

        private void OrderClaimProviders(List<IClaimProvider> claimProviders)
        {
            var providedClaims = new HashSet<ClaimType>();

            for(int i = 0; i < claimProviders.Count; i++)
            {
                bool foundNextProvider = false;

                for(int j = i; j < claimProviders.Count; j++)
                {
                    var provider = claimProviders[j];

                    if(provider.RequiredClaimTypes.All(providedClaims.Contains))
                    {
                        foundNextProvider = true;
                        providedClaims.UnionWith(provider.ProvidedClaimTypes);
                        (claimProviders[i], claimProviders[j]) = (claimProviders[j], claimProviders[i]);

                        break;
                    }
                }

                if (!foundNextProvider)
                {
                    throw new InvalidOperationException("Circular or non fullfillable dependency detected among claim providers.");
                }
            }
        }



        private static readonly IEnumerable<string> IdTokenOnly = [Destinations.IdentityToken];
        private static readonly IEnumerable<string> AccessTokenOnly = [Destinations.AccessToken];
        private static readonly IEnumerable<string> BothTokens = [Destinations.IdentityToken, Destinations.AccessToken];


        private static IEnumerable<string> GetDestinations(System.Security.Claims.Claim claim, HashSet<ClaimType> idTokenClaims, HashSet<ClaimType> accessTokenClaims)
        {
            if (accessTokenClaims.Contains(claim.Type))
            {
                if (idTokenClaims.Contains(claim.Type))
                {
                    return BothTokens;
                }
                
                return AccessTokenOnly;
            }


            if (idTokenClaims.Contains(claim.Type))
            {
                return IdTokenOnly;
            }

            return [];
        }


        private IEnumerable<Model.Claim> GetStaticClaimsAndUpdateClaimSets(
            OIDCContext context,
            HashSet<ClaimType> idTokenClaims,
            HashSet<ClaimType> accessTokenClaims)
        {
            var result = new List<Model.Claim>();

            result.AddRange(GetStaticClaimsFromProps(context.Application.Properties.StaticClaims, idTokenClaims));
            
            foreach (var scope in context.Scopes) {
                result.AddRange(GetStaticClaimsFromProps(scope.Properties.StaticClaims, accessTokenClaims));
            }

            return result;
        }


        private static IEnumerable<Model.Claim> GetStaticClaimsFromProps(List<Model.Claim> staticClaims, HashSet<ClaimType> claimTypeList)
        {
            claimTypeList.UnionWith(staticClaims.Select(x => x.Type));
            return staticClaims;
        }
    }
}
