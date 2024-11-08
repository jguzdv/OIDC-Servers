﻿using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.ClaimProviders;
using JGUZDV.OIDC.ProtocolServer.Model;
using JGUZDV.OIDC.ProtocolServer.OpenIddictExt;

using Microsoft.AspNetCore.Authentication;

using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.Web;

public partial class Endpoints
{
    public static partial class OIDC
    {
        public static async Task<IResult> UserInfo(
            HttpContext httpContext,
            IOpenIddictScopeManager scopeManager,
            IdentityProvider identityProvider,
            CancellationToken ct)
        {
            var authResult = await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            if(!authResult.Succeeded)
            {
                return Unauthorized();
            }

            var user = authResult.Principal!;
            var userSubject = user.GetClaim(Claims.Subject);
            if (string.IsNullOrWhiteSpace(userSubject))
            {
                return Unauthorized();
            }

            var userScopes = user.GetScopes();

            var scopes = await ScopeModel.FromScopeNamesAsync(scopeManager, user.GetScopes(), ct);
            var idClaims = scopes
                .Where(x => x.Properties.TargetToken.Contains(Destinations.IdentityToken))
                .SelectMany(x => x.Properties.RequestedClaimTypes)
                .Except([Claims.Subject], StringComparer.OrdinalIgnoreCase) // We'll add the subject from the current user
                .ToHashSet();

            var userClaims = new List<Model.Claim>
            {
                new(Claims.Subject, userSubject)
            };

            var moreClaims = await identityProvider.LoadUserClaims(user, idClaims, ct);
            userClaims.AddRange(moreClaims);

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

        private static IResult Unauthorized() 
            => Results.BadRequest(new OpenIddictResponse
            {
                Error = Errors.InvalidRequest,
                ErrorDescription = "Could not provide user-info, since the user could not be identified."
            });
    }
}
