﻿using System.Collections.Immutable;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

using JGUZDV.OIDC.ProtocolServer.Model;

using OpenIddict.Abstractions;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.OpenIddictExt
{
    public static class ClaimsIdentityExtensions
    {
        // Some claims are defined to be arrays by the OIDC spec. We'll need to handle them accordingly.
        private static readonly HashSet<ClaimType> ArrayTypeClaims = ["amr"];

        public static void SetClaims(this ClaimsIdentity identity, IEnumerable<Model.Claim> claims)
        {
            // Claims may be single value or multi value. So we group by type and add them accordingly.
            foreach (var claimTypeClaims in claims.GroupBy(x => x.Type))
            {
                var forceArraySemantics = ArrayTypeClaims.Contains(claimTypeClaims.Key);

                if(forceArraySemantics || claimTypeClaims.Count() > 1)
                {
                    if (claimTypeClaims.Count() > 1)
                    {
                        identity.SetClaims(claimTypeClaims.Key.Type, claimTypeClaims.Select(x => x.Value.Value).Distinct().ToImmutableArray());
                    }
                    else
                    {
                        // This will trigger the claim to be written as an array
                        // TODO: Kevin said it will be simplified in OpenIdDict 6.0
                        var value = JsonSerializer.Serialize(claimTypeClaims.Select(x => x.Value));
                        identity.AddClaim(new (claimTypeClaims.Key.Type, value, JsonClaimValueTypes.JsonArray));
                    }
                }
                else
                {
                    identity.SetClaim(claimTypeClaims.Key.Type, claimTypeClaims.First().Value.Value);
                }
            }
        }
    }
}
