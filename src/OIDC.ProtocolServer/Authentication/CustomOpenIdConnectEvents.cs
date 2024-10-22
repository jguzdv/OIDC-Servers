using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.Configuration;

using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace JGUZDV.OIDC.ProtocolServer.Authentication;

public class CustomOpenIdConnectEvents : OpenIdConnectEvents
{
    public override Task TokenValidated(TokenValidatedContext context)
    {
        if(context.Principal?.Identity == null)
        {
            return Task.CompletedTask;
        }

        // This transformation seems odd at first, but it is necessary to decode the user identifier from base64.
        // This is because ADFS encodes the object guids as base64 strings.
        context.Principal = new ClaimsPrincipal(
            new ClaimsIdentity(
                context.Principal.Claims
                    .Select(c =>
                        string.Equals(c.Type, "zdv_sub")
                            ? c.Transform(ClaimTransformationMethod.Base64DecodeGuid)
                            : new Claim(c.Type, c.Value)
                        ),
                context.Principal.Identity.AuthenticationType,
                "sub", "role")
            );

        return Task.CompletedTask;
    }
}
