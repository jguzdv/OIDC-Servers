using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.Configuration;

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace JGUZDV.OIDC.ProtocolServer.Authentication
{
    public class CustomOpenIdConnectEvents(IOptions<ProtocolServerOptions> options) : OpenIdConnectEvents
    {
        private readonly IOptions<ProtocolServerOptions> _options = options;

        private static readonly Dictionary<string, TransformationDescriptor> Transformers = new()
        {
            ["sid"] = new("zdv_sid"),
            // ADFS provides object guids as base64 encoded - we'll reverse that here.
            ["zdv_sub"] = new("zdv_sub", x => new Guid(Convert.FromBase64String(x)).ToString()),
            ["amr"] = new("amr"),
            ["sub"] = new("sub"),
            ["mfa_auth_time"] = new("mfa_auth_time")
        };

        
        public override async Task TokenValidated(TokenValidatedContext context)
        {
            await base.TokenValidated(context);

            var user = context.Principal;
            if(user == null)
            {
                return;
            }

            context.Principal = new(new ClaimsIdentity(
                user.Claims
                    .Where(x => Transformers.ContainsKey(x.Type))
                    .Select(x =>
                    {
                        var td = Transformers[x.Type];
                        return new Claim(td.TargetClaimType, td.TransformationFunc(x.Value));
                    }),
                    user.Identity!.AuthenticationType,
                    "sub", "none"
                )
            );
        }
    }

    internal class TransformationDescriptor(string targetClaimType, Func<string, string>? transformationFunc = null)
    {

        public string TargetClaimType { get; } = targetClaimType;

        public Func<string, string> TransformationFunc { get; } = transformationFunc ?? (x => x);
    }
}
