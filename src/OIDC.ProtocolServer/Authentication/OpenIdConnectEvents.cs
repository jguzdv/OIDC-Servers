using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.Configuration;

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace JGUZDV.OIDC.ProtocolServer.Authentication
{
    public class CustomOpenIdConnectEvents(IOptions<ProtocolServerOptions> options) : OpenIdConnectEvents
    {
        private readonly IOptions<ProtocolServerOptions> _options = options;

        private readonly List<(string from, string to)> _claimMap = [("sid", "zdv_sid"), ("amr", "amr"), ("sub", "sub"), ("mfa_auth_time", "mfa_auth_time")];

        public override async Task TokenValidated(TokenValidatedContext context)
        {
            await base.TokenValidated(context);

            var user = context.Principal;
            if(user == null)
            {
                return;
            }

            var claimMap = _claimMap.ToDictionary(x => x.from, x => x.to, StringComparer.OrdinalIgnoreCase);

            context.Principal = new(new ClaimsIdentity(
                user.Claims
                    .Where(x => claimMap.ContainsKey(x.Type))
                    .Select(x => new Claim(claimMap[x.Type], x.Value)),
                    user.Identity!.AuthenticationType,
                    "sub", "none"
                )
            );
        }
    }
}
