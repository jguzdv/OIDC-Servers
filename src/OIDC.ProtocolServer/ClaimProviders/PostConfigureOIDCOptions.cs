using JGUZDV.OIDC.ProtocolServer.Configuration;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders;

public class PostConfigureOIDCOptions : IPostConfigureOptions<OpenIdConnectOptions>
    {
        private readonly IOptions<ProtocolServerOptions> _options;

        public PostConfigureOIDCOptions(IOptions<ProtocolServerOptions> options)
        {
            _options = options;
        }

        public void PostConfigure(string? name, OpenIdConnectOptions options)
        {
            // To be able to load the claims from the PrincipalClaimProvider, we need to make sure that, the claims are part of the ClaimsPrincipal.
            foreach(var claimType in _options.Value.PrincipalClaimProvider.ClaimTypeMaps)
            {
                options.ClaimActions.MapJsonKey(claimType.ClaimType, claimType.ClaimType);
            }
        }
    }
