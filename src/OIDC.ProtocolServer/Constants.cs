using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace JGUZDV.OIDC.ProtocolServer
{
    public static class Constants
    {
        public static class AuthenticationSchemes
        {
            public const string OIDC = OpenIdConnectDefaults.AuthenticationScheme;
            public const string MFA = "OpenIdConnect-MFA";
        }

        public static class ClaimTypes
        {
            public const string MFAAuthTime = "mfa_auth_time";
        }
    }
}
