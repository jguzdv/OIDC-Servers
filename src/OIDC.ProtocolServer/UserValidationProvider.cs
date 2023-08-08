
using System.Security.Claims;

using JGUZDV.ActiveDirectory.ClaimProvider;

namespace JGUZDV.OIDC.ProtocolServer
{
    public class UserValidationProvider
    {
        private readonly ADClaimProvider _adClaimProvider;

        public UserValidationProvider(ADClaimProvider adClaimProvider)
        {
            _adClaimProvider = adClaimProvider;
        }

        public bool IsUserActive(ClaimsPrincipal claimsPrincipal)
            => _adClaimProvider.IsUserActive(claimsPrincipal);
        
        public DateTimeOffset? LastPasswordChange(ClaimsPrincipal claimsPrincipal)
        {
            var lastChange = _adClaimProvider.GetClaims(claimsPrincipal, new[] { "pwdLastChanged" });
            return DateTimeOffset.TryParse(lastChange.FirstOrDefault().Value, out var lastChangeDatetime)
                ? lastChangeDatetime
                : null;
        }
    }
}
