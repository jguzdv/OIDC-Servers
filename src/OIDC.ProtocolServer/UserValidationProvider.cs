
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
            if(!lastChange.Any())
                return null;

            return DateTimeOffset.TryParse(lastChange.First().Value, out var lastChangeDatetime)
                ? lastChangeDatetime
                : null;
        }
    }
}
