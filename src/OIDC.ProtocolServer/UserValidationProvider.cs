
using System.Security.Claims;

using JGUZDV.ActiveDirectory.ClaimProvider;

using OpenIddict.Abstractions;

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
            => true;
        
        public DateTimeOffset? LastPasswordChange(ClaimsPrincipal claimsPrincipal)
        {
            var lastChange = _adClaimProvider.GetClaims(claimsPrincipal, new[] { "pwd_changed" });
            return DateTimeOffset.TryParse(lastChange.FirstOrDefault().Value, out var lastChangeDatetime)
                ? lastChangeDatetime
                : null;
        }

        /* TODO
         * 
        public bool IsUserActive(ClaimsPrincipal subject)
        {
            try
            {
                var userDirectoryEntry = GetUserDirectoryEntry(subject, new[] { accountControlProperty });
                if (userDirectoryEntry?.Properties[accountControlProperty][0] is int adsUserFlags)
                {
                    //See https://docs.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_user_flag_enum ADS_UF_ACCOUNTDISABLE 
                    return (adsUserFlags & 0x2) != 2;
                }

                return false;
            }
            catch (InvalidOperationException ex)
            {
                _logger.LogError(ex, "Could not determine ActiveState of user.");
                return false;
            }
        }

        */
    }
}
