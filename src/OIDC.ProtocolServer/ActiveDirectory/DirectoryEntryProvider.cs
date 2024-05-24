using System.DirectoryServices;
using System.Security.Claims;
using System.Security.Principal;

using JGUZDV.ActiveDirectory;
using JGUZDV.OIDC.ProtocolServer.Configuration;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.ActiveDirectory
{
    public class DirectoryEntryProvider
    {
        private readonly IOptions<ProtocolServerOptions> _options;
        private readonly ILogger<DirectoryEntryProvider> _logger;

        public DirectoryEntryProvider(
            IOptions<ProtocolServerOptions> options,
            ILogger<DirectoryEntryProvider> logger)
        {
            _options = options;
            _logger = logger;
        }

        public DirectoryEntry GetUserEntryFromPrincipal(ClaimsPrincipal principal, params string[] propertiesToLoad)
        {
            var userSid = principal.FindFirstValue(_options.Value.UserClaimType);
            var userSub = principal.FindFirstValue(Claims.Subject);
            if (string.IsNullOrEmpty(userSid) && string.IsNullOrEmpty(userSub))
            {
                throw new InvalidOperationException("No subject or sid claim found in principal.");
            }

            if (!string.IsNullOrEmpty(userSid) && userSid.StartsWith("S-"))
            {
                return UserEntryHelper.BindDirectoryEntry(_options.Value.LdapServer, $"<Sid={userSid}>", propertiesToLoad);
            }

            if (!string.IsNullOrEmpty(userSub) && Guid.TryParse(userSub, out var userObjectGuid))
            {
                return UserEntryHelper.BindDirectoryEntry(_options.Value.LdapServer, $"<GUID={userObjectGuid}>", propertiesToLoad);
            }

            throw new InvalidOperationException("No valid subject or sid claim found in principal.");
        }
    }
}
