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
            var userIdentifier = principal.FindFirstValue(_options.Value.UserClaimType) ?? principal.FindFirstValue(Claims.Subject);

            if (string.IsNullOrEmpty(userIdentifier))
            {
                throw new InvalidOperationException($"No subject or {_options.Value.UserClaimType} claim found in principal.");
            }

            var (isBindable, bindPath) = UserEntryHelper.IsBindableIdentity(userIdentifier);
            if (!isBindable)
            {
                throw new InvalidOperationException("No valid subject or sid claim found in principal.");
            }

            return UserEntryHelper.BindDirectoryEntry(_options.Value.LdapServer, bindPath!, propertiesToLoad);
        }
    }
}
