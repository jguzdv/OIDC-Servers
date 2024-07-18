using System.DirectoryServices;
using System.Security.Claims;

using JGUZDV.ActiveDirectory;
using JGUZDV.OIDC.ProtocolServer.Configuration;

using Microsoft.Extensions.Options;

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
                _logger.LogDebug("No 'sub' or '{claimType}' claim found in principal. Listing principal claims: {claims}",
                    _options.Value.UserClaimType,
                    string.Join("\r\n", principal.Claims.Select(c => $"{c.Type}: {c.Value}"))
                    );
                throw new InvalidOperationException($"No subject or {_options.Value.UserClaimType} claim found in principal.");
            }

            var (isBindable, bindPath) = UserEntryHelper.IsBindableIdentity(userIdentifier);
            if (!isBindable)
            {
                _logger.LogDebug("No 'sub' or '{claimType}' claim found in principal. Listing principal claims: {claims}",
                    _options.Value.UserClaimType,
                    string.Join("\r\n", principal.Claims.Select(c => $"{c.Type}: {c.Value}"))
                    );

                throw new InvalidOperationException($"The user identifier '{userIdentifier}' seems not to be bindable to AD.");
            }

            return UserEntryHelper.BindDirectoryEntry(_options.Value.LdapServer, bindPath!, propertiesToLoad);
        }
    }
}
