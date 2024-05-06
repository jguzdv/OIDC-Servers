using System.DirectoryServices;
using System.Security.Claims;

using JGUZDV.ActiveDirectory;
using JGUZDV.OIDC.ProtocolServer.Configuration;

using Microsoft.Extensions.Options;

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
            if (string.IsNullOrEmpty(userSid))
            {
                throw new InvalidOperationException("No sid claim found in principal");
            }

            var entry = UserEntryHelper.BindDirectoryEntry(_options.Value.LdapServer, $"<Sid={userSid}>", propertiesToLoad);
            return entry;
        }
    }
}
