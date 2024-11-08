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
            // TODO: Make this a configurable list e.g. authenticationType -> ClaimType
            var userIdentifier = string.Equals(principal.Identity?.AuthenticationType, Constants.AuthenticationTypes.RemoteOIDC)
                    // ADFS will provide 'zdv_sub' as a claim in the principal
                ? principal.FindFirst(_options.Value.SubjectClaimType)?.TransformValue(ClaimTransformationMethod.Base64DecodeGuid)
                    // OpenIddict will provide 'sub' as a claim in the principal
                : principal.FindFirstValue(Claims.Subject);

            if (string.IsNullOrEmpty(userIdentifier))
            {
                _logger.LogDebug("No 'sub' or '{claimType}' claim found in principal. Listing principal claims: {claims}",
                    _options.Value.SubjectClaimType,
                    string.Join("\r\n", principal.Claims.Select(c => $"{c.Type}: {c.Value}"))
                    );
                throw new InvalidOperationException($"No subject or {_options.Value.SubjectClaimType} claim found in principal.");
            }

            var (isBindable, bindPath) = UserEntryHelper.IsBindableIdentity(userIdentifier);
            if (!isBindable)
            {
                _logger.LogDebug("No 'sub' or '{claimType}' claim found in principal. Listing principal claims: {claims}",
                    _options.Value.SubjectClaimType,
                    string.Join("\r\n", principal.Claims.Select(c => $"{c.Type}: {c.Value}"))
                    );

                throw new InvalidOperationException($"The user identifier '{userIdentifier}' seems not to be bindable to AD.");
            }

            return UserEntryHelper.BindDirectoryEntry(_options.Value.ActiveDirectory.LdapServer, bindPath!, propertiesToLoad);
        }
    }
}
