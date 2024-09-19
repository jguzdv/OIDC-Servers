using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

using Microsoft.Extensions.Options;

using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore.Models;

namespace JGUZDV.OIDC.ProtocolServer.OpenIddictExt
{
    public class JGUApplicationManager : OpenIddictApplicationManager<OpenIddictEntityFrameworkCoreApplication>
    {
        public JGUApplicationManager(
            IOpenIddictApplicationCache<OpenIddictEntityFrameworkCoreApplication> cache,
            ILogger<OpenIddictApplicationManager<OpenIddictEntityFrameworkCoreApplication>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictApplicationStoreResolver resolver)
            : base(cache, logger, options, resolver)
        { }

        protected override async ValueTask<bool> ValidateClientSecretAsync(string secret, string comparand, CancellationToken cancellationToken = default)
        {
            var result = await base.ValidateClientSecretAsync(secret, comparand, cancellationToken);

            // The secret might be migrated from IdentityServer 4,
            // so we need to replicate their hashing before we check the secret, since we copied the hashed values from there.
            if (!result)
            {
                // Base64 encode the sha256 hash of the secret
                var hashedSecret = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
                result = await base.ValidateClientSecretAsync(hashedSecret, comparand, cancellationToken);
            }

            return result;
        }

        public override async ValueTask<bool> ValidateRedirectUriAsync(OpenIddictEntityFrameworkCoreApplication application, [StringSyntax("Uri")] string uri, CancellationToken cancellationToken = default)
        {
            if (await base.ValidateRedirectUriAsync(application, uri, cancellationToken))
            {
                return true;
            }

            var redirectUris = await Store.GetRedirectUrisAsync(application, cancellationToken);

            // We allow validation of redirect uris with placeholders in them. Indicated by ___ in the uri.
            return ValidateRegexRedirectUri(redirectUris, uri, cancellationToken);
        }


        public override async ValueTask<bool> ValidatePostLogoutRedirectUriAsync(OpenIddictEntityFrameworkCoreApplication application, [StringSyntax("Uri")] string uri, CancellationToken cancellationToken = default)
        {
            if (await base.ValidatePostLogoutRedirectUriAsync(application, uri, cancellationToken))
            {
                return true;
            }

            var redirectUris = await Store.GetPostLogoutRedirectUrisAsync(application, cancellationToken);
            return ValidateRegexRedirectUri(redirectUris, uri, cancellationToken);
        }


        private static bool ValidateRegexRedirectUri(ICollection<string> redirectUris, string uri, CancellationToken cancellationToken = default)
        {
            foreach (var redirectUri in redirectUris.Where(x => x.Contains("__")))
            {
                var regexedRedirectUri = new Regex($"^{redirectUri.Replace("__", "[\\w\\d\\._-]*")}$", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250));

                if (regexedRedirectUri.IsMatch(uri))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
