using System.Security.Cryptography;
using System.Text;

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

            // The secret might be migrated from IdentityServer 4, which uses SHA256 hashing
            if (!result)
            {
                // Base64 encode the sha1 hash of the secret
                var hashedSecret = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
                result = await base.ValidateClientSecretAsync(hashedSecret, comparand, cancellationToken);
            }

            return result;
        }
    }
}
