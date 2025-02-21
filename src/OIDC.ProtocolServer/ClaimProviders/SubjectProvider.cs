
using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.Configuration;
using JGUZDV.OIDC.ProtocolServer.Model;

using Microsoft.Extensions.Options;

using OpenIddict.Abstractions;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders
{
    public class SubjectProvider : IClaimProvider
    {
        private readonly IOptions<ProtocolServerOptions> _options;

        public ClaimType[] RequiredClaimTypes => [_options.Value.SubjectClaimType];

        public ClaimType[] ProvidedClaimTypes => [OpenIddictConstants.Claims.Subject];


        public SubjectProvider(IOptions<ProtocolServerOptions> options)
        {
            _options = options;
        }


        public Task AddProviderClaimsToContext(ClaimProviderContext context, CancellationToken ct)
        {
            var subjectClaim = context.Claims.FirstOrDefault(x => x.Type == _options.Value.SubjectClaimType);
            if(subjectClaim == null)
            {
                throw new InvalidOperationException("Subject claim not found.");
            }

            context.AddClaim(new(OpenIddictConstants.Claims.Subject, subjectClaim.Value));
            return Task.CompletedTask;
        }

        public bool CanProvideAnyOf(IEnumerable<ClaimType> claimTypes)
        {
            return claimTypes.Intersect(ProvidedClaimTypes).Any();
        }
    }
}
