using System.Security.Claims;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders
{
    public class ClaimProviderContext
    {
        private readonly HashSet<Model.Claim> _claims = [];

        public required ClaimsPrincipal User { get; init; }
        public required HashSet<string> RequestedClaimTypes { get; init; }

        public IEnumerable<Model.Claim> Claims => _claims;

        internal void AddClaim(Model.Claim claim)
        {
            _claims.Add(claim);
        }

        internal void AddClaims(IEnumerable<Model.Claim> claims)
        {
            _claims.UnionWith(claims);
        }
    }
}
