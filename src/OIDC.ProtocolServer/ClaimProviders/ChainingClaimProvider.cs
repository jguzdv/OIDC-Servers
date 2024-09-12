using System.Security.Claims;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders
{
    // TODO: use this to create a claim provider that chains multiple claim providers
    // It's intended to obsolete the ExecutionOrder property in IClaimProvider
    internal class ChainingClaimProvider : IClaimProvider
    {
        public int ExecutionOrder => throw new NotImplementedException();

        public bool CanProvideAnyOf(IEnumerable<string> claimTypes)
        {
            throw new NotImplementedException();
        }

        public Task<List<Model.Claim>> GetClaimsAsync(ClaimsPrincipal currentUser, IEnumerable<Model.Claim> knownClaims, IEnumerable<string> claimTypes, CancellationToken ct)
        {
            throw new NotImplementedException();
        }
    }
}
