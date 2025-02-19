using System.Security.Claims;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders
{
    public interface IClaimProvider
    {
        /// <summary>
        /// The claim types that this provider needs before it can run.
        /// This list can be used to build a execution order.
        /// </summary>
        string[] RequiredClaims { get; }

        Task<List<Model.Claim>> GetClaimsAsync(
            ClaimsPrincipal currentUser, 
            IEnumerable<Model.Claim> knownClaims, // TODO: this should probably be a ISet<>
            IEnumerable<string> claimTypes, 
            CancellationToken ct);

        bool CanProvideAnyOf(IEnumerable<string> claimTypes);
    }
}
