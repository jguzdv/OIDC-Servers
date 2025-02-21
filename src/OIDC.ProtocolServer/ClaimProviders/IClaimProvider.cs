using System.Security.Claims;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders
{
    public interface IClaimProvider
    {
        /// <summary>
        /// The claim types that this provider needs before it can run.
        /// This list can be used to build a execution order.
        /// </summary>
        string[] RequiredClaimTypes { get; }

        /// <summary>
        /// The claim types that this provider can provide.
        /// </summary>
        string[] ProvidedClaimTypes { get; }

        /// <summary>
        /// Determines if the provider can provide any of the requested claim types.
        /// </summary>
        bool CanProvideAnyOf(IEnumerable<string> claimTypes);

        /// <summary>
        /// Add the claims of this provider to the claim provider context.
        /// </summary>
        Task AddProviderClaimsToContext(
            ClaimProviderContext context,
            CancellationToken ct);

    }
}
