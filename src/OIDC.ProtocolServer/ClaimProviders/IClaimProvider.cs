using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.Model;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders
{
    public interface IClaimProvider
    {
        /// <summary>
        /// The claim types that this provider needs before it can run.
        /// This list can be used to build a execution order.
        /// </summary>
        ClaimType[] RequiredClaimTypes { get; }

        /// <summary>
        /// The claim types that this provider can provide.
        /// </summary>
        ClaimType[] ProvidedClaimTypes { get; }

        // TODO: Replace with "ShouldProvideClaims" method
        /// <summary>
        /// Determines if the provider can provide any of the requested claim types.
        /// </summary>
        bool CanProvideAnyOf(IEnumerable<ClaimType> claimTypes);

        /// <summary>
        /// Add the claims of this provider to the claim provider context.
        /// </summary>
        Task AddProviderClaimsToContext(
            ClaimProviderContext context,
            CancellationToken ct);

    }
}
