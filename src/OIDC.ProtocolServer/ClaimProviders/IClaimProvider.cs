using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Security.Claims;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders
{
    public interface IClaimProvider
    {
        // TODO: this is not ideal, since it should be defined elsewhere, but it's a quick fix for now
        int ExecutionOrder { get; }

        Task<List<Model.Claim>> GetClaimsAsync(
            ClaimsPrincipal currentUser, 
            IEnumerable<Model.Claim> knownClaims, // TOD: this should probably be a ISet<>
            IEnumerable<string> claimTypes, 
            CancellationToken ct);

        bool CanProvideAnyOf(IEnumerable<string> claimTypes);
    }

    public static class ClaimProviderExtensions
    {
        public static IServiceCollection AddClaimProvider<T>(this IServiceCollection services)
        {
            services.TryAddEnumerable(new ServiceDescriptor(typeof(IClaimProvider), typeof(T), ServiceLifetime.Scoped));

            return services;
        }
    }
}
