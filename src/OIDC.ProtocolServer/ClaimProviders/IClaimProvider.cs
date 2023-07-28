using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Security.Claims;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders
{
    public interface IClaimProvider
    {
        Task<List<(string Type, string Value)>> GetClaims(ClaimsPrincipal currentUser, IEnumerable<string> claimTypes, CancellationToken ct);

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
