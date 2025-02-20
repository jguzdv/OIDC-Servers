using Microsoft.Extensions.DependencyInjection.Extensions;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders
{
    public static class ClaimProviderExtensions
    {
        public static IServiceCollection AddClaimProvider<T>(this IServiceCollection services)
        {
            services.TryAddEnumerable(new ServiceDescriptor(typeof(IClaimProvider), typeof(T), ServiceLifetime.Scoped));

            return services;
        }
    }
}
