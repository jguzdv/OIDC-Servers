using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

using OpenIddict.Abstractions;

namespace JGUZDV.OIDC.ProtocolServer.Data
{
    public record ApplicationModel(
        [property:NotNull] string? Id,
        [property: NotNull] string? ClientId,
        [property: NotNull] string? ConsentType,
        [property: NotNull] string? DisplayName,

        ImmutableArray<string> Persmissions,
        ImmutableArray<(string Type, string Value)> StaticClaims,
        ImmutableArray<string> RequestedClaimTypes
        )
    {
        public static async Task<ApplicationModel> FromClientIdAsync(
            IOpenIddictApplicationManager appManager,
            string clientId, CancellationToken ct)
        {
            var application = await appManager.FindByClientIdAsync(clientId!, ct) ??
                throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

            var props = await appManager.GetPropertiesAsync(application, ct);
            var appProps = new ApplicationProperties(props);

            return new ApplicationModel(
                await appManager.GetIdAsync(application, ct),
                await appManager.GetClientIdAsync(application, ct)!,
                await appManager.GetConsentTypeAsync(application, ct)!,
                await appManager.GetLocalizedDisplayNameAsync(application, ct)!,
                await appManager.GetPermissionsAsync(application, ct),
                appProps.StaticClaims.ToImmutableArray(),
                appProps.ClaimTypes.ToImmutableArray()
                );
        }
    }
}
