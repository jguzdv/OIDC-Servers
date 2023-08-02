using System.Diagnostics.CodeAnalysis;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.Configuration
{
    public class ProtocolServerOptions
    {
        [NotNull]
        public string? UserClaimType { get; set; }
        public string DefaultConsentType { get; set; } = ConsentTypes.Implicit;

        public Dictionary<string, List<string>> ScopeClaims { get; set; } = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
    }
}
