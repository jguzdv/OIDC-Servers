using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using JGUZDV.ActiveDirectory.ClaimProvider.Configuration;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.Configuration
{
    public class ProtocolServerOptions : IValidatableObject
    {
        [NotNull]
        public string? UserClaimType { get; set; }
        public string DefaultConsentType { get; set; } = ConsentTypes.Implicit;

        public List<string> IdTokenScopes { get; set; } = new();

        public Dictionary<string, string> Properties { get; set; } = new();
        public List<ClaimSource> ClaimSources { get; set; } = new();


        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (string.IsNullOrWhiteSpace(UserClaimType))
                yield return new("The user claim type needs to be set.", new[] { nameof(UserClaimType) });
        }
    }
}
