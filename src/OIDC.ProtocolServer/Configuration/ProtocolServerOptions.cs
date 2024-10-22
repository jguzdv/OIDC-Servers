using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.Configuration
{
    public class ProtocolServerOptions : IValidatableObject
    {
        [NotNull]
        public string? SubjectClaimType { get; set; }

        [NotNull]
        public string? PersonIdentifierClaimType { get; set; }

        public ActiveDirectoryClaimProviderOptions ActiveDirectory { get; set; } = new();
        public JGUDirectoryClaimProviderOptions JGUDirectory { get; set; } = new();
        public PrincipalClaimProviderOptions PrincipalClaimProvider { get; set; } = new();

        public string DefaultConsentType { get; set; } = ConsentTypes.Implicit;


        public HashSet<string> DefaultClaimTypes { get; set; } = new();
        public ISet<string> DefaultIdTokenClaims => DefaultClaimTypes;
        public ISet<string> DefaultAccessTokenClaims => DefaultClaimTypes;


        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (string.IsNullOrWhiteSpace(SubjectClaimType))
            {
                yield return new("The user claim type needs to be set.", [nameof(SubjectClaimType)]);
            }

            foreach (var result in ActiveDirectory.Validate(validationContext))
            {
                yield return result;
            }

            foreach (var result in JGUDirectory.Validate(validationContext))
            {
                yield return result;
            }

            foreach (var result in PrincipalClaimProvider.Validate(validationContext))
            {
                yield return result;
            }
        }
    }
}
